"""Email and Google accounts with private MongoDB storage."""
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from threading import BoundedSemaphore
from typing import Literal
from urllib.parse import urlsplit

from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

router = APIRouter(prefix="/account", tags=["Accounts"])
hasher = PasswordHasher()
HASH_SLOTS = BoundedSemaphore(2)

def hash_password(password):
    with HASH_SLOTS:
        return hasher.hash(password)

DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
COOKIE = "vitalsense_session"
SESSION_DAYS = 7
GOOGLE_COOKIE = "vitalsense_google_nonce"
GOOGLE_TTL = 300
Kind = Literal["chats", "journals", "goals", "moods"]


def now():
    return datetime.now(timezone.utc)


@lru_cache(maxsize=1)
def database():
    uri = os.getenv("MONGODB_URI", "").strip()
    if not uri:
        raise HTTPException(503, "Accounts are being set up. Please continue as a guest.")
    client = MongoClient(uri, serverSelectionTimeoutMS=5000, tz_aware=True)
    db = client[os.getenv("MONGODB_DB", "vital_sense")]
    try:
        db.command("ping")
        db.users.create_index("email", unique=True)
        db.users.create_index("googleSub", unique=True, sparse=True)
        db.sessions.create_index("expiresAt", expireAfterSeconds=0)
        db.sessions.create_index("userId")
        db.records.create_index([("userId", 1), ("kind", 1), ("createdAt", -1)])
        db.limits.create_index("expiresAt", expireAfterSeconds=0)
    except PyMongoError:
        client.close()
        raise HTTPException(503, "Account storage is unavailable. Please try again later.") from None
    return db


def browser_request(request: Request):
    # Custom headers cannot be sent by cross-site HTML forms. CORS limits which
    # browser origins may send them, including login/signup (login CSRF).
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("x-vital-sense") != "1":
            raise HTTPException(403, "Invalid account request.")
        origin = request.headers.get("origin")
        allowed = {v.strip() for v in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")}
        if origin and origin not in allowed:
            raise HTTPException(403, "Origin is not allowed.")


router.dependencies.append(Depends(browser_request))


def rate_limit(db, key, maximum):
    window = int(now().timestamp()) // 900
    identity = hashlib.sha256(f"{key}:{window}".encode()).hexdigest()
    entry = db.limits.find_one_and_update(
        {"_id": identity},
        {"$inc": {"count": 1}, "$setOnInsert": {"expiresAt": now() + timedelta(minutes=30)}},
        upsert=True, return_document=ReturnDocument.AFTER,
    )
    if entry["count"] > maximum:
        raise HTTPException(429, "Too many attempts. Please try again in 15 minutes.")


def public_user(user):
    return {"uid": user["_id"], "email": user["email"], "displayName": user["displayName"], "photoURL": user.get("photoURL"), "hasPassword": bool(user.get("passwordHash"))}


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def set_session(db, user, response):
    token = secrets.token_urlsafe(48)
    db.sessions.insert_one({"_id": token_hash(token), "userId": user["_id"], "expiresAt": now() + timedelta(days=SESSION_DAYS)})
    response.set_cookie(COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True,
                        secure=os.getenv("COOKIE_SECURE", "true").lower() != "false",
                        samesite="lax", path="/api/v1/account")
    response.headers["Cache-Control"] = "no-store"


def current_user(request: Request, db=Depends(database)):
    token = request.cookies.get(COOKIE, "")
    session = db.sessions.find_one({"_id": token_hash(token), "expiresAt": {"$gt": now()}}) if token else None
    user = db.users.find_one({"_id": session["userId"], "deleting": {"$ne": True}}) if session else None
    if not user:
        raise HTTPException(401, "Please sign in to continue.")
    return user


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class Registration(Credentials):
    password: str = Field(min_length=10, max_length=128)
    displayName: str = Field(min_length=1, max_length=80)


class DeleteAccount(BaseModel):
    password: str | None = Field(default=None, min_length=1, max_length=128)
    credential: str | None = Field(default=None, min_length=1, max_length=12000)


class GoogleCredentials(BaseModel):
    credential: str = Field(min_length=1, max_length=12000)
    password: str | None = Field(default=None, min_length=1, max_length=128)


def verify_password(encoded, password):
    try:
        with HASH_SLOTS:
            return hasher.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


@router.get("/status")
def status(response: Response):
    response.headers["Cache-Control"] = "no-store"
    database()
    return {"enabled": True, "googleClientId": google_client_id() or None}



def google_client_id():
    return os.getenv("GOOGLE_CLIENT_ID", "").strip()


class GoogleTransport(GoogleRequest):
    def __call__(self, *args, **kwargs):
        kwargs["timeout"] = 10
        return super().__call__(*args, **kwargs)


def verify_google(credential, request):
    client_id = google_client_id()
    if not client_id:
        raise HTTPException(503, "Google sign-in is not available yet. Use email instead.")
    nonce = request.cookies.get(GOOGLE_COOKIE, "")
    if not nonce or len(nonce) > 128:
        raise HTTPException(401, "Please start Google sign-in again.")
    try:
        # The Google library verifies signature, expiry, audience and issuer.
        claims = id_token.verify_oauth2_token(credential, GoogleTransport(), client_id)
    except ValueError:
        raise HTTPException(401, "Google could not verify this sign-in. Please try again.") from None
    except GoogleAuthError:
        raise HTTPException(503, "Google sign-in is temporarily unavailable. Please try again.") from None
    if (claims.get("email_verified") is not True or not claims.get("email")
            or not isinstance(claims.get("sub"), str) or not 0 < len(claims["sub"]) <= 255
            or not isinstance(claims.get("nonce"), str)
            or not secrets.compare_digest(claims["nonce"], nonce)
            or claims.get("azp", client_id) != client_id):
        raise HTTPException(401, "Google could not verify this sign-in. Please try again.")
    return claims, nonce


def consume_google_nonce(db, nonce):
    challenge = db.limits.find_one_and_delete({"_id": "google:" + token_hash(nonce), "expiresAt": {"$gt": now()}})
    if not challenge:
        raise HTTPException(401, "This Google sign-in has expired. Please start again.")


@router.post("/google/challenge")
def google_challenge(request: Request, response: Response, db=Depends(database)):
    if not google_client_id():
        raise HTTPException(503, "Google sign-in is not available yet. Use email instead.")
    rate_limit(db, f"google-challenge:{request.client.host}", 100)
    nonce = secrets.token_urlsafe(32)
    db.limits.insert_one({"_id": "google:" + token_hash(nonce), "expiresAt": now() + timedelta(seconds=GOOGLE_TTL)})
    response.set_cookie(GOOGLE_COOKIE, nonce, max_age=GOOGLE_TTL, httponly=True,
                        secure=os.getenv("COOKIE_SECURE", "true").lower() != "false",
                        samesite="strict", path="/api/v1/account")
    return {"nonce": nonce}


@router.post("/google")
def google_login(data: GoogleCredentials, request: Request, response: Response, db=Depends(database)):
    rate_limit(db, f"google-login:{request.client.host}", 100)
    claims, nonce = verify_google(data.credential, request)
    # Check expiry before any account change; consumption below prevents replay.
    if not db.limits.find_one({"_id": "google:" + token_hash(nonce), "expiresAt": {"$gt": now()}}):
        raise HTTPException(401, "This Google sign-in has expired. Please start again.")
    user = db.users.find_one({"googleSub": claims["sub"]})
    if not user:
        email = str(claims["email"]).strip().lower()
        user = db.users.find_one({"email": email})
        if user:
            # Email alone never links accounts: require the existing password.
            if user.get("deleting") or user.get("googleSub"):
                raise HTTPException(409, "This email is already connected to another account.")
            rate_limit(db, f"google-link:{user['_id']}", 15)
            if not data.password:
                raise HTTPException(409, "Confirm your existing Vital Sense password to connect Google.", headers={"X-Google-Link": "password"})
            if not user.get("passwordHash") or not verify_password(user["passwordHash"], data.password):
                raise HTTPException(401, "Password is incorrect.")
            consume_google_nonce(db, nonce)
            try:
                linked = db.users.update_one({"_id": user["_id"], "googleSub": {"$exists": False}, "deleting": {"$ne": True}}, {"$set": {"googleSub": claims["sub"]}})
                if not linked.modified_count:
                    raise HTTPException(409, "Account changed. Please start Google sign-in again.")
            except DuplicateKeyError:
                raise HTTPException(409, "This Google account is already connected.") from None
        else:
            consume_google_nonce(db, nonce)
            name = str(claims.get("name") or email.split("@")[0]).strip()[:80] or "Member"
            user = {"_id": secrets.token_hex(16), "email": email, "displayName": name, "googleSub": claims["sub"], "createdAt": now()}
            try:
                db.users.insert_one(user)
            except DuplicateKeyError:
                raise HTTPException(409, "Account changed. Please start Google sign-in again.") from None
    else:
        if user.get("deleting"):
            raise HTTPException(401, "This account is unavailable.")
        consume_google_nonce(db, nonce)
    # Only accept Google's hosted HTTPS photo from the verified identity token.
    picture = claims.get("picture")
    photo = None
    if isinstance(picture, str) and len(picture) <= 2048:
        try:
            parsed = urlsplit(picture)
            if parsed.scheme == "https" and (parsed.hostname or "").endswith(".googleusercontent.com") and not parsed.username and not parsed.password:
                photo = picture
        except ValueError:
            pass
    db.users.update_one({"_id": user["_id"]}, {"$set": {"photoURL": photo}})
    user["photoURL"] = photo
    set_session(db, user, response)
    response.delete_cookie(GOOGLE_COOKIE, path="/api/v1/account")
    return public_user(user)


@router.post("/signup", status_code=201)
def signup(data: Registration, request: Request, response: Response, db=Depends(database)):
    email = str(data.email).strip().lower()
    rate_limit(db, f"signup:{request.client.host}", 20)
    name = data.displayName.strip()
    if not name:
        raise HTTPException(422, "Please enter your name.")
    user = {"_id": secrets.token_hex(16), "email": email, "displayName": name,
            "passwordHash": hash_password(data.password), "createdAt": now()}
    try:
        db.users.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(409, "Unable to create this account. Try signing in instead.") from None
    set_session(db, user, response)
    return public_user(user)


@router.post("/login")
def login(data: Credentials, request: Request, response: Response, db=Depends(database)):
    email = str(data.email).strip().lower()
    rate_limit(db, f"login:{request.client.host}", 100)
    rate_limit(db, f"email:{email}", 15)
    user = db.users.find_one({"email": email, "deleting": {"$ne": True}})
    valid = verify_password(user.get("passwordHash", DUMMY_HASH) if user else DUMMY_HASH, data.password)
    if not user or not user.get("passwordHash") or not valid:
        raise HTTPException(401, "Email or password is incorrect.")
    if hasher.check_needs_rehash(user["passwordHash"]):
        db.users.update_one({"_id": user["_id"]}, {"$set": {"passwordHash": hash_password(data.password)}})
    set_session(db, user, response)
    return public_user(user)


@router.get("/me")
def me(response: Response, user=Depends(current_user)):
    response.headers["Cache-Control"] = "no-store"
    return public_user(user)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db=Depends(database)):
    db.sessions.delete_one({"_id": token_hash(request.cookies.get(COOKIE, ""))})
    response.delete_cookie(COOKIE, path="/api/v1/account", secure=os.getenv("COOKIE_SECURE", "true").lower() != "false", httponly=True, samesite="lax")


@router.delete("/me", status_code=204)
def delete_account(data: DeleteAccount, request: Request, response: Response, user=Depends(current_user), db=Depends(database)):
    rate_limit(db, f"delete:{user['_id']}", 10)
    if user.get("passwordHash"):
        if not data.password or not verify_password(user["passwordHash"], data.password):
            raise HTTPException(401, "Password is incorrect.")
    else:
        if not data.credential:
            raise HTTPException(401, "Confirm with Google before deleting your account.")
        claims, nonce = verify_google(data.credential, request)
        if claims["sub"] != user.get("googleSub"):
            raise HTTPException(401, "Use the Google account connected to Vital Sense.")
        consume_google_nonce(db, nonce)

    # Revoke account access first; failed deletions can be retried administratively.
    db.users.update_one({"_id": user["_id"]}, {"$set": {"deleting": True}})
    db.sessions.delete_many({"userId": user["_id"]})
    db.records.delete_many({"userId": user["_id"]})
    db.users.delete_one({"_id": user["_id"]})
    response.delete_cookie(COOKIE, path="/api/v1/account")


class Preferences(BaseModel):
    theme: Literal["dark", "premium", "blue", "sunset", "aurora"]


@router.get("/preferences")
def preferences(user=Depends(current_user)):
    return {"theme": user.get("theme", "dark")}


@router.put("/preferences")
def save_preferences(data: Preferences, user=Depends(current_user), db=Depends(database)):
    db.users.update_one({"_id": user["_id"]}, {"$set": data.model_dump()})
    return data.model_dump()


class Record(BaseModel):
    data: dict


def clean_record(data):
    if len(json.dumps(data)) > 500_000:
        raise HTTPException(413, "This entry is too large to save.")
    def clean(value, depth=0):
        if depth > 30:
            raise HTTPException(422, "Entry is too deeply nested.")
        if isinstance(value, dict):
            if value == {"__serverTimestamp": True}:
                return now().isoformat()
            if any(key.startswith("$") or "." in key or key in {"_id", "id", "userId", "kind"} for key in value):
                raise HTTPException(422, "Invalid entry fields.")
            return {key: clean(item, depth + 1) for key, item in value.items()}
        if isinstance(value, list):
            return [clean(item, depth + 1) for item in value]
        return value
    return clean(data)


def record_view(record):
    return {"id": record["_id"], **record["data"]}


@router.get("/records/{kind}")
def list_records(kind: Kind, user=Depends(current_user), db=Depends(database)):
    return [record_view(r) for r in db.records.find({"userId": user["_id"], "kind": kind}).sort("createdAt", -1)]


@router.post("/records/{kind}", status_code=201)
def add_record(kind: Kind, body: Record, user=Depends(current_user), db=Depends(database)):
    data = clean_record(body.data)
    data["createdAt"] = now().isoformat()
    data["updatedAt"] = data["createdAt"]
    record = {"_id": secrets.token_hex(16), "userId": user["_id"], "kind": kind, "data": data, "createdAt": now()}
    db.records.insert_one(record)
    return record_view(record)


@router.patch("/records/{kind}/{record_id}")
def update_record(kind: Kind, record_id: str, body: Record, user=Depends(current_user), db=Depends(database)):
    data = clean_record(body.data)
    data.pop("createdAt", None)
    data["updatedAt"] = now().isoformat()
    result = db.records.find_one_and_update(
        {"_id": record_id, "userId": user["_id"], "kind": kind},
        {"$set": {f"data.{key}": value for key, value in data.items()}}, return_document=ReturnDocument.AFTER)
    if not result:
        raise HTTPException(404, "Entry not found.")
    return record_view(result)


@router.delete("/records/{kind}/{record_id}", status_code=204)
def delete_record(kind: Kind, record_id: str, user=Depends(current_user), db=Depends(database)):
    result = db.records.delete_one({"_id": record_id, "userId": user["_id"], "kind": kind})
    if not result.deleted_count:
        raise HTTPException(404, "Entry not found.")
