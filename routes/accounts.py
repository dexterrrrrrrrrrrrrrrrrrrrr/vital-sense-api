"""Email accounts and private MongoDB storage; no credentials reach the browser."""
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from threading import BoundedSemaphore
from typing import Literal

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
    return {"uid": user["_id"], "email": user["email"], "displayName": user["displayName"], "photoURL": None}


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
    password: str = Field(min_length=1, max_length=128)


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
    return {"enabled": True}


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
    valid = verify_password(user["passwordHash"] if user else DUMMY_HASH, data.password)
    if not user or not valid:
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
    if not verify_password(user["passwordHash"], data.password):
        raise HTTPException(401, "Password is incorrect.")
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
