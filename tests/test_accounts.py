"""Integration checks against an isolated disposable local MongoDB database."""
import hashlib
import os
import secrets
import unittest
from unittest.mock import patch
from datetime import timedelta

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pymongo import MongoClient

from routes import accounts


@unittest.skipUnless(os.getenv("MONGODB_TEST_URI"), "Set MONGODB_TEST_URI to a disposable MongoDB server")
class AccountsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.name = "vital_sense_test_" + secrets.token_hex(8)
        os.environ["MONGODB_URI"] = os.environ["MONGODB_TEST_URI"]
        os.environ["MONGODB_DB"] = cls.name
        os.environ["COOKIE_SECURE"] = "true"
        os.environ["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com"
        os.environ["ALLOWED_ORIGINS"] = "https://app.example.com"
        accounts.database.cache_clear()
        cls.db = accounts.database()
        cls.app = FastAPI()
        cls.app.include_router(accounts.router, prefix="/api/v1")

    @classmethod
    def tearDownClass(cls):
        cls.db.client.drop_database(cls.name)
        cls.db.client.close()
        accounts.database.cache_clear()

    def setUp(self):
        for name in self.db.list_collection_names():
            self.db[name].delete_many({})
        self.a = TestClient(self.app, base_url="https://app.example.com", headers={"X-Vital-Sense": "1", "Origin": "https://app.example.com"})
        self.b = TestClient(self.app, base_url="https://app.example.com", headers={"X-Vital-Sense": "1", "Origin": "https://app.example.com"})
        self.base = "/api/v1/account"
        self.password = "A-test-password-123!"

    def signup(self, client, email="alice@example.com"):
        result = client.post(self.base + "/signup", json={"displayName": "Alice", "email": email, "password": self.password})
        self.assertEqual(result.status_code, 201, result.text)
        return result

    def test_signup_login_logout_and_hashed_secrets(self):
        result = self.signup(self.a)
        cookie = result.headers["set-cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=lax", cookie)
        self.assertNotIn("passwordHash", result.json())
        self.assertTrue(self.db.users.find_one()["passwordHash"].startswith("$argon2id$"))
        token = self.a.cookies.get(accounts.COOKIE)
        self.assertIsNotNone(self.db.sessions.find_one({"_id": hashlib.sha256(token.encode()).hexdigest()}))
        self.assertEqual(self.a.get(self.base + "/me").status_code, 200)
        self.assertEqual(self.a.post(self.base + "/logout").status_code, 204)
        self.assertEqual(self.a.get(self.base + "/me").status_code, 401)
        self.assertEqual(self.a.post(self.base + "/login", json={"email": "ALICE@example.com", "password": self.password}).status_code, 200)
        self.assertEqual(self.b.post(self.base + "/login", json={"email": "alice@example.com", "password": "wrong"}).status_code, 401)

    def test_unique_email_and_password_validation(self):
        self.signup(self.a)
        result = self.b.post(self.base + "/signup", json={"displayName": "Other", "email": "ALICE@example.com", "password": self.password})
        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.b.post(self.base + "/signup", json={"displayName": "Other", "email": "b@example.com", "password": "short"}).status_code, 422)

    def test_private_records_and_preferences(self):
        self.signup(self.a)
        self.signup(self.b, "bob@example.com")
        for kind in ("chats", "journals", "goals", "moods"):
            result = self.a.post(f"{self.base}/records/{kind}", json={"data": {"title": "Private", "createdAt": {"__serverTimestamp": True}}})
            self.assertEqual(result.status_code, 201)
            record_id = result.json()["id"]
            self.assertEqual(self.b.get(f"{self.base}/records/{kind}").json(), [])
            self.assertEqual(self.b.patch(f"{self.base}/records/{kind}/{record_id}", json={"data": {"title": "Stolen"}}).status_code, 404)
            self.assertEqual(self.b.delete(f"{self.base}/records/{kind}/{record_id}").status_code, 404)
            self.assertEqual(self.a.patch(f"{self.base}/records/{kind}/{record_id}", json={"data": {"title": "Updated"}}).status_code, 200)
            self.assertEqual(self.a.get(f"{self.base}/records/{kind}").json()[0]["title"], "Updated")
        self.assertEqual(self.a.put(self.base + "/preferences", json={"theme": "blue"}).status_code, 200)
        self.assertEqual(self.b.get(self.base + "/preferences").json()["theme"], "dark")
        self.assertEqual(self.b.get(self.base + "/records/users").status_code, 422)
        self.assertEqual(self.a.post(self.base + "/records/chats", json={"data": {"userId": "bob"}}).status_code, 422)

    def test_csrf_expiration_and_revocation(self):
        self.assertEqual(self.a.post(self.base + "/login", headers={"X-Vital-Sense": ""}, json={"email": "a@example.com", "password": "hello"}).status_code, 403)
        self.assertEqual(self.a.post(self.base + "/login", headers={"Origin": "https://evil.example.com"}, json={"email": "a@example.com", "password": "hello"}).status_code, 403)
        self.signup(self.a)
        self.db.sessions.update_many({}, {"$set": {"expiresAt": accounts.now() - timedelta(seconds=1)}})
        self.assertEqual(self.a.get(self.base + "/me").status_code, 401)

    def test_delete_requires_password_and_removes_all_data_and_sessions(self):
        uid = self.signup(self.a).json()["uid"]
        self.a.post(self.base + "/records/journals", json={"data": {"text": "Private"}})
        self.assertEqual(self.a.request("DELETE", self.base + "/me", json={"password": "wrong"}).status_code, 401)
        self.assertEqual(self.a.request("DELETE", self.base + "/me", json={"password": self.password}).status_code, 204)
        self.assertEqual(self.db.users.count_documents({"_id": uid}), 0)
        self.assertEqual(self.db.records.count_documents({"userId": uid}), 0)
        self.assertEqual(self.db.sessions.count_documents({"userId": uid}), 0)
        self.assertEqual(self.a.get(self.base + "/me").status_code, 401)

    def test_login_rate_limit(self):
        for _ in range(15):
            self.assertEqual(self.a.post(self.base + "/login", json={"email": "nobody@example.com", "password": "wrong"}).status_code, 401)
        self.assertEqual(self.a.post(self.base + "/login", json={"email": "nobody@example.com", "password": "wrong"}).status_code, 429)

    def google_claims(self, client, **changes):
        result = client.post(self.base + "/google/challenge")
        self.assertEqual(result.status_code, 200, result.text)
        claims = {"sub": "google-alice", "email": "alice@example.com", "email_verified": True,
                  "name": "Google Alice", "nonce": result.json()["nonce"]}
        return {**claims, **changes}

    def google_login(self, client, claims, **body):
        with patch.object(accounts.id_token, "verify_oauth2_token", return_value=claims) as verifier:
            result = client.post(self.base + "/google", json={"credential": "test-id-token", **body})
            if verifier.called:
                self.assertEqual(verifier.call_args.args[2], os.environ["GOOGLE_CLIENT_ID"])
            return result

    def test_google_signup_returning_login_and_replay(self):
        claims = self.google_claims(self.a)
        result = self.google_login(self.a, claims)
        self.assertEqual(result.status_code, 200, result.text)
        uid = result.json()["uid"]
        self.assertFalse(result.json()["hasPassword"])
        self.assertIn("HttpOnly", result.headers["set-cookie"])
        self.assertNotIn("passwordHash", self.db.users.find_one({"_id": uid}))
        self.assertEqual(self.a.get(self.base + "/me").json()["uid"], uid)
        # Replay with the old nonce fails even if a cookie is restored.
        self.a.cookies.set(accounts.GOOGLE_COOKIE, claims["nonce"], domain="app.example.com", path="/api/v1/account")
        self.assertEqual(self.google_login(self.a, claims).status_code, 401)
        self.a.post(self.base + "/logout")
        claims = self.google_claims(self.a, email="new-email@example.com")
        self.assertEqual(self.google_login(self.a, claims).json()["uid"], uid)
        self.assertEqual(self.db.users.count_documents({}), 1)
        # A Google-only account never crashes the password login route.
        self.assertEqual(self.a.post(self.base + "/login", json={"email": "alice@example.com", "password": "wrong"}).status_code, 401)

    def test_google_existing_email_requires_password_and_keeps_data(self):
        uid = self.signup(self.a).json()["uid"]
        self.a.post(self.base + "/records/journals", json={"data": {"text": "Keep me"}})
        claims = self.google_claims(self.b)
        self.assertEqual(self.google_login(self.b, claims).status_code, 409)
        self.assertNotIn("googleSub", self.db.users.find_one({"_id": uid}))
        self.assertEqual(self.google_login(self.b, claims, password="wrong").status_code, 401)
        result = self.google_login(self.b, claims, password=self.password)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["uid"], uid)
        self.assertTrue(result.json()["hasPassword"])
        self.assertEqual(self.b.get(self.base + "/records/journals").json()[0]["text"], "Keep me")

    def test_google_rejects_bad_claims_expired_nonce_and_forged_tokens(self):
        for changes in ({"email_verified": False}, {"nonce": "wrong"}, {"sub": ""}, {"azp": "wrong-client"}):
            claims = self.google_claims(self.a, **changes)
            self.assertEqual(self.google_login(self.a, claims).status_code, 401)
        claims = self.google_claims(self.a)
        self.db.limits.update_many({"_id": "google:" + accounts.token_hash(claims["nonce"])}, {"$set": {"expiresAt": accounts.now() - timedelta(seconds=1)}})
        self.assertEqual(self.google_login(self.a, claims).status_code, 401)
        self.google_claims(self.a)
        with patch.object(accounts.id_token, "verify_oauth2_token", side_effect=ValueError("invalid signature/audience/expiry")):
            self.assertEqual(self.a.post(self.base + "/google", json={"credential": "forged"}).status_code, 401)
        self.assertEqual(self.db.users.count_documents({}), 0)

    def test_google_disabled_and_csrf(self):
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": ""}):
            self.assertIsNone(self.a.get(self.base + "/status").json()["googleClientId"])
            self.assertEqual(self.a.post(self.base + "/google/challenge").status_code, 503)
        self.assertEqual(self.a.post(self.base + "/google/challenge", headers={"X-Vital-Sense": ""}).status_code, 403)
        self.assertEqual(self.a.post(self.base + "/google/challenge", headers={"Origin": "https://evil.example.com"}).status_code, 403)

    def test_google_delete_requires_same_google_account_and_fresh_nonce(self):
        claims = self.google_claims(self.a)
        uid = self.google_login(self.a, claims).json()["uid"]
        self.a.post(self.base + "/records/journals", json={"data": {"text": "Private"}})
        self.assertEqual(self.a.request("DELETE", self.base + "/me", json={"password": "anything"}).status_code, 401)
        for subject, expected in (("other-google", 401), ("google-alice", 204)):
            claims = self.google_claims(self.a, sub=subject)
            with patch.object(accounts.id_token, "verify_oauth2_token", return_value=claims):
                self.assertEqual(self.a.request("DELETE", self.base + "/me", json={"credential": "test-id-token"}).status_code, expected)
        self.assertEqual(self.db.users.count_documents({"_id": uid}), 0)
        self.assertEqual(self.db.records.count_documents({"userId": uid}), 0)
        self.assertEqual(self.a.get(self.base + "/me").status_code, 401)
