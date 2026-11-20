"""Integration checks against an isolated disposable local MongoDB database."""
import hashlib
import os
import secrets
import unittest
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
