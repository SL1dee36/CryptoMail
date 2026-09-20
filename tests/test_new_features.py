import asyncio
import unittest
from starlette.requests import Request
from cryptomail.app import app, inbox_route, rsa_reissue_action, ACTIVE_SESSIONS, SESSION_COOKIE_NAME
from cryptomail.database import SessionLocal
from cryptomail.models.user import User
from cryptomail.models.message import Message
from crypto.rsa import find_prime, build_rsa_keypair_from_primes

class TestNewFeatures(unittest.TestCase):
    def test_build_rsa_from_custom_pq(self):
        p = find_prime(1024)
        q = find_prime(1024)
        while q == p:
            q = find_prime(1024)
        priv, pub = build_rsa_keypair_from_primes(p, q)
        self.assertIn(priv.key_size, (2047, 2048))
        self.assertIn(pub.key_size, (2047, 2048))

        msg = b"Antigravity RSA 32K Custom PQ Test"
        c = pub.encrypt(msg)
        d = priv.decrypt(c)
        self.assertEqual(d, msg)

    def test_admin_inbox_has_all_messages(self):
        db = SessionLocal()
        try:
            admin = db.query(User).filter(User.username == "admin").first()
            user = db.query(User).filter(User.username == "alice").first()

            # Admin request
            scope_admin = {
                "type": "http",
                "method": "GET",
                "path": "/inbox",
                "headers": [(b"cookie", f"{SESSION_COOKIE_NAME}=admin_token".encode())],
                "query_string": b"",
                "app": app,
                "session": {"user_id": admin.id, "role": admin.role},
            }
            ACTIVE_SESSIONS["admin_token"] = admin.id
            req_admin = Request(scope_admin)
            res_admin = inbox_route(req_admin, db)
            self.assertEqual(res_admin.status_code, 200)
            body_admin = res_admin.body.decode("utf-8")
            self.assertIn("Все сообщения", body_admin)
            self.assertIn("gm-tab-all", body_admin)
            self.assertIn("gm-all-list", body_admin)

            # Non-admin request
            scope_user = {
                "type": "http",
                "method": "GET",
                "path": "/inbox",
                "headers": [(b"cookie", f"{SESSION_COOKIE_NAME}=alice_token".encode())],
                "query_string": b"",
                "app": app,
                "session": {"user_id": user.id, "role": user.role},
            }
            ACTIVE_SESSIONS["alice_token"] = user.id
            req_user = Request(scope_user)
            res_user = inbox_route(req_user, db)
            self.assertEqual(res_user.status_code, 200)
            body_user = res_user.body.decode("utf-8")
            self.assertNotIn("gm-tab-all", body_user)
            self.assertNotIn("gm-all-list", body_user)
        finally:
            db.close()

    def test_rsa_reissue_custom_pq(self):
        db = SessionLocal()
        try:
            admin = db.query(User).filter(User.username == "admin").first()
            scope = {
                "type": "http",
                "method": "POST",
                "path": "/ecp/rsa/reissue",
                "headers": [(b"cookie", f"{SESSION_COOKIE_NAME}=admin_token2".encode())],
                "query_string": b"",
                "app": app,
                "session": {"user_id": admin.id, "role": admin.role},
            }
            ACTIVE_SESSIONS["admin_token2"] = admin.id
            req = Request(scope)

            p = find_prime(1024)
            q = find_prime(1024)
            while q == p:
                q = find_prime(1024)

            res = asyncio.run(rsa_reissue_action(
                request=req,
                key_size=2048,
                custom_p=str(p),
                custom_q=str(q),
                db=db,
            ))
            self.assertEqual(res.status_code, 303)
            db.refresh(admin)
            self.assertIn("BEGIN PUBLIC KEY", admin.rsa_public_key)

            # Test 2: JSON input in custom_p
            json_str = f'{{"p": "{p}", "q": "{q}"}}'
            res_json = asyncio.run(rsa_reissue_action(
                request=req,
                key_size=2048,
                custom_p=json_str,
                db=db,
            ))
            self.assertEqual(res_json.status_code, 303)

            # Test 3: Invalid P == Q should trigger error alert
            res_err = asyncio.run(rsa_reissue_action(
                request=req,
                key_size=2048,
                custom_p=str(p),
                custom_q=str(p),
                db=db,
            ))
            self.assertEqual(res_err.status_code, 303)
            self.assertEqual(req.session.get("alert_type"), "error")
        finally:
            db.close()

if __name__ == "__main__":
    unittest.main()
