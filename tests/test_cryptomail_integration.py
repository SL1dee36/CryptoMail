# Description: Comprehensive integration test suite for CryptoMail application.
# Tests DB encryption at rest, 3FA, regexes, RSA-2k/4k/8k/32k, Kuznyechik, ECP, and exports.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import json
import os
import sys
import unittest

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

from cryptomail.app import app, seed_default_users, index_route, login_guest, mailtrap_route
from cryptomail.database import SessionLocal, init_db
from cryptomail.models.message import Message
from cryptomail.models.user import User
from cryptomail.services.auth_service import (
    generate_totp_code,
    hash_password,
    register_user,
    start_3fa_login,
    validate_registration_inputs,
    verify_3fa_factor2,
    verify_3fa_factor3,
    verify_password,
)
from cryptomail.services.export_service import export_to_json_bytes, export_to_pdf_bytes
from cryptomail.services.mail_server import get_all_received_emails, send_system_email
from cryptomail.services.message_service import decrypt_message_content, send_message


class TestCryptoMailIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        seed_default_users()

    def test_01_registration_regex_validation(self):
        """Test username, email, and password complexity regexes."""
        # Invalid username (too short, illegal symbols)
        val, err = validate_registration_inputs("ab", "test@mail.ru", "ValidPass123!")
        self.assertFalse(val)

        val, err = validate_registration_inputs("user@name", "test@mail.ru", "ValidPass123!")
        self.assertFalse(val)

        # Invalid email
        val, err = validate_registration_inputs("valid_user", "invalid-email", "ValidPass123!")
        self.assertFalse(val)

        # Weak password (missing uppercase, number, or special char)
        val, err = validate_registration_inputs("valid_user", "test@mail.ru", "nouppercase123!")
        self.assertFalse(val)

        val, err = validate_registration_inputs("valid_user", "test@mail.ru", "NOLOWERCASE123!")
        self.assertFalse(val)

        val, err = validate_registration_inputs("valid_user", "test@mail.ru", "NoDigitsAndSpecial")
        self.assertFalse(val)

        # Valid credentials
        val, err = validate_registration_inputs("valid_user-99", "test@mail.ru", "StrongPassword123!")
        self.assertTrue(val)
        self.assertIsNone(err)

    def test_02_password_hashing_streebog512(self):
        """Test PBKDF2 password hashing with GOST Streebog-512."""
        pwd = "TestSecretPassword123!"
        h1, salt1 = hash_password(pwd)
        self.assertEqual(len(h1), 128)  # 64 bytes hex
        self.assertEqual(len(salt1), 32)  # 16 bytes hex
        self.assertTrue(verify_password(pwd, h1, salt1))
        self.assertFalse(verify_password("WrongPassword123!", h1, salt1))

    def test_03_database_encryption_at_rest(self):
        """Verify that private keys and recovery codes are encrypted in SQLite by Kuznyechik."""
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == "admin").first()
            self.assertIsNotNone(user)
            # When accessed via ORM model, transparently decrypted
            self.assertIn("BEGIN", user.rsa_private_key)
            self.assertIn("BEGIN", user.ecp_private_key)
            self.assertIsInstance(user.recovery_codes_list, list)
            self.assertGreater(len(user.recovery_codes_list), 0)

            # Check raw database record directly via SQL to ensure it's not plaintext on disk!
            raw_row = db.execute(
                __import__("sqlalchemy").text("SELECT rsa_private_key, ecp_private_key FROM users WHERE username = 'admin'")
            ).fetchone()
            raw_rsa_priv = raw_row[0]
            raw_ecp_priv = raw_row[1]

            # Raw stored string MUST NOT contain "BEGIN RSA PRIVATE KEY" in plaintext!
            self.assertNotIn("BEGIN RSA PRIVATE KEY", raw_rsa_priv)
            self.assertNotIn("BEGIN PRIVATE KEY", raw_ecp_priv)
        finally:
            db.close()

    def test_04_full_3fa_pipeline(self):
        """Test 3FA: Factor 1 (Password) -> Factor 2 (SMTP OTP) -> Factor 3 (TOTP / Recovery Code)."""
        db = SessionLocal()
        try:
            # 1. Start 3FA Login
            sess_id, user, err = start_3fa_login(db, "alice", "AlicePassword123!")
            self.assertIsNone(err)
            self.assertIsNotNone(sess_id)
            self.assertEqual(user.username, "alice")

            # 2. Factor 2: Read OTP from mail_server
            emails = get_all_received_emails()
            latest_email = next((e for e in emails if "alice" in e["to"]), None)
            self.assertIsNotNone(latest_email)
            otp = latest_email["otp_code"]
            self.assertIsNotNone(otp)

            # Verify Factor 2
            ok2, err2 = verify_3fa_factor2(sess_id, otp)
            self.assertTrue(ok2)
            self.assertIsNone(err2)

            # 3. Factor 3: TOTP or Recovery Code
            # Let's test with TOTP first
            totp_code = generate_totp_code(user.totp_secret)
            auth_user, err3 = verify_3fa_factor3(sess_id, totp_code, db)
            self.assertIsNone(err3)
            self.assertIsNotNone(auth_user)
            self.assertEqual(auth_user.id, user.id)

            # Now test Factor 3 with one-time recovery code on a new login session
            sess_id2, user2, _ = start_3fa_login(db, "bob", "BobPassword123!")
            emails2 = get_all_received_emails()
            latest2 = next((e for e in emails2 if "bob" in e["to"]), None)
            verify_3fa_factor2(sess_id2, latest2["otp_code"])

            unused_rec_code = user2.recovery_codes_list[0]
            initial_count = len(user2.recovery_codes_list)
            auth_user2, err_rec = verify_3fa_factor3(sess_id2, unused_rec_code, db)
            self.assertIsNone(err_rec)
            self.assertEqual(auth_user2.id, user2.id)

            # Verify the recovery code was consumed and removed from user
            db.refresh(user2)
            self.assertEqual(len(user2.recovery_codes_list), initial_count - 1)
            self.assertNotIn(unused_rec_code, user2.recovery_codes_list)
        finally:
            db.close()

    def test_05_guest_rank_restrictions(self):
        """Verify guest user has no permissions to send messages."""
        db = SessionLocal()
        try:
            guest = db.query(User).filter(User.role == "guest").first()
            alice = db.query(User).filter(User.username == "alice").first()
            msg, err = send_message(
                db=db,
                sender=guest,
                recipient_id=alice.id,
                subject="Guest test",
                body="Attempting to send",
                encryption_type="RSA-2048",
            )
            self.assertIsNone(msg)
            self.assertIn("Гость", err)
        finally:
            db.close()

    def test_06_message_encryption_and_ecp_signature(self):
        """Test sending message with RSA-4096, Kuznyechik-256, and RSA-32K, with ECP signing."""
        db = SessionLocal()
        try:
            alice = db.query(User).filter(User.username == "alice").first()
            bob = db.query(User).filter(User.username == "bob").first()

            # Test 1: RSA-4096 with ECP signature
            msg_rsa, err = send_message(
                db=db,
                sender=alice,
                recipient_id=bob.id,
                subject="RSA-4K Test",
                body="Секретные данные для Боба (RSA-4096)",
                encryption_type="RSA-4096",
                sign_ecp=True,
            )
            self.assertIsNone(err)
            self.assertIsNotNone(msg_rsa.ecp_signature)

            # Recipient decrypts and verifies ECP
            dec_text, sig_ok, sig_comm, cert = decrypt_message_content(db, msg_rsa, bob)
            self.assertEqual(dec_text, "Секретные данные для Боба (RSA-4096)")
            self.assertTrue(sig_ok)
            self.assertIn("ПОДЛИННАЯ", sig_comm)

            # Sender also can read what she sent!
            dec_sender, _, _, _ = decrypt_message_content(db, msg_rsa, alice)
            self.assertEqual(dec_sender, "Секретные данные для Боба (RSA-4096)")

            # Test 2: Kuznyechik-256 (CBC)
            msg_kuz, err_kuz = send_message(
                db=db,
                sender=alice,
                recipient_id=bob.id,
                subject="Kuznyechik-256 Test",
                body="Секретное сообщение ГОСТ Кузнечик CBC",
                encryption_type="KUZNYECHIK-256",
                sign_ecp=True,
            )
            self.assertIsNone(err_kuz)
            dec_kuz, sig_kuz, _, _ = decrypt_message_content(db, msg_kuz, bob)
            self.assertEqual(dec_kuz, "Секретное сообщение ГОСТ Кузнечик CBC")
            self.assertTrue(sig_kuz)

            # Test 3: RSA-32768 (32K) using pregen primes
            msg_32k, err_32k = send_message(
                db=db,
                sender=alice,
                recipient_id=bob.id,
                subject="RSA-32K Extreme Test",
                body="Сверхзащищенное сообщение RSA-32768!",
                encryption_type="RSA-32768",
                sign_ecp=True,
            )
            self.assertIsNone(err_32k)
            dec_32k, sig_32k, _, _ = decrypt_message_content(db, msg_32k, bob)
            self.assertEqual(dec_32k, "Сверхзащищенное сообщение RSA-32768!")
            self.assertTrue(sig_32k)
        finally:
            db.close()

    def test_07_export_json_and_pdf(self):
        """Test exporting messages to JSON and PDF with decrypted + encrypted fields."""
        db = SessionLocal()
        try:
            admin = db.query(User).filter(User.username == "admin").first()
            messages = db.query(Message).all()
            self.assertGreater(len(messages), 0)

            from cryptomail.app import _build_export_payload
            data = _build_export_payload(db, messages, admin, variant="all")

            # Check structure contains both decrypted and encrypted info
            self.assertIn("messages", data)
            first = data["messages"][0]
            self.assertIn("decrypted_body", first)
            self.assertIn("ciphertext", first)
            self.assertIn("key_bundle", first)

            # Test JSON serialization
            json_bytes = export_to_json_bytes(data)
            self.assertGreater(len(json_bytes), 100)
            parsed = json.loads(json_bytes.decode("utf-8"))
            self.assertEqual(len(parsed["messages"]), len(messages))

            # Test PDF generation (ReportLab with Cyrillic font)
            pdf_bytes = export_to_pdf_bytes(data, title="Тестовый аудит-отчет")
            self.assertGreater(len(pdf_bytes), 500)
            self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        finally:
            db.close()

    def test_08_http_routes_and_admin_panel(self):
        """Test HTTP web endpoint logic directly."""
        db = SessionLocal()
        try:
            # 1. Guest login response
            res_guest = login_guest(db)
            self.assertEqual(res_guest.status_code, 302)
            self.assertEqual(res_guest.headers["location"], "/inbox")
            self.assertIn("set-cookie", res_guest.headers)

            # 2. Build mock request for root route (redirects to /login)
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [],
                "query_string": b"",
                "app": app,
            }
            from starlette.requests import Request
            req = Request(scope)
            res_index = index_route(req, db)
            self.assertEqual(res_index.status_code, 302)
            self.assertEqual(res_index.headers["location"], "/login")

            # 3. MailTrap inbox route
            res_mailtrap = mailtrap_route(req)
            self.assertEqual(res_mailtrap.status_code, 200)
            self.assertIn("MailTrap", res_mailtrap.body.decode("utf-8"))
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
