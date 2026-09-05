# Description: Unit tests for background crypto task tracker service and decrypted memory cache.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import time
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base, SessionLocal
from models.user import User
from services.auth_service import register_user
from services.crypto_task_service import (
    start_encryption_task,
    start_decryption_task,
    get_task,
    get_user_tasks,
    get_cached_decrypted_message,
    clear_cached_decrypted_message,
)


class TestCryptoTaskService(unittest.TestCase):

    def setUp(self):
        self.db = SessionLocal()
        # Find or register two users
        self.u1 = self.db.query(User).filter(User.username == "test_sender").first()
        if not self.u1:
            self.u1, _ = register_user(
                self.db, "test_sender", "test_sender@mail.local", "StrongPass123!", role="user", rsa_key_size=2048
            )
        self.u2 = self.db.query(User).filter(User.username == "test_recipient").first()
        if not self.u2:
            self.u2, _ = register_user(
                self.db, "test_recipient", "test_rec@mail.local", "StrongPass123!", role="user", rsa_key_size=2048
            )

    def tearDown(self):
        self.db.close()

    def test_encryption_and_decryption_tracking(self):
        # 1. Start encryption task
        task_id = start_encryption_task(
            self.u1.id,
            self.u2.id,
            "Тестовая тема",
            "Тестовое защищенное сообщение",
            "RSA",
        )
        self.assertIsNotNone(task_id)

        # Poll until finished or timeout
        t0 = time.time()
        final_enc = None
        while time.time() - t0 < 8:
            task = get_task(task_id)
            self.assertIsNotNone(task)
            self.assertIn("iterations", task)
            self.assertIn("candidates", task)
            self.assertIn("elapsed_seconds", task)
            self.assertIn("stage", task)
            if task["status"] in ("completed", "error"):
                final_enc = task
                break
            time.sleep(0.15)

        self.assertIsNotNone(final_enc)
        self.assertEqual(final_enc["status"], "completed", f"Error: {final_enc.get('error')}")
        self.assertIsNotNone(final_enc["message_id"])
        self.assertGreater(final_enc["iterations"], 0)
        self.assertGreater(final_enc["candidates"], 0)

        # 2. Start decryption task for the created message
        msg_id = final_enc["message_id"]
        # Verify message is not yet in memory cache
        clear_cached_decrypted_message(self.u2.id, msg_id)
        self.assertIsNone(get_cached_decrypted_message(self.u2.id, msg_id))

        dec_task_id = start_decryption_task(self.u2.id, msg_id)
        self.assertIsNotNone(dec_task_id)

        t0 = time.time()
        final_dec = None
        while time.time() - t0 < 8:
            task = get_task(dec_task_id)
            self.assertIsNotNone(task)
            if task["status"] in ("completed", "error"):
                final_dec = task
                break
            time.sleep(0.15)

        self.assertIsNotNone(final_dec)
        self.assertEqual(final_dec["status"], "completed", f"Error: {final_dec.get('error')}")
        self.assertIsNotNone(final_dec["result"])
        self.assertEqual(final_dec["result"]["decrypted_content"], "Тестовое защищенное сообщение")
        self.assertTrue(final_dec["result"]["is_sig_valid"])

        # Verify message is now present in in-memory cache
        cached = get_cached_decrypted_message(self.u2.id, msg_id)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["decrypted_content"], "Тестовое защищенное сообщение")
        self.assertTrue(cached["is_sig_valid"])
        self.assertIn("timestamp", cached)

        # Verify clear works
        clear_cached_decrypted_message(self.u2.id, msg_id)
        self.assertIsNone(get_cached_decrypted_message(self.u2.id, msg_id))


if __name__ == "__main__":
    unittest.main()
