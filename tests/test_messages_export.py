# Description: Unit tests for message delivery, digital signature verification, and PDF/JSON export generation.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import json
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
from main import (
    api_kuznyechik_decrypt,
    api_kuznyechik_encrypt,
    api_rsa_decrypt,
    api_rsa_encrypt,
    api_rsa_generate,
    api_streebog_hash,
    KuznyechikRequest,
    RSADecryptRequest,
    RSAEncryptRequest,
    RSAGenRequest,
    StreebogRequest,
)
from models.message import Message
from models.user import User
from services.auth_service import register_user
from services.export_service import (
    collect_admin_messages_data,
    collect_user_messages_data,
    export_to_json_bytes,
    export_to_pdf_bytes,
)
from services.message_service import decrypt_message_content, send_message


class TestMessagesExportAndAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        cls.Session = sessionmaker(bind=cls.engine)
        Base.metadata.create_all(bind=cls.engine)

    def setUp(self):
        self.db = self.Session()

    def tearDown(self):
        self.db.close()

    def test_send_and_decrypt_rsa_and_streebog(self):
        # Create Alice (User), Bob (User), and Charlie (Guest)
        alice, _ = register_user(self.db, "alice_msg", "alice_msg@cryptomail.local", "AlicePass123!", role="user")
        bob, _ = register_user(self.db, "bob_msg", "bob_msg@cryptomail.local", "BobPass123!", role="user")
        guest, _ = register_user(self.db, "guest_msg", "guest_msg@cryptomail.local", "GuestPass123!", role="guest")

        # 1. Guest attempts to send a message -> Rejected
        _, err = send_message(self.db, guest, bob.id, "Test", "Body", "RSA-32K")
        self.assertIsNotNone(err)

        # 2. Alice sends RSA-32K message to Bob
        msg_rsa, err = send_message(self.db, alice, bob.id, "Секретный проект RSA", "Текст для Боба через RSA-32K", "RSA-32K")
        self.assertIsNone(err)
        self.assertIsNotNone(msg_rsa)
        self.assertEqual(msg_rsa.encryption_type, "RSA-32K")

        # Bob decrypts RSA message
        text_bob, sig_ok, sig_status = decrypt_message_content(self.db, msg_rsa, bob)
        self.assertEqual(text_bob, "Текст для Боба через RSA-32K")
        self.assertTrue(sig_ok)

        # 3. Bob sends Streebog-512 message to Alice
        msg_stree, err = send_message(self.db, bob, alice.id, "Отчет Стрибог", "Текст через Стрибог-512", "STREEBOG-512")
        self.assertIsNone(err)
        self.assertIsNotNone(msg_stree)

        # Alice decrypts Streebog message
        text_alice, sig_ok2, _ = decrypt_message_content(self.db, msg_stree, alice)
        self.assertEqual(text_alice, "Текст через Стрибог-512")
        self.assertTrue(sig_ok2)

    def test_exports_json_and_pdf(self):
        user, _ = register_user(self.db, "export_user", "export_user@cryptomail.local", "ExportPass123!", role="user")
        recipient, _ = register_user(self.db, "export_rec", "export_rec@cryptomail.local", "ExportPass123!", role="user")
        send_message(self.db, user, recipient.id, "Отчет за квартал", "Секретные данные экспорта", "RSA-32K")
        user_data = collect_user_messages_data(self.db, user)
        self.assertTrue(len(user_data) > 0)

        # JSON User Export
        j_bytes = export_to_json_bytes(user_data, "Личный архив")
        j_obj = json.loads(j_bytes.decode("utf-8"))
        self.assertIn("messages", j_obj)
        self.assertEqual(len(j_obj["messages"]), len(user_data))

        # PDF User Export
        pdf_bytes = export_to_pdf_bytes(user_data, "Личный архив", is_user_export=True)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

        # Admin Export
        admin_data = collect_admin_messages_data(self.db, target_user_id=None)
        self.assertTrue(len(admin_data) > 0)
        pdf_admin = export_to_pdf_bytes(admin_data, "Аудит администратора")
        self.assertTrue(pdf_admin.startswith(b"%PDF"))

    def test_rest_api_crypto_endpoints(self):
        # 1. RSA Generate API
        data = api_rsa_generate(RSAGenRequest(bits=2048))
        self.assertIn("public_key_pem", data)
        pub_pem = data["public_key_pem"]
        priv_pem = data["private_key_pem"]

        # 2. RSA Encrypt API
        enc_res = api_rsa_encrypt(RSAEncryptRequest(public_key_pem=pub_pem, data="Hello API"))
        bundle = enc_res["encrypted_bundle"]

        # 3. RSA Decrypt API
        dec_res = api_rsa_decrypt(RSADecryptRequest(private_key_pem=priv_pem, bundle_json=bundle))
        self.assertEqual(dec_res["decrypted_data"], "Hello API")

        # 4. Kuznyechik Encrypt/Decrypt API
        key_hex = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
        kuz_res = api_kuznyechik_encrypt(KuznyechikRequest(key_hex=key_hex, data="Kuzya", mode="cbc"))
        ct_b64 = kuz_res["ciphertext_base64"]

        kuz_dec = api_kuznyechik_decrypt(KuznyechikRequest(key_hex=key_hex, data=ct_b64, mode="cbc"))
        self.assertEqual(kuz_dec["decrypted_data"], "Kuzya")

        # 5. Streebog Hash API
        stree_res = api_streebog_hash(StreebogRequest(data="test", bits=512))
        self.assertIn("hash_streebog512", stree_res)


if __name__ == "__main__":
    unittest.main()
