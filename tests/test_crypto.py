# Description: Unit tests for cryptographic core: RFC 7801, RFC 6986, RSA-32K, digital signatures, and DB encryption.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import json
import unittest
from crypto.kuznyechik import Kuznyechik
from crypto.streebog import streebog512, streebog256, hmac_streebog512, pbkdf2_streebog512
from crypto.rsa32k import generate_rsa_keypair, rsa_encrypt_hybrid, rsa_decrypt_hybrid
from crypto.ecp import (
    generate_ecp_keypair,
    issue_self_signed_certificate,
    verify_certificate,
    sign_message,
    verify_message_signature,
)
from crypto.db_cipher import encrypt_db_field, decrypt_db_field


class TestCryptoSubsystem(unittest.TestCase):

    def test_kuznyechik_rfc7801(self):
        """Verify Kuznyechik block cipher against official RFC 7801 test vector."""
        key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        plaintext = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
        expected_ct = "7f679d90bebc24305a468d42b9d4edcd"

        cipher = Kuznyechik(key)
        ct = cipher.encrypt_block(plaintext)
        self.assertEqual(ct.hex(), expected_ct)

        dt = cipher.decrypt_block(ct)
        self.assertEqual(dt, plaintext)

    def test_kuznyechik_cbc_and_ctr(self):
        key = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        cipher = Kuznyechik(key)
        data = b"Arbitrary length secret message to test GOST Kuznyechik in CBC and CTR modes."

        enc_cbc = cipher.encrypt_cbc(data)
        dec_cbc = cipher.decrypt_cbc(enc_cbc)
        self.assertEqual(dec_cbc, data)

        enc_ctr = cipher.encrypt_ctr(data)
        dec_ctr = cipher.decrypt_ctr(enc_ctr)
        self.assertEqual(dec_ctr, data)

    def test_streebog512_rfc6986(self):
        """Verify Streebog-512 against official RFC 6986 test vector M1."""
        m1 = bytes.fromhex("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130")
        expected_h = "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b"
        h = streebog512(m1)
        self.assertEqual(h.hex(), expected_h)

    def test_streebog_hmac_and_pbkdf2(self):
        key = b"supersecret"
        msg = b"message to authenticate"
        tag = hmac_streebog512(key, msg)
        self.assertEqual(len(tag), 64)

        salt = b"random_salt_16b_"
        dk = pbkdf2_streebog512("PassWord123!", salt, iterations=50, dklen=32)
        self.assertEqual(len(dk), 32)

    def test_rsa_hybrid_envelope(self):
        priv, pub = generate_rsa_keypair(key_size=2048)
        message = "Секретное сообщение для проверки гибридного конвертного шифрования RSA."
        bundle_str = rsa_encrypt_hybrid(pub, message)
        bundle = json.loads(bundle_str)
        self.assertIn("enc_key", bundle)
        self.assertIn("ciphertext", bundle)

        dec = rsa_decrypt_hybrid(priv, bundle_str)
        self.assertEqual(dec.decode("utf-8"), message)

    def test_ecp_signature_and_cert(self):
        priv, pub = generate_ecp_keypair()
        cert = issue_self_signed_certificate("alice", 42, priv, pub)
        self.assertTrue(verify_certificate(cert))

        message = b"Signed document payload"
        sig = sign_message(priv, message)
        self.assertTrue(verify_message_signature(pub, message, sig))

        tampered = b"Modified document payload"
        self.assertFalse(verify_message_signature(pub, tampered, sig))

    def test_db_kuznyechik_field_encryption(self):
        secret = "Очень конфиденциальные данные пользователя в базе данных"
        encrypted = encrypt_db_field(secret)
        self.assertNotEqual(encrypted, secret)
        decrypted = decrypt_db_field(encrypted)
        self.assertEqual(decrypted, secret)

    def test_rsa_parallel_generation(self):
        from crypto.rsa_parallel import generate_rsa_keypair_parallel
        priv, pub, stats = generate_rsa_keypair_parallel(key_size=2048, num_workers=2, verbose=False)
        self.assertEqual(priv.key_size, 2048)
        self.assertGreater(stats["total_candidates"], 0)
        self.assertGreater(stats["elapsed_seconds"], 0)

    def test_rsa_pregen_and_build(self):
        import os
        import shutil
        from cli import generate_and_save_pq, load_pregen_primes
        from crypto.rsa32k import build_rsa_keypair_from_primes, rsa_encrypt_hybrid, rsa_decrypt_hybrid

        test_dir = os.path.join(os.path.dirname(__file__), "..", "data", "test_pregen_unit")
        try:
            res = generate_and_save_pq(bits=2048, out_dir=test_dir, threads=2, verbose=False)
            self.assertIn("p", res)
            self.assertIn("q", res)
            self.assertEqual(res["key_size"], 2048)

            p, q = load_pregen_primes(test_dir)
            self.assertEqual(p, res["p"])
            self.assertEqual(q, res["q"])
            self.assertEqual((p * q).bit_length(), 2048)

            priv, pub = build_rsa_keypair_from_primes(p, q)
            self.assertEqual(priv.key_size, 2048)

            # Check encryption and decryption with key assembled from precomputed primes
            msg = "Тестовое сообщение для проверки pregen ключа"
            bundle = rsa_encrypt_hybrid(pub, msg)
            dec = rsa_decrypt_hybrid(priv, bundle).decode("utf-8")
            self.assertEqual(dec, msg)
        finally:
            if os.path.exists(test_dir):
                shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

