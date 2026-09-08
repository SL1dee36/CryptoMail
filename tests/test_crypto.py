# Description: Unit tests for cryptographic core: RFC 7801, RFC 6986, RSA-32K, digital signatures, and DB encryption.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import json
import logging
import os
import sys
import time
import unittest

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Configure test runner logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("test_crypto")

from crypto.kuznyechik import Kuznyechik
from crypto.streebog import streebog512, streebog256, hmac_streebog512, pbkdf2_streebog512
from crypto.rsa import (
    build_rsa_keypair_from_primes,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    get_or_create_rsa_keypair,
    load_private_key_pem,
    load_public_key_pem,
    oaep_pad,
    oaep_unpad,
    rsa_decrypt_hybrid,
    rsa_encrypt_hybrid,
)
from crypto.ecp import (
    generate_ecp_keypair,
    issue_self_signed_certificate,
    verify_certificate,
    sign_message,
    verify_message_signature,
    export_ecp_private_key_pem,
    export_ecp_public_key_pem,
    load_ecp_private_key_pem,
    load_ecp_public_key_pem,
    CURVE_GOST_2012_256,
    CURVE_GOST_2012_512,
    GostPrivateKey,
    sign_file,
    verify_file_signature,
)
from crypto.db_cipher import encrypt_db_field, decrypt_db_field


class TestCryptoSubsystem(unittest.TestCase):

    def setUp(self):
        self._start_time = time.time()
        logger.info(">>> ЗАПУСК ТЕСТА: %s", self._testMethodName)

    def tearDown(self):
        elapsed = time.time() - self._start_time
        logger.info("<<< ТЕСТ ЗАВЕРШЕН: %s (время: %.3f с)\n", self._testMethodName, elapsed)

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
        """Verify Streebog-512 against official RFC 6986 test vectors M1 and M2."""
        m1 = bytes.fromhex("303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132")
        expected_m1 = "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
        h = streebog512(m1)
        self.assertEqual(h.hex(), expected_m1)

        m2 = bytes.fromhex("d0e5e1e5e4e820eff0eeeceee2e820eaeef0eef1e5ec20f0e0e4eee1e0eb2c20e4ebff20efeff0eef8e5e3eee2e0edf820d1f2f0e8e1eee3e020f1eef2e8")
        expected_m2 = "0b1d78600f99c71bfe3b365cc3fab0e0e2c8193ddb6f1fd9a0683fabf62b24f4bf1f5d00bd6a7b55e351d855e86859d986a5c99e487ef1b205add99d31bcca9a"
        self.assertEqual(streebog512(m2).hex(), expected_m2)

    def test_streebog256_rfc6986(self):
        """Verify Streebog-256 against official RFC 6986 test vectors M1 and M2."""
        m1 = bytes.fromhex("303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132")
        expected_m1 = "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
        self.assertEqual(streebog256(m1).hex(), expected_m1)

        m2 = bytes.fromhex("d0e5e1e5e4e820eff0eeeceee2e820eaeef0eef1e5ec20f0e0e4eee1e0eb2c20e4ebff20efeff0eef8e5e3eee2e0edf820d1f2f0e8e1eee3e020f1eef2e8")
        expected_m2 = "6fe9b5adda62b91fb689ffe4e8c4614ffd87dfe24b5d3c2d25e5a3a9469e780f"
        self.assertEqual(streebog256(m2).hex(), expected_m2)

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
        self.assertIn("hmac", bundle)

        dec = rsa_decrypt_hybrid(priv, bundle_str)
        self.assertEqual(dec.decode("utf-8"), message)

        # Verify HMAC tampering detection
        tampered_bundle = dict(bundle)
        raw_ct = list(tampered_bundle["ciphertext"])
        raw_ct[0] = "A" if raw_ct[0] != "A" else "B"
        tampered_bundle["ciphertext"] = "".join(raw_ct)
        with self.assertRaises(ValueError):
            rsa_decrypt_hybrid(priv, json.dumps(tampered_bundle))

    def test_rsa_pem_export_load_roundtrip(self):
        priv, pub = generate_rsa_keypair(key_size=2048)
        priv_pem = export_private_key_pem(priv)
        pub_pem = export_public_key_pem(pub)
        self.assertTrue(priv_pem.startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(pub_pem.startswith("-----BEGIN PUBLIC KEY-----"))

        loaded_priv = load_private_key_pem(priv_pem)
        loaded_pub = load_public_key_pem(pub_pem)
        self.assertEqual(loaded_priv.n, priv.n)
        self.assertEqual(loaded_priv.d, priv.d)
        self.assertEqual(loaded_pub.n, pub.n)
        self.assertEqual(loaded_pub.e, pub.e)
        self.assertEqual(loaded_priv.key_size, 2048)
        self.assertEqual(loaded_pub.key_size, 2048)

        # Cross encrypt/decrypt with reloaded keys
        test_msg = "Тестовое сообщение для проверки сериализации RSA в PEM"
        bundle = rsa_encrypt_hybrid(loaded_pub, test_msg)
        decrypted = rsa_decrypt_hybrid(loaded_priv, bundle).decode("utf-8")
        self.assertEqual(decrypted, test_msg)

    def test_rsa_oaep_pad_unpad(self):
        k = 256  # 2048-bit modulus byte length
        secret = b"My top secret session key 123456"
        padded = oaep_pad(secret, k)
        self.assertEqual(len(padded), k)
        self.assertEqual(padded[0], 0)

        unpadded = oaep_unpad(padded, k)
        self.assertEqual(unpadded, secret)

        # Corrupted padded message must raise ValueError
        bad_padded = bytearray(padded)
        bad_padded[10] ^= 0xFF
        with self.assertRaises(ValueError):
            oaep_unpad(bytes(bad_padded), k)


    def test_ecp_signature_and_cert(self):
        priv, pub = generate_ecp_keypair()
        cert = issue_self_signed_certificate("alice", 42, priv, pub)
        self.assertTrue(verify_certificate(cert))

        message = b"Signed document payload"
        sig = sign_message(priv, message)
        self.assertTrue(verify_message_signature(pub, message, sig))

        tampered = b"Modified document payload"
        self.assertFalse(verify_message_signature(pub, tampered, sig))

    def test_ecp_256_bit_signature_and_cert(self):
        priv, pub = generate_ecp_keypair(256)
        self.assertEqual(priv.key_size, 256)
        self.assertEqual(pub.key_size, 256)

        cert = issue_self_signed_certificate("bob", 43, priv, pub)
        self.assertTrue(verify_certificate(cert))
        self.assertIn("GOST-R-34.10-2012-256", cert["signature_algorithm"])

        message = b"Another test message for GOST 256"
        sig = sign_message(priv, message)
        self.assertTrue(verify_message_signature(pub, message, sig))
        self.assertFalse(verify_message_signature(pub, message + b"!", sig))

    def test_ecp_rfc7091_vector(self):
        """Verify GOST R 34.10-2012 against official RFC 7091 Section 7 test vector."""
        curve = CURVE_GOST_2012_256
        d_rfc = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
        priv = GostPrivateKey(d_rfc, curve)
        pub = priv.public_key()

        exp_xq = 0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B
        exp_yq = 0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA
        self.assertEqual(pub.x, exp_xq)
        self.assertEqual(pub.y, exp_yq)

        # RFC 7091 Section 7.2 intermediate values
        e_rfc = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
        k_rfc = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3

        C = curve.point_mul(k_rfc, curve.P)
        r = C[0] % curve.q
        s = (r * d_rfc + k_rfc * e_rfc) % curve.q

        exp_r = 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493
        exp_s = 0x1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40
        self.assertEqual(r, exp_r)
        self.assertEqual(s, exp_s)

        # RFC 7091 Section 7.3 verification
        v = pow(e_rfc, -1, curve.q)
        z1 = (s * v) % curve.q
        z2 = (-r * v) % curve.q
        C_ver = curve.point_add(curve.point_mul(z1, curve.P), curve.point_mul(z2, (pub.x, pub.y)))
        self.assertIsNotNone(C_ver)
        self.assertEqual(C_ver[0] % curve.q, r)

    def test_ecp_pem_export_load(self):
        for bits in (512, 256):
            priv, pub = generate_ecp_keypair(bits)
            priv_pem = export_ecp_private_key_pem(priv)
            pub_pem = export_ecp_public_key_pem(pub)

            loaded_priv = load_ecp_private_key_pem(priv_pem)
            loaded_pub = load_ecp_public_key_pem(pub_pem)

            self.assertEqual(loaded_priv.d, priv.d)
            self.assertEqual(loaded_pub.x, pub.x)
            self.assertEqual(loaded_pub.y, pub.y)
            self.assertEqual(loaded_priv.key_size, bits)
            self.assertEqual(loaded_pub.key_size, bits)

            # Test cross sign/verify with reloaded keys
            msg = f"Testing PEM roundtrip with {bits}-bit key".encode("utf-8")
            sig = sign_message(loaded_priv, msg)
            self.assertTrue(verify_message_signature(loaded_pub, msg, sig))

    def test_ecp_detached_sig_files(self):
        import tempfile
        import os

        priv, pub = generate_ecp_keypair(512)

        with tempfile.TemporaryDirectory() as tmp_dir:
            data_file = os.path.join(tmp_dir, "contract.pdf")
            sig_file_b64 = os.path.join(tmp_dir, "contract.pdf.sig")
            sig_file_bin = os.path.join(tmp_dir, "contract_bin.sig")

            with open(data_file, "wb") as f:
                f.write(b"OFFICIAL CONTRACT DATA \x00\x01\x02\xFF")

            # 1. Base64 detached CMS signature
            sig_b64 = sign_file(priv, data_file, out_sig_path=sig_file_b64, binary=False)
            self.assertTrue(os.path.exists(sig_file_b64))
            self.assertTrue(verify_file_signature(pub, data_file, sig_file_b64))
            self.assertTrue(verify_file_signature(pub, data_file, sig_b64))
            # Verification also works without passing pub explicitly because CMS has embedded X.509 cert!
            self.assertTrue(verify_file_signature(None, data_file, sig_file_b64))

            # 2. Binary detached CMS signature (ASN.1 DER format conforming to RFC 5652 / RFC 9215)
            sig_bin = sign_file(priv, data_file, out_sig_path=sig_file_bin, binary=True)
            self.assertTrue(os.path.exists(sig_file_bin))
            self.assertEqual(sig_bin[0], 0x30)  # Valid ASN.1 SEQUENCE tag!
            self.assertTrue(verify_file_signature(pub, data_file, sig_file_bin))
            self.assertTrue(verify_file_signature(None, data_file, sig_bin))

            # 3. Raw detached signature (cms=False)
            sig_raw_file = os.path.join(tmp_dir, "raw.sig")
            sig_raw = sign_file(priv, data_file, out_sig_path=sig_raw_file, binary=True, cms=False)
            self.assertEqual(len(sig_raw), 128)  # 512-bit curve => 128 bytes raw signature
            self.assertTrue(verify_file_signature(pub, data_file, sig_raw_file))

            # 4. Tampered data file verification failure
            tampered_file = os.path.join(tmp_dir, "tampered.pdf")
            with open(tampered_file, "wb") as f:
                f.write(b"OFFICIAL CONTRACT DATA \x00\x01\x02\xFE")
            self.assertFalse(verify_file_signature(pub, tampered_file, sig_file_b64))
            self.assertFalse(verify_file_signature(pub, tampered_file, sig_file_bin))
            self.assertFalse(verify_file_signature(pub, tampered_file, sig_raw_file))

            # 5. 256-bit detached signature
            priv256, pub256 = generate_ecp_keypair(256)
            sig_file_256 = os.path.join(tmp_dir, "contract256.sig")
            sig_bin256 = sign_file(priv256, data_file, out_sig_path=sig_file_256, binary=True)
            self.assertEqual(sig_bin256[0], 0x30)  # CMS ASN.1 SEQUENCE
            self.assertTrue(verify_file_signature(pub256, data_file, sig_file_256))

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
        from crypto.rsa import build_rsa_keypair_from_primes, rsa_encrypt_hybrid, rsa_decrypt_hybrid

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

    def test_rsa_4k_hybrid(self):
        """Test RSA-4096 hybrid encryption and PEM serialization."""
        logger.info("RSA-4096: Загрузка или генерация ключа 4096 бит...")
        priv, pub = get_or_create_rsa_keypair(key_size=4096)
        self.assertEqual(priv.key_size, 4096)
        self.assertEqual(pub.key_size, 4096)
        logger.info("RSA-4096: Ключевая пара готова (%d бит)", pub.key_size)

        priv_pem = export_private_key_pem(priv)
        pub_pem = export_public_key_pem(pub)
        self.assertTrue(priv_pem.startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(pub_pem.startswith("-----BEGIN PUBLIC KEY-----"))

        loaded_priv = load_private_key_pem(priv_pem)
        loaded_pub = load_public_key_pem(pub_pem)
        self.assertEqual(loaded_priv.n, priv.n)
        self.assertEqual(loaded_pub.n, pub.n)
        logger.info("RSA-4096: Сериализация и парсинг PEM подтверждены")

        message = "Тестовое секретное сообщение для проверки RSA-4096 гибридного конверта."
        logger.info("RSA-4096: Гибридное конвертное шифрование (Кузнечик-CTR + HMAC-Стрибог512)...")
        bundle_str = rsa_encrypt_hybrid(pub, message)
        bundle = json.loads(bundle_str)
        self.assertEqual(bundle["key_bits"], 4096)
        self.assertIn("enc_key", bundle)
        self.assertIn("hmac", bundle)

        logger.info("RSA-4096: Расшифрование пакета...")
        dec = rsa_decrypt_hybrid(priv, bundle_str)
        self.assertEqual(dec.decode("utf-8"), message)
        logger.info("RSA-4096: Расшифрованное сообщение совпадает с исходным")

        # Tampering detection
        logger.info("RSA-4096: Проверка обнаружения подделки HMAC...")
        tampered = dict(bundle)
        tampered["hmac"] = base64.b64encode(b"\x00" * 64).decode("ascii")
        with self.assertRaises(ValueError):
            rsa_decrypt_hybrid(priv, json.dumps(tampered))
        logger.info("RSA-4096: Поддельный HMAC успешно отклонен")

    def test_rsa_8k_hybrid(self):
        """Test RSA-8192 hybrid encryption and PEM serialization."""
        logger.info("RSA-8192: Загрузка или генерация ключа 8192 бит...")
        priv, pub = get_or_create_rsa_keypair(key_size=8192)
        self.assertEqual(priv.key_size, 8192)
        self.assertEqual(pub.key_size, 8192)
        logger.info("RSA-8192: Ключевая пара готова (%d бит)", pub.key_size)

        priv_pem = export_private_key_pem(priv)
        pub_pem = export_public_key_pem(pub)
        self.assertTrue(priv_pem.startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(pub_pem.startswith("-----BEGIN PUBLIC KEY-----"))

        loaded_priv = load_private_key_pem(priv_pem)
        self.assertEqual(loaded_priv.n, priv.n)
        logger.info("RSA-8192: Сериализация и парсинг PEM подтверждены")

        message = "Тестовое конфиденциальное сообщение для проверки RSA-8192 гибридного шифрования."
        logger.info("RSA-8192: Выполнение гибридного шифрования...")
        bundle_str = rsa_encrypt_hybrid(pub, message)
        bundle = json.loads(bundle_str)
        self.assertEqual(bundle["key_bits"], 8192)

        logger.info("RSA-8192: Выполнение расшифрования...")
        dec = rsa_decrypt_hybrid(priv, bundle_str)
        self.assertEqual(dec.decode("utf-8"), message)
        logger.info("RSA-8192: Расшифрованное сообщение корректно")

    def test_rsa_32k_hybrid_with_pregen(self):
        """
        Test RSA-32768 (32K bits) hybrid encryption:
        Uses pregenerated p and q parameters if available.
        Only generates under test if confirmed by the user.
        """
        from cli import load_pregen_primes

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pregen_dir = os.path.join(base_dir, "data", "rsa_pregen")

        logger.info("RSA-32K: Проверка каталога предвычисленных параметров %s...", pregen_dir)
        p, q = None, None
        try:
            p, q = load_pregen_primes(pregen_dir)
        except Exception as e:
            logger.warning("RSA-32K: Ошибка загрузки предвычисленных простых чисел: %s", e)

        if p is None or q is None:
            logger.info("RSA-32K: Предвычисленные p и q не найдены")
            # Ask the user before launching heavy multi-minute 32k generation
            should_gen = False
            if sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                try:
                    ans = input("\n[?] RSA-32K: Предвычисленные p и q не найдены. Сгенерировать их сейчас? [y/N]: ").strip().lower()
                    should_gen = ans in ("y", "yes", "д", "да")
                except (EOFError, OSError):
                    should_gen = False

            if should_gen:
                logger.info("RSA-32K: Запуск параллельной генерации простых чисел 32768 бит...")
                from crypto.rsa_parallel import generate_rsa_keypair_parallel
                priv, pub, _ = generate_rsa_keypair_parallel(key_size=32768, verbose=True)
            else:
                logger.info("RSA-32K: Генерация отменена пользователем. Пропуск теста.")
                self.skipTest("Предвычисленные p и q для RSA-32K не найдены, генерация отменена пользователем.")
        else:
            logger.info("RSA-32K: Успешно загружены простые числа p (%d бит) и q (%d бит)", p.bit_length(), q.bit_length())
            priv, pub = build_rsa_keypair_from_primes(p, q)

        self.assertEqual(priv.key_size, 32768)
        self.assertEqual(pub.key_size, 32768)
        logger.info("RSA-32K: Ключевая пара готова (размер ключа: %d бит)", priv.key_size)

        # PEM serialization validation
        logger.info("RSA-32K: Проверка экспорта открытого ключа в PEM SPKI...")
        pub_pem = export_public_key_pem(pub)
        self.assertTrue(pub_pem.startswith("-----BEGIN PUBLIC KEY-----"))
        loaded_pub = load_public_key_pem(pub_pem)
        self.assertEqual(loaded_pub.n, pub.n)
        logger.info("RSA-32K: Экспорт и парсинг PEM открытого ключа 32K пройдены успешно")

        # Hybrid envelope encryption and CRT decryption
        message = "Секретные данные для проверки экстремального 32768-битного гибридного шифрования RSA-32K."
        logger.info("RSA-32K: Выполнение гибридного конвертного шифрования...")
        bundle_str = rsa_encrypt_hybrid(pub, message)
        bundle = json.loads(bundle_str)
        self.assertEqual(bundle["key_bits"], 32768)
        self.assertIn("enc_key", bundle)
        self.assertIn("hmac", bundle)

        logger.info("RSA-32K: Выполнение расшифрования с CRT ускорением (Китайская теорема об остатках)...")
        t_start_dec = time.time()
        decrypted = rsa_decrypt_hybrid(priv, bundle_str)
        t_elapsed_dec = time.time() - t_start_dec
        logger.info("RSA-32K: Расшифрование 32768-битного пакета завершено за %.3f с", t_elapsed_dec)
        self.assertEqual(decrypted.decode("utf-8"), message)

        # Tampering detection
        logger.info("RSA-32K: Проверка устойчивости к подмене шифртекста...")
        tampered_bundle = dict(bundle)
        raw_ct = list(tampered_bundle["ciphertext"])
        raw_ct[0] = "X" if raw_ct[0] != "X" else "Y"
        tampered_bundle["ciphertext"] = "".join(raw_ct)
        with self.assertRaises(ValueError):
            rsa_decrypt_hybrid(priv, json.dumps(tampered_bundle))
        logger.info("RSA-32K: Искажение данных обнаружено, проверка целостности работает корректно")

    def test_kuznyechik_with_salt(self):
        """
        Test Kuznyechik block cipher with salt-based PBKDF2 key derivation and IV.
        Verifies CBC and CTR modes, salt uniqueness, and tampering resistance.
        """
        logger.info("Кузнечик+Соль: Проверка деривации ключей PBKDF2-Стрибог512 с уникальными солями...")
        passphrase = "UserStrongPassphrase2026!#%"
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)

        # 1. Salt uniqueness: different salts yield different derived keys
        key1 = pbkdf2_streebog512(passphrase, salt1, iterations=50, dklen=32)
        key2 = pbkdf2_streebog512(passphrase, salt2, iterations=50, dklen=32)
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)
        self.assertNotEqual(key1, key2)
        logger.info("Кузнечик+Соль: Уникальность производных ключей подтверждена")

        data = "Конфиденциальные данные пользователя для шифрования шифром ГОСТ Кузнечик с солью.".encode("utf-8")
        cipher1 = Kuznyechik(key1)

        # 2. CBC mode with random IV and salt
        logger.info("Кузнечик+Соль: Шифрование и расшифрование в режиме CBC со случайным IV...")
        iv = os.urandom(16)
        ct_cbc = cipher1.encrypt_cbc(data, iv=iv)
        dec_cbc = cipher1.decrypt_cbc(ct_cbc)
        self.assertEqual(dec_cbc, data)

        # Decrypting with wrong key (derived from different salt) fails PKCS#7 unpadding
        cipher2 = Kuznyechik(key2)
        with self.assertRaises(Exception):
            cipher2.decrypt_cbc(ct_cbc)
        logger.info("Кузнечик+Соль: Расшифрование CBC с неверной солью/ключом корректно отклонено")

        # 3. CTR mode with random IV and salt
        logger.info("Кузнечик+Соль: Шифрование и расшифрование в режиме CTR...")
        ct_ctr = cipher1.encrypt_ctr(data, iv=iv)
        dec_ctr = cipher1.decrypt_ctr(ct_ctr)
        self.assertEqual(dec_ctr, data)

        # CTR decrypted with wrong key yields corrupted plaintext
        dec_ctr_wrong = cipher2.decrypt_ctr(ct_ctr)
        self.assertNotEqual(dec_ctr_wrong, data)
        logger.info("Кузнечик+Соль: Режим CTR подтвержден")

        # 4. Salted authenticated container with HMAC-Streebog512
        logger.info("Кузнечик+Соль: Проверка аутентифицированного контейнера (соль + IV + шифртекст + HMAC)...")
        tag = hmac_streebog512(key1, salt1 + iv + ct_cbc)
        self.assertEqual(len(tag), 64)
        calc_tag = hmac_streebog512(key1, salt1 + iv + ct_cbc)
        self.assertEqual(tag, calc_tag)
        # Corrupted salt must fail HMAC check
        bad_tag = hmac_streebog512(key1, salt2 + iv + ct_cbc)
        self.assertNotEqual(tag, bad_tag)
        logger.info("Кузнечик+Соль: Аутентификация и контроль целостности подтверждены")

    def test_streebog512_comprehensive(self):
        """
        Comprehensive test of GOST R 34.11-2012 Streebog-512:
        - RFC 6986 empty string test vector
        - Multi-block payload processing
        - Strict avalanche criterion (> 200 bits flipped on 1-bit input change)
        - HMAC-Streebog512 with keys <, ==, and > 64 bytes
        - PBKDF2-Streebog512 with multiple iteration counts and lengths
        """
        # 1. Empty string hash test
        logger.info("Стрибог-512: Проверка тестового вектора RFC 6986 для пустой строки...")
        empty_hash = streebog512(b"")
        self.assertEqual(len(empty_hash), 64)
        expected_empty = "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a"
        self.assertEqual(empty_hash.hex(), expected_empty)
        logger.info("Стрибог-512: Хеш пустой строки совпал с RFC 6986")

        # 2. Multi-block large payload (10 KB)
        logger.info("Стрибог-512: Хеширование мульти-блочного объема данных (10 КБ)...")
        large_payload = b"GOST-R-34.11-2012-STREEBOG-TEST-" * 320
        h_large = streebog512(large_payload)
        self.assertEqual(len(h_large), 64)
        self.assertEqual(h_large, streebog512(large_payload))
        logger.info("Стрибог-512: Мульти-блочное хеширование выполнено детерминированно")

        # 3. Avalanche effect test: 1 bit change in message flips ~50% of digest bits
        logger.info("Стрибог-512: Проверка лавинного эффекта (изменение 1 бита в сообщении)...")
        msg_a = b"X" * 64
        msg_b = bytearray(msg_a)
        msg_b[0] ^= 0x01
        h_a = streebog512(msg_a)
        h_b = streebog512(bytes(msg_b))
        flipped = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(h_a, h_b))
        self.assertGreater(flipped, 200)  # at least 200 out of 512 bits differ
        logger.info("Стрибог-512: Лавинный критерий выполнен (изменилось %d из 512 бит, > 200)", flipped)

        # 4. HMAC-Streebog512 key lengths: short (16b), exact (64b), and long (128b)
        logger.info("Стрибог-512: Проверка HMAC-Стрибог512 с ключами 16, 64 и 128 байт...")
        msg = b"Authenticated payload via Streebog"
        tag_short = hmac_streebog512(b"short_16_bytes!!", msg)
        tag_exact = hmac_streebog512(b"K" * 64, msg)
        tag_long = hmac_streebog512(b"L" * 128, msg)
        self.assertEqual(len(tag_short), 64)
        self.assertEqual(len(tag_exact), 64)
        self.assertEqual(len(tag_long), 64)
        self.assertNotEqual(tag_short, tag_exact)
        self.assertNotEqual(tag_exact, tag_long)
        logger.info("Стрибог-512: HMAC расчет подтвержден")

        # 5. PBKDF2-Streebog512 lengths and iterations
        logger.info("Стрибог-512: Проверка PBKDF2-Стрибог512 (32 и 64 байта)...")
        pwd = "ComplexPassphrase!123"
        salt = b"test_salt_32b_length_streebog__"
        dk32 = pbkdf2_streebog512(pwd, salt, iterations=10, dklen=32)
        dk64 = pbkdf2_streebog512(pwd, salt, iterations=10, dklen=64)
        self.assertEqual(len(dk32), 32)
        self.assertEqual(len(dk64), 64)
        self.assertEqual(dk64[:32], dk32)  # PBKDF2 standard block prefix property
        logger.info("Стрибог-512: PBKDF2 деривация подтверждена")


if __name__ == "__main__":
    unittest.main()
