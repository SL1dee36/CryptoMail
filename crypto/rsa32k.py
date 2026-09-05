# Description: RSA asymmetric cryptosystem (up to 32768 bits), RSA-OAEP padding, and hybrid envelope encryption.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import json
import os
import sys
from typing import Dict, Tuple, Union

# Python 3.11 integer-to-string digit conversion security limit increase
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from crypto.kuznyechik import Kuznyechik


def generate_rsa_keypair(key_size: int = 32768, public_exponent: int = 65537) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates an RSA key pair of the specified bit length (e.g. 2048, 4096, 8192, 32768).
    For 32768 bits, key generation may take several minutes.
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def build_rsa_keypair_from_primes(
    p: int, q: int, public_exponent: int = 65537
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Constructs an RSA key pair directly from two primes p and q.
    Calculates modulus n, private exponent d, and CRT coefficients.
    """
    if p < q:
        p, q = q, p

    e = public_exponent
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)

    pub_nums = rsa.RSAPublicNumbers(e, n)
    priv_nums = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub_nums)
    priv_key = priv_nums.private_key(backend=default_backend())
    pub_key = priv_key.public_key()
    return priv_key, pub_key


def get_or_create_rsa_keypair(key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Retrieves or generates an RSA key pair.
    For 32768-bit keys, checks the precomputed pool cache for instant delivery.
    For 2048, 4096, 8192 bits, generates on demand.
    """
    if key_size == 32768:
        pool_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data",
            "rsa_pool",
            "precomputed_32k.json",
        )
        if os.path.exists(pool_file):
            try:
                with open(pool_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                priv = load_private_key_pem(data["priv_pem"])
                pub = load_public_key_pem(data["pub_pem"])
                return priv, pub
            except Exception:
                pass
    return generate_rsa_keypair(key_size=key_size)



def export_private_key_pem(private_key: rsa.RSAPrivateKey, password: str = None) -> str:
    encryption = (
        serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    return pem.decode("utf-8")


def export_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def load_private_key_pem(pem_data: Union[str, bytes], password: str = None) -> rsa.RSAPrivateKey:
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    pwd_bytes = password.encode("utf-8") if password else None
    return serialization.load_pem_private_key(pem_data, password=pwd_bytes, backend=default_backend())


def load_public_key_pem(pem_data: Union[str, bytes]) -> rsa.RSAPublicKey:
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def rsa_encrypt_hybrid(public_key: rsa.RSAPublicKey, plaintext: Union[str, bytes]) -> str:
    """
    Hybrid Envelope Encryption using RSA public key (any size up to 32K) and GOST Kuznyechik.
    1. Generates 32-byte (256-bit) session key and 16-byte IV.
    2. Encrypts plaintext with Kuznyechik in CTR mode.
    3. Encrypts session key with RSA OAEP (SHA-256).
    4. Bundles into JSON string encoded with base64.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    session_key = os.urandom(32)
    iv = os.urandom(16)

    kuz = Kuznyechik(session_key)
    # Encrypt data with Kuznyechik CTR
    enc_data = kuz.encrypt_ctr(plaintext, iv=iv)
    ciphertext = enc_data[16:]  # skip IV prefix as we store IV explicitly

    # Encrypt session key with RSA OAEP
    enc_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    bundle = {
        "alg": "RSA-HYBRID",
        "key_bits": public_key.key_size,
        "enc_key": base64.b64encode(enc_session_key).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(bundle)


def rsa_decrypt_hybrid(private_key: rsa.RSAPrivateKey, encrypted_bundle_str: str) -> bytes:
    """
    Decrypts a hybrid RSA envelope bundle using the RSA private key.
    """
    bundle = json.loads(encrypted_bundle_str)
    enc_session_key = base64.b64decode(bundle["enc_key"])
    iv = base64.b64decode(bundle["iv"])
    ciphertext = base64.b64decode(bundle["ciphertext"])

    session_key = private_key.decrypt(
        enc_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    kuz = Kuznyechik(session_key)
    return kuz.decrypt_ctr(iv + ciphertext)
