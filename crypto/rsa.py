# Description: Pure-Python RSA cryptosystem (up to 32768 bits), RSA-OAEP padding, ASN.1 DER/PEM serialization, and hybrid envelope encryption without cryptography library.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

# Python 3.11 integer-to-string digit conversion security limit increase
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

from crypto.kuznyechik import Kuznyechik
from crypto.streebog import hmac_streebog512

logger = logging.getLogger("crypto.rsa")


# Primality testing and prime generation (Pure Python, Miller-Rabin)

def _sieve_primes(limit: int = 2000) -> List[int]:
    """Generates a list of small primes up to limit using Sieve of Eratosthenes."""
    sieve = [True] * limit
    sieve[0] = sieve[1] = False
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            for j in range(i * i, limit, i):
                sieve[j] = False
    return [i for i, is_p in enumerate(sieve) if is_p]


SMALL_PRIMES = _sieve_primes(2000)


def is_probable_prime(n: int, rounds: int = 6) -> bool:
    """
    Miller-Rabin primality test with pre-sieve.
    Rounds = 6 provides probability of false positive < 2^-128 for numbers >= 1024 bits.
    """
    if n < 2 or n % 2 == 0:
        return False
    # Quick trial division by small primes
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p

    # Write n - 1 as 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Miller-Rabin test
    for _ in range(rounds):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def find_prime(prime_bits: int, public_exponent: int = 65537) -> int:
    """
    Generates a random prime number of prime_bits length coprime with public_exponent - 1.
    """
    logger.debug("RSA find_prime: поиск простого числа длиной %d бит...", prime_bits)
    while True:
        cand = secrets.randbits(prime_bits) | (1 << (prime_bits - 1)) | (1 << (prime_bits - 2)) | 1
        if (cand - 1) % public_exponent == 0:
            continue
        if is_probable_prime(cand, rounds=6):
            return cand

# RSA-OAEP Padding (RFC 8017 / PKCS#1 v2.2)

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    """
    Mask Generation Function 1 (MGF1) per PKCS#1 v2.2 / RFC 8017 Appendix B.2.1.
    """
    h_len = hash_func().digest_size
    t = bytearray()
    counter = 0
    while len(t) < length:
        c = counter.to_bytes(4, byteorder="big")
        t.extend(hash_func(seed + c).digest())
        counter += 1
    return bytes(t[:length])


def oaep_pad(message: bytes, k: int, label: bytes = b"", hash_func=hashlib.sha256) -> bytes:
    """
    EME-OAEP encoding per PKCS#1 v2.2 / RFC 8017 Section 7.1.1.
    k is the byte length of the RSA modulus.
    """
    h_len = hash_func().digest_size
    m_len = len(message)
    if m_len > k - 2 * h_len - 2:
        raise ValueError(
            f"Message too long for RSA-OAEP: length {m_len} exceeds max {k - 2 * h_len - 2}"
        )
    l_hash = hash_func(label).digest()
    ps_len = k - m_len - 2 * h_len - 2
    ps = b"\x00" * ps_len
    db = l_hash + ps + b"\x01" + message
    seed = os.urandom(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = mgf1(masked_db, h_len, hash_func)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def oaep_unpad(em: bytes, k: int, label: bytes = b"", hash_func=hashlib.sha256) -> bytes:
    """
    EME-OAEP decoding per PKCS#1 v2.2 / RFC 8017 Section 7.1.2.
    """
    h_len = hash_func().digest_size
    if len(em) != k or k < 2 * h_len + 2:
        raise ValueError("Decryption error: invalid ciphertext / modulus length")

    y = em[0]
    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]

    seed_mask = mgf1(masked_db, h_len, hash_func)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, len(masked_db), hash_func)
    db = bytearray(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash = hash_func(label).digest()
    l_hash_prime = bytes(db[:h_len])

    bad = (y != 0) | (not hmac.compare_digest(l_hash_prime, l_hash))

    sep_idx = -1
    for i in range(h_len, len(db)):
        byte = db[i]
        if byte == 0x01 and sep_idx == -1:
            sep_idx = i
        elif byte != 0x00 and sep_idx == -1:
            bad = True

    if sep_idx == -1 or bad:
        raise ValueError("Decryption error: OAEP padding check failed")

    return bytes(db[sep_idx + 1 :])

# RSA Key Classes

class RSAPublicKey:
    """
    Pure Python RSA Public Key representation.
    """
    def __init__(self, n: int, e: int = 65537):
        self.n = n
        self.e = e

    @property
    def key_size(self) -> int:
        return self.n.bit_length()

    def encrypt(self, plaintext: Union[str, bytes], padding: Any = None) -> bytes:
        """
        Encrypts plaintext using RSA-OAEP (SHA-256).
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        label = b""
        if padding is not None and hasattr(padding, "label") and padding.label:
            label = padding.label
        k = (self.n.bit_length() + 7) // 8
        em = oaep_pad(plaintext, k, label=label)
        m = int.from_bytes(em, "big")
        c = pow(m, self.e, self.n)
        return c.to_bytes(k, "big")

    def public_bytes(self, encoding=None, format=None) -> bytes:
        return export_public_key_pem(self).encode("utf-8")

    def public_numbers(self):
        class _PubNums:
            def __init__(self, n, e):
                self.n = n
                self.e = e
        return _PubNums(self.n, self.e)

    def __eq__(self, other) -> bool:
        if not isinstance(other, RSAPublicKey):
            return False
        return self.n == other.n and self.e == other.e

    def __repr__(self) -> str:
        return f"<RSAPublicKey(bits={self.key_size}, e={self.e})>"


class RSAPrivateKey:
    """
    Pure Python RSA Private Key representation with CRT acceleration.
    """
    def __init__(
        self,
        n: int,
        e: int,
        d: int,
        p: Optional[int] = None,
        q: Optional[int] = None,
        dmp1: Optional[int] = None,
        dmq1: Optional[int] = None,
        iqmp: Optional[int] = None,
    ):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dmp1 = dmp1
        self.dmq1 = dmq1
        self.iqmp = iqmp

    @property
    def key_size(self) -> int:
        return self.n.bit_length()

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)

    def decrypt(self, ciphertext: bytes, padding: Any = None) -> bytes:
        """
        Decrypts ciphertext using RSA-OAEP (SHA-256) with CRT acceleration.
        """
        label = b""
        if padding is not None and hasattr(padding, "label") and padding.label:
            label = padding.label
        k = (self.n.bit_length() + 7) // 8
        c = int.from_bytes(ciphertext, "big")
        if self.p and self.q and self.dmp1 and self.dmq1 and self.iqmp:
            # Chinese Remainder Theorem (CRT) acceleration (~4x speedup)
            m1 = pow(c % self.p, self.dmp1, self.p)
            m2 = pow(c % self.q, self.dmq1, self.q)
            h = ((m1 - m2) * self.iqmp) % self.p
            m = (m2 + h * self.q) % self.n
        else:
            m = pow(c, self.d, self.n)
        em = m.to_bytes(k, "big")
        return oaep_unpad(em, k, label=label)

    def private_bytes(self, encoding=None, format=None, encryption_algorithm=None) -> bytes:
        return export_private_key_pem(self).encode("utf-8")

    def private_numbers(self):
        class _PrivNums:
            def __init__(self, n, e, d, p, q, dmp1, dmq1, iqmp):
                self.public_numbers = RSAPublicKey(n, e).public_numbers()
                self.d = d
                self.p = p
                self.q = q
                self.dmp1 = dmp1
                self.dmq1 = dmq1
                self.iqmp = iqmp
        return _PrivNums(self.n, self.e, self.d, self.p, self.q, self.dmp1, self.dmq1, self.iqmp)

    def __eq__(self, other) -> bool:
        if not isinstance(other, RSAPrivateKey):
            return False
        return self.n == other.n and self.d == other.d

    def __repr__(self) -> str:
        return f"<RSAPrivateKey(bits={self.key_size}, e={self.e})>"


# ---------------------------------------------------------------------------
# ASN.1 DER primitives (pure Python, zero external dependencies)
# ---------------------------------------------------------------------------

RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(len_bytes)]) + len_bytes


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(n: int) -> bytes:
    if n == 0:
        return _encode_tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _encode_tlv(0x02, b)


def _encode_oid(oid_str: str) -> bytes:
    parts = [int(p) for p in oid_str.split(".")]
    first = 40 * parts[0] + parts[1]
    res = bytearray([first])
    for part in parts[2:]:
        if part == 0:
            res.append(0)
            continue
        sub = []
        val = part
        while val > 0:
            sub.append(val & 0x7F)
            val >>= 7
        for i in range(len(sub) - 1, 0, -1):
            res.append(sub[i] | 0x80)
        res.append(sub[0])
    return _encode_tlv(0x06, bytes(res))


def _encode_sequence(*items: bytes) -> bytes:
    return _encode_tlv(0x30, b"".join(items))


def _encode_octet_string(data: bytes) -> bytes:
    return _encode_tlv(0x04, data)


def _encode_bit_string(data: bytes) -> bytes:
    return _encode_tlv(0x03, b"\x00" + data)


def _decode_der(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of DER data")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("Unexpected end of DER data")
    length_byte = data[offset]
    offset += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        num_len_bytes = length_byte & 0x7F
        if offset + num_len_bytes > len(data):
            raise ValueError("Truncated DER length")
        length = int.from_bytes(data[offset : offset + num_len_bytes], "big")
        offset += num_len_bytes
    if offset + length > len(data):
        raise ValueError(f"Truncated DER content: expected {length} bytes, have {len(data) - offset}")
    value = data[offset : offset + length]
    next_offset = offset + length
    return tag, value, next_offset


def _parse_sequence(data: bytes) -> List[Tuple[int, bytes]]:
    items = []
    offset = 0
    while offset < len(data):
        tag, val, offset = _decode_der(data, offset)
        items.append((tag, val))
    return items


def _decode_integer(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=False)


def _rsa_algorithm_identifier() -> bytes:
    # AlgorithmIdentifier: SEQUENCE { OBJECT IDENTIFIER rsaEncryption, NULL (0x05 0x00) }
    return _encode_sequence(_encode_oid(RSA_ENCRYPTION_OID), b"\x05\x00")


def _export_public_key_der(public_key: RSAPublicKey) -> bytes:
    # PKCS#1 RSAPublicKey SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    pkcs1 = _encode_sequence(
        _encode_integer(public_key.n),
        _encode_integer(public_key.e),
    )
    # SPKI SEQUENCE { AlgorithmIdentifier, SubjectPublicKey BIT STRING }
    return _encode_sequence(_rsa_algorithm_identifier(), _encode_bit_string(pkcs1))


def _export_private_key_der(private_key: RSAPrivateKey) -> bytes:
    p = private_key.p or 0
    q = private_key.q or 0
    dmp1 = private_key.dmp1 or (private_key.d % (p - 1) if p > 1 else 0)
    dmq1 = private_key.dmq1 or (private_key.d % (q - 1) if q > 1 else 0)
    iqmp = private_key.iqmp or (pow(q, -1, p) if (p > 1 and q > 1) else 0)

    # PKCS#1 RSAPrivateKey SEQUENCE
    pkcs1 = _encode_sequence(
        _encode_integer(0),  # version
        _encode_integer(private_key.n),
        _encode_integer(private_key.e),
        _encode_integer(private_key.d),
        _encode_integer(p),
        _encode_integer(q),
        _encode_integer(dmp1),
        _encode_integer(dmq1),
        _encode_integer(iqmp),
    )
    # PKCS#8 PrivateKeyInfo SEQUENCE { version (0), AlgorithmIdentifier, OCTET STRING }
    return _encode_sequence(
        _encode_integer(0),
        _rsa_algorithm_identifier(),
        _encode_octet_string(pkcs1),
    )


def export_public_key_pem(public_key: RSAPublicKey) -> str:
    """Exports RSA public key in standard PEM (SubjectPublicKeyInfo) format."""
    der = _export_public_key_der(public_key)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def export_private_key_pem(private_key: RSAPrivateKey, password: str = None) -> str:
    """Exports RSA private key in standard PEM (PKCS#8) format."""
    der = _export_private_key_der(private_key)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"


def load_public_key_pem(pem_data: Union[str, bytes]) -> RSAPublicKey:
    """Loads RSA public key from PEM string or bytes (SubjectPublicKeyInfo or PKCS#1)."""
    if isinstance(pem_data, bytes):
        pem_data = pem_data.decode("utf-8", errors="replace")

    clean_text = pem_data.strip()
    if clean_text.startswith("{"):
        try:
            data = json.loads(clean_text)
            if "n" in data and "e" in data:
                return RSAPublicKey(int(data["n"], 0), int(data["e"], 0))
            if "pub_pem" in data:
                return load_public_key_pem(data["pub_pem"])
        except Exception:
            pass

    clean_lines = [
        line.strip()
        for line in pem_data.splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    raw = base64.b64decode("".join(clean_lines))

    tag, val, _ = _decode_der(raw)
    if tag != 0x30:
        raise ValueError("Invalid public key DER: expected SEQUENCE")
    items = _parse_sequence(val)

    # 1. PKCS#1 format: SEQUENCE { INTEGER (n), INTEGER (e) }
    if len(items) == 2 and items[0][0] == 0x02 and items[1][0] == 0x02:
        return RSAPublicKey(_decode_integer(items[0][1]), _decode_integer(items[1][1]))

    # 2. SPKI format: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    pub_bytes = None
    for item_tag, item_val in items:
        if item_tag == 0x03:
            pub_bytes = item_val[1:]  # strip leading unused bits byte
            break
        elif item_tag == 0x04:
            pub_bytes = item_val
            break

    if pub_bytes is None:
        raise ValueError("Could not extract public key modulus from DER")

    inner_tag, inner_val, _ = _decode_der(pub_bytes)
    inner_items = _parse_sequence(inner_val)
    if len(inner_items) >= 2 and inner_items[0][0] == 0x02 and inner_items[1][0] == 0x02:
        return RSAPublicKey(_decode_integer(inner_items[0][1]), _decode_integer(inner_items[1][1]))

    raise ValueError("Failed to parse RSA public key from DER")


def load_private_key_pem(pem_data: Union[str, bytes], password: str = None) -> RSAPrivateKey:
    """Loads RSA private key from PEM string or bytes (PKCS#8 or PKCS#1)."""
    if isinstance(pem_data, bytes):
        pem_data = pem_data.decode("utf-8", errors="replace")

    clean_text = pem_data.strip()
    if clean_text.startswith("{"):
        try:
            data = json.loads(clean_text)
            if "priv_pem" in data:
                return load_private_key_pem(data["priv_pem"], password=password)
            if "n" in data and "d" in data:
                return RSAPrivateKey(
                    n=int(data["n"], 0),
                    e=int(data.get("e", 65537)),
                    d=int(data["d"], 0),
                    p=int(data["p"], 0) if "p" in data else None,
                    q=int(data["q"], 0) if "q" in data else None,
                )
        except Exception:
            pass

    clean_lines = [
        line.strip()
        for line in pem_data.splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    raw = base64.b64decode("".join(clean_lines))

    tag, val, _ = _decode_der(raw)
    if tag != 0x30:
        raise ValueError("Invalid private key DER: expected SEQUENCE")
    items = _parse_sequence(val)

    # 1. PKCS#1 direct format: items has >= 9 integers
    if len(items) >= 9 and items[0][0] == 0x02 and items[1][0] == 0x02:
        return RSAPrivateKey(
            n=_decode_integer(items[1][1]),
            e=_decode_integer(items[2][1]),
            d=_decode_integer(items[3][1]),
            p=_decode_integer(items[4][1]),
            q=_decode_integer(items[5][1]),
            dmp1=_decode_integer(items[6][1]),
            dmq1=_decode_integer(items[7][1]),
            iqmp=_decode_integer(items[8][1]),
        )

    # 2. PKCS#8 format: SEQUENCE { version (0), AlgorithmIdentifier, OCTET STRING }
    priv_octets = None
    for item_tag, item_val in items:
        if item_tag == 0x04:
            priv_octets = item_val
            break

    if priv_octets is None:
        raise ValueError("Could not extract private key from PKCS#8 DER")

    inner_tag, inner_val, _ = _decode_der(priv_octets)
    inner_items = _parse_sequence(inner_val)
    if len(inner_items) >= 9:
        return RSAPrivateKey(
            n=_decode_integer(inner_items[1][1]),
            e=_decode_integer(inner_items[2][1]),
            d=_decode_integer(inner_items[3][1]),
            p=_decode_integer(inner_items[4][1]),
            q=_decode_integer(inner_items[5][1]),
            dmp1=_decode_integer(inner_items[6][1]),
            dmq1=_decode_integer(inner_items[7][1]),
            iqmp=_decode_integer(inner_items[8][1]),
        )

    raise ValueError("Failed to parse RSA private key from DER")


# ---------------------------------------------------------------------------
# Key generation & Pool Retrieval
# ---------------------------------------------------------------------------

def build_rsa_keypair_from_primes(
    p: int, q: int, public_exponent: int = 65537
) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Constructs an RSA key pair directly from two primes p and q.
    Calculates modulus n, private exponent d, and CRT coefficients.
    """
    if p < q:
        p, q = q, p

    e = public_exponent
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError("Invalid primes: phi(n) is not coprime to public exponent e.")

    d = pow(e, -1, phi)
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)

    priv_key = RSAPrivateKey(n, e, d, p, q, dmp1, dmq1, iqmp)
    pub_key = priv_key.public_key()
    logger.info("RSA: построена ключевая пара %d бит из множителей p и q (CRT ускорение активировано)", n.bit_length())
    return priv_key, pub_key


def generate_rsa_keypair(key_size: int = 32768, public_exponent: int = 65537) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generates an RSA key pair of the specified bit length (e.g. 2048, 4096, 8192, 32768).
    For keys <= 2048 bits, generates instantaneously in pure Python.
    For larger keys, attempts multi-core parallel generation if rsa_parallel is present.
    """
    prime_bits = key_size // 2
    t0 = time.time()
    logger.info("RSA: генерация ключевой пары %d бит (по %d бит на простые числа p и q)...", key_size, prime_bits)

    # For larger keys, use multi-worker search if available
    if key_size > 2048:
        try:
            from crypto.rsa_parallel import find_prime_parallel
            p, _, _ = find_prime_parallel(prime_bits)
            min_diff = 1 << max(1, prime_bits - 100)
            q = p
            while q == p or abs(p - q) < min_diff or (p * q).bit_length() != key_size:
                q, _, _ = find_prime_parallel(prime_bits)
            priv, pub = build_rsa_keypair_from_primes(p, q, public_exponent=public_exponent)
            logger.info("RSA: ключ %d бит успешно сгенерирован за %.2f сек", key_size, time.time() - t0)
            return priv, pub
        except Exception:
            pass

    p = find_prime(prime_bits, public_exponent)
    min_diff = 1 << max(1, prime_bits - 100)
    q = p
    while q == p or abs(p - q) < min_diff or (p * q).bit_length() != key_size:
        q = find_prime(prime_bits, public_exponent)

    priv, pub = build_rsa_keypair_from_primes(p, q, public_exponent=public_exponent)
    logger.info("RSA: ключ %d бит успешно сгенерирован за %.2f сек", key_size, time.time() - t0)
    return priv, pub


def get_or_create_rsa_keypair(key_size: int = 4096) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Retrieves or generates an RSA key pair.
    Checks precomputed pool cache and pregen primes for instant response (4K, 8K, 32K, etc.).
    Falls back to parallel generation if precomputed parameters are not found.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pool_dir = os.path.join(base_dir, "data", "rsa_pool")
    pregen_dir = os.path.join(base_dir, "data", "rsa_pregen")

    # 1. Look for precomputed key in rsa_pool
    if os.path.exists(pool_dir):
        pool_cand_name = f"precomputed_{key_size // 1024 if key_size % 1024 == 0 else key_size}k.json"
        pool_cand_path = os.path.join(pool_dir, pool_cand_name)
        if os.path.exists(pool_cand_path):
            try:
                with open(pool_cand_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info("RSA-%d: загружен ключ из пула (%s)", key_size, pool_cand_name)
                return load_private_key_pem(data["priv_pem"]), load_public_key_pem(data["pub_pem"])
            except Exception:
                pass

        for fname in sorted(os.listdir(pool_dir)):
            if fname.endswith(".json"):
                try:
                    with open(os.path.join(pool_dir, fname), "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data.get("key_size") == key_size and "priv_pem" in data:
                        logger.info("RSA-%d: загружен ключ из пула (%s)", key_size, fname)
                        return load_private_key_pem(data["priv_pem"]), load_public_key_pem(data["pub_pem"])
                except Exception:
                    pass

    # 2. Look for pregenerated p and q in rsa_pregen
    if os.path.exists(pregen_dir):
        named_cands = [
            f"rsa{key_size // 1024}k_primes.json" if key_size % 1024 == 0 else f"rsa_{key_size}_primes.json",
        ]
        if key_size == 32768:
            named_cands.extend(["primes.json", "rsa32k_primes.json", "pq.json"])

        for cand_name in named_cands:
            cand_path = os.path.join(pregen_dir, cand_name)
            if os.path.exists(cand_path):
                try:
                    with open(cand_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    p = int(data["p"], 0)
                    q = int(data["q"], 0)
                    logger.info("RSA-%d: загружены предвычисленные параметры p и q из %s", key_size, cand_name)
                    return build_rsa_keypair_from_primes(p, q)
                except Exception:
                    pass

        if key_size == 32768:
            p_file = os.path.join(pregen_dir, "p.txt")
            q_file = os.path.join(pregen_dir, "q.txt")
            if os.path.exists(p_file) and os.path.exists(q_file):
                try:
                    p = int(open(p_file, "r", encoding="utf-8").read().strip(), 0)
                    q = int(open(q_file, "r", encoding="utf-8").read().strip(), 0)
                    return build_rsa_keypair_from_primes(p, q)
                except Exception:
                    pass

    return generate_rsa_keypair(key_size=key_size)


# Hybrid Envelope Encryption & Decryption

def rsa_encrypt_hybrid(public_key: RSAPublicKey, plaintext: Union[str, bytes]) -> str:
    """
    Hybrid Envelope Encryption using RSA public key (any size up to 32K) and GOST Kuznyechik.
    1. Generates 32-byte (256-bit) session key and 16-byte IV.
    2. Encrypts plaintext with Kuznyechik in CTR mode.
    3. Encrypts session key with RSA OAEP (SHA-256).
    4. Computes HMAC-Streebog-512 authentication tag over IV + ciphertext.
    5. Bundles into JSON string encoded with base64.
    """
    t0 = time.time()
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    logger.info("RSA-Hybrid: шифрование (%d байт) открытым ключом RSA-%d...", len(plaintext), public_key.key_size)
    session_key = os.urandom(32)
    iv = os.urandom(16)

    kuz = Kuznyechik(session_key)
    # Encrypt data with Kuznyechik CTR
    enc_data = kuz.encrypt_ctr(plaintext, iv=iv)
    ciphertext = enc_data[16:]  # skip IV prefix as we store IV explicitly

    # Encrypt session key with RSA OAEP
    enc_session_key = public_key.encrypt(session_key)

    hmac_tag = hmac_streebog512(session_key, iv + ciphertext)

    bundle = {
        "alg": "RSA-HYBRID",
        "key_bits": public_key.key_size,
        "enc_key": base64.b64encode(enc_session_key).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "hmac": base64.b64encode(hmac_tag).decode("ascii"),
    }
    logger.info("RSA-Hybrid: шифрование завершено за %.4f с (размер пакета: %d байт)", time.time() - t0, len(ciphertext))
    return json.dumps(bundle)


def rsa_decrypt_hybrid(private_key: RSAPrivateKey, encrypted_bundle_str: str) -> bytes:
    """
    Decrypts a hybrid RSA envelope bundle using the RSA private key with HMAC integrity verification.
    """
    t0 = time.time()
    logger.info("RSA-Hybrid: расшифрование пакета приватным ключом RSA-%d (CRT ускорение)...", private_key.key_size)
    bundle = json.loads(encrypted_bundle_str)
    enc_session_key = base64.b64decode(bundle["enc_key"])
    iv = base64.b64decode(bundle["iv"])
    ciphertext = base64.b64decode(bundle["ciphertext"])

    session_key = private_key.decrypt(enc_session_key)

    if "hmac" in bundle:
        expected_hmac = base64.b64decode(bundle["hmac"])
        calc_hmac = hmac_streebog512(session_key, iv + ciphertext)
        if not hmac.compare_digest(calc_hmac, expected_hmac):
            raise ValueError("RSA-Hybrid ciphertext integrity verification failed (HMAC mismatch)!")
        logger.debug("RSA-Hybrid: имитовставка HMAC-Стрибог512 успешно проверена")

    kuz = Kuznyechik(session_key)
    decrypted_bytes = kuz.decrypt_ctr(iv + ciphertext)
    logger.info("RSA-Hybrid: пакет успешно расшифрован за %.4f с", time.time() - t0)
    return decrypted_bytes

# Compatibility / Namespace classes

class _MGF1:
    def __init__(self, algorithm=None):
        self.algorithm = algorithm

class _OAEP:
    def __init__(self, mgf=None, algorithm=None, label: Optional[bytes] = None):
        self.mgf = mgf
        self.algorithm = algorithm
        self.label = label or b""

class _PaddingNamespace:
    OAEP = _OAEP
    MGF1 = _MGF1

padding = _PaddingNamespace()


# ---------------------------------------------------------------------------
# High-level Helper Functions for Console / CLI / API
# ---------------------------------------------------------------------------

def encrypt_string_rsa(
    plaintext: Union[str, bytes],
    key: Union[str, bytes, RSAPublicKey],
) -> str:
    """
    Шифрует строку или байты открытым ключом RSA (гибридный конверт: RSA-OAEP + ГОСТ «Кузнечик» CTR + ГОСТ «Стрибог»-512 HMAC).
    Принимает:
    - Путь к PEM-файлу открытого ключа
    - PEM-строку или байты
    - Объект RSAPublicKey
    Возвращает строку с JSON-бандлом.
    """
    if isinstance(key, RSAPublicKey):
        pub = key
    elif isinstance(key, (str, bytes)):
        if isinstance(key, str) and os.path.isfile(key):
            with open(key, "r", encoding="utf-8") as f:
                pem_data = f.read()
        else:
            pem_data = key
        pub = load_public_key_pem(pem_data)
    else:
        raise TypeError(f"Неподдерживаемый тип ключа RSA: {type(key)}")

    return rsa_encrypt_hybrid(pub, plaintext)


def decrypt_string_rsa(
    bundle_str: str,
    key: Union[str, bytes, RSAPrivateKey],
) -> str:
    """
    Расшифровывает JSON-бандл гибридного шифрования RSA закрытым ключом с CRT-ускорением и проверкой целостности HMAC.
    Принимает:
    - Путь к PEM-файлу закрытого ключа
    - PEM-строку или байты
    - Объект RSAPrivateKey
    Возвращает расшифрованную UTF-8 строку.
    """
    if isinstance(key, RSAPrivateKey):
        priv = key
    elif isinstance(key, (str, bytes)):
        if isinstance(key, str) and os.path.isfile(key):
            with open(key, "r", encoding="utf-8") as f:
                pem_data = f.read()
        else:
            pem_data = key
        priv = load_private_key_pem(pem_data)
    else:
        raise TypeError(f"Неподдерживаемый тип ключа RSA: {type(key)}")

    decrypted_bytes = rsa_decrypt_hybrid(priv, bundle_str)
    return decrypted_bytes.decode("utf-8", errors="replace")
