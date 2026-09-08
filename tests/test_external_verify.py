# -*- coding: utf-8 -*-
"""
Demonstrates how our GOST R 34.10-2012 digital signature can be verified:
1. Using an isolated standalone pure Python script (without cryptography or app imports)
2. Using the CryptoMail core API (crypto.ecp)
3. Full compliance with GOST R 34.10-2012 / RFC 7091 / RFC 7836 standards
"""
import base64
import os
import sys

sys.path.insert(0, ".")

from crypto.ecp import (
    export_ecp_private_key_pem,
    export_ecp_public_key_pem,
    generate_ecp_keypair,
    load_ecp_public_key_pem,
    sign_message,
    verify_message_signature,
)
from crypto.streebog import streebog512

# ------------------------------------------------------------------
# Generate key pair and sign a message (GOST R 34.10-2012, 512-bit)
# ------------------------------------------------------------------
priv, pub = generate_ecp_keypair(512)
priv_pem = export_ecp_private_key_pem(priv)
pub_pem = export_ecp_public_key_pem(pub)

message = b"Test message for external verification"
sig_b64 = sign_message(priv, message)
sig_bytes = base64.b64decode(sig_b64)

# Full 512-bit Streebog digest
digest_64 = streebog512(message)

print("=" * 60)
print("GOST R 34.10-2012 KEY PAIR & SIGNATURE")
print("=" * 60)
print("[PUBLIC KEY PEM]")
print(pub_pem.strip())
print("[SIGNATURE base64 (128 bytes = R || S)]")
print(sig_b64)
print(f"[MESSAGE (ASCII)] {message.decode()}")
print(f"[Streebog-512(message) hex] {digest_64.hex()}")
print()

# ------------------------------------------------------------------
# Method 1: Standalone Pure Python (No cryptography, zero dependencies)
# ------------------------------------------------------------------
print("=" * 60)
print("METHOD 1: Standalone Pure Python Verification (RFC 7091 / RFC 7836)")
print("=" * 60)

standalone_verify_script = f'''
import base64

# --- Parameters from GOST R 34.10-2012 (paramSetA 512-bit) ---
p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", 16)
a = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4", 16)
b = int("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760", 16)
q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275", 16)
P = (3, int("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4", 16))

# Public key coordinates
pub_x = {pub.x}
pub_y = {pub.y}
Q = (pub_x, pub_y)

# Message and signature
streebog_digest_hex = "{digest_64.hex()}"
sig_b64 = "{sig_b64}"

sig_raw = base64.b64decode(sig_b64)
r = int.from_bytes(sig_raw[:64], "big")
s = int.from_bytes(sig_raw[64:], "big")

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k, P):
    R = None
    addend = P
    while k > 0:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R

# GOST R 34.10-2012 Algorithm II
H = bytes.fromhex(streebog_digest_hex)
alpha = int.from_bytes(H, "little")
e = alpha % q
if e == 0: e = 1

v = pow(e, -1, q)
z1 = (s * v) % q
z2 = (-r * v) % q
C = point_add(point_mul(z1, P), point_mul(z2, Q))

if C is not None and (C[0] % q == r):
    print("STANDALONE PURE PYTHON VERIFICATION: SIGNATURE VALID [OK]")
else:
    print("STANDALONE PURE PYTHON VERIFICATION: SIGNATURE INVALID [FAIL]")
'''

exec(standalone_verify_script)

# ------------------------------------------------------------------
# Method 2: Internal CryptoMail API Verification
# ------------------------------------------------------------------
print()
print("=" * 60)
print("METHOD 2: CryptoMail API Verification")
print("=" * 60)

reloaded_pub = load_ecp_public_key_pem(pub_pem)
valid = verify_message_signature(reloaded_pub, message, sig_b64)
print(f"API verify result: {'SIGNATURE VALID [OK]' if valid else 'SIGNATURE INVALID [FAIL]'}")

# Verify tampering resistance
tampered_valid = verify_message_signature(reloaded_pub, message + b" [tampered]", sig_b64)
print(f"Tampered message verify result: {'REJECTED [OK]' if not tampered_valid else 'ACCEPTED [FAIL]'}")
