# Description: GOST R 34.12-2015 Kuznyechik 128-bit block cipher implementation supporting CBC and CTR modes.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import hmac
import os
from typing import List, Tuple

# RFC 7801 Section 4.1 Nonlinear Bijection Pi'
PI = (
    252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77,
    233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193,
    249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79,
      5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31,
    235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
    181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135,
     21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
     50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87,
    223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3,
    224,  15, 236, 222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74,
    167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
    173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59,
      7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228, 136, 217, 231, 137,
    225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,
     32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,
     89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,  75,  99, 182
)

# RFC 7801 Section 4.1 Pi^(-1)' Inverse S-box
PI_INV = (
    165,  45,  50, 143,  14,  48,  56, 192,  84, 230, 158,  57,  85, 126,  82, 145,
    100,   3,  87,  90,  28,  96,   7,  24,  33, 114, 168, 209,  41, 198, 164,  63,
    224,  39, 141,  12, 130, 234, 174, 180, 154,  99,  73, 229,  66, 228,  21, 183,
    200,   6, 112, 157,  65, 117,  25, 201, 170, 252,  77, 191,  42, 115, 132, 213,
    195, 175,  43, 134, 167, 177, 178,  91,  70, 211, 159, 253, 212,  15, 156,  47,
    155,  67, 239, 217, 121, 182,  83, 127, 193, 240,  35, 231,  37,  94, 181,  30,
    162, 223, 166, 254, 172,  34, 249, 226,  74, 188,  53, 202, 238, 120,   5, 107,
     81, 225,  89, 163, 242, 113,  86,  17, 106, 137, 148, 101, 140, 187, 119,  60,
    123,  40, 171, 210,  49, 222, 196,  95, 204, 207, 118,  44, 184, 216,  46,  54,
    219, 105, 179,  20, 149, 190,  98, 161,  59,  22, 102, 233,  92, 108, 109, 173,
     55,  97,  75, 185, 227, 186, 241, 160, 133, 131, 218,  71, 197, 176,  51, 250,
    150, 111, 110, 194, 246,  80, 255,  93, 169, 142,  23,  27, 151, 125, 236,  88,
    247,  31, 251, 124,   9,  13, 122, 103,  69, 135, 220, 232,  79,  29,  78,   4,
    235, 248, 243,  62,  61, 189, 138, 136, 221, 205,  11,  19, 152,   2, 147, 128,
    144, 208,  36,  52, 203, 237, 244, 206, 153,  16,  68,  64, 146,  58,   1,  38,
     18,  26,  72, 104, 245, 129, 139, 199, 214,  32,  10,   8,   0,  76, 215, 116
)

# GF(2^8) multiplication table for polynomial x^8 + x^7 + x^6 + x + 1 (0x1C3)
def _gf_mult(a: int, b: int) -> int:
    res = 0
    while b > 0:
        if b & 1:
            res ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1C3
        b >>= 1
    return res & 0xFF

GF_MULT = [[_gf_mult(i, j) for j in range(256)] for i in range(256)]

# Linear transformation constants c from RFC 7801 Section 4.2
L_VEC = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]


def _R(state: bytes) -> bytes:
    val = 0
    for i in range(16):
        val ^= GF_MULT[state[i]][L_VEC[i]]
    return bytes([val]) + state[:15]


def _R_inv(state: bytes) -> bytes:
    val = state[0]
    for i in range(15):
        val ^= GF_MULT[state[i + 1]][L_VEC[i]]
    return state[1:] + bytes([val])


def _L(state: bytes) -> bytes:
    for _ in range(16):
        state = _R(state)
    return state


def _L_inv(state: bytes) -> bytes:
    for _ in range(16):
        state = _R_inv(state)
    return state


def _S(state: bytes) -> bytes:
    return bytes(PI[b] for b in state)


def _S_inv(state: bytes) -> bytes:
    return bytes(PI_INV[b] for b in state)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _gen_round_constants() -> List[bytes]:
    c = []
    for i in range(1, 33):
        vec = bytearray(16)
        vec[15] = i
        c.append(_L(bytes(vec)))
    return c

ROUND_CONSTANTS = _gen_round_constants()


def _F(k1: bytes, k2: bytes, c: bytes) -> Tuple[bytes, bytes]:
    transformed = _L(_S(_xor(k1, c)))
    return _xor(transformed, k2), k1


def expand_key(key: bytes) -> List[bytes]:
    """Expands 32-byte key into 10 round keys of 16 bytes each."""
    if len(key) != 32:
        raise ValueError("Kuznyechik key must be 32 bytes (256 bits).")
    
    k1 = key[:16]
    k2 = key[16:]
    round_keys = [k1, k2]
    
    a = k1
    b = k2
    for i in range(4):
        for j in range(8):
            c_idx = i * 8 + j
            a, b = _F(a, b, ROUND_CONSTANTS[c_idx])
        round_keys.append(a)
        round_keys.append(b)
        
    return round_keys


class Kuznyechik:
    """Kuznyechik cipher (GOST R 34.12-2015) 128-bit block / 256-bit key."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError(f"Key length must be 32 bytes, got {len(key)}")
        self.round_keys = expand_key(key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError(f"Block size must be 16 bytes, got {len(block)}")
        
        state = block
        for i in range(9):
            state = _L(_S(_xor(state, self.round_keys[i])))
        return _xor(state, self.round_keys[9])

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError(f"Block size must be 16 bytes, got {len(block)}")
        
        state = _xor(block, self.round_keys[9])
        for i in range(8, 0, -1):
            state = _xor(_S_inv(_L_inv(state)), self.round_keys[i])
        state = _S_inv(_L_inv(state))
        return _xor(state, self.round_keys[0])

    @staticmethod
    def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
        if not data or len(data) % block_size != 0:
            raise ValueError("Invalid PKCS#7 padding.")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("Invalid PKCS#7 padding.")
        expected_pad = bytes([pad_len] * pad_len)
        if not hmac.compare_digest(data[-pad_len:], expected_pad):
            raise ValueError("Invalid PKCS#7 padding.")
        return data[:-pad_len]

    def encrypt_cbc(self, plaintext: bytes, iv: bytes = None) -> bytes:
        """Encrypts data in CBC mode with PKCS#7 padding. Returns IV + ciphertext."""
        if iv is None:
            iv = os.urandom(16)
        elif len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        padded = self.pad_pkcs7(plaintext, 16)
        prev = iv
        ciphertext = bytearray()

        for i in range(0, len(padded), 16):
            block = padded[i:i + 16]
            xored = _xor(block, prev)
            enc = self.encrypt_block(xored)
            ciphertext.extend(enc)
            prev = enc

        return iv + bytes(ciphertext)

    def decrypt_cbc(self, data: bytes) -> bytes:
        """Decrypts IV + ciphertext in CBC mode and unpads PKCS#7."""
        if len(data) < 32 or len(data) % 16 != 0:
            raise ValueError("Invalid CBC ciphertext length (minimum 32 bytes, multiple of 16)")
        iv = data[:16]
        ct = data[16:]
        
        prev = iv
        plaintext = bytearray()
        for i in range(0, len(ct), 16):
            block = ct[i:i + 16]
            dec = self.decrypt_block(block)
            plaintext.extend(_xor(dec, prev))
            prev = block
            
        return self.unpad_pkcs7(bytes(plaintext), 16)

    def encrypt_ctr(self, data: bytes, iv: bytes = None) -> bytes:
        """Encrypts/Decrypts data in CTR mode (GOST R 34.13-2015). Returns IV + ciphertext."""
        if iv is None:
            iv = os.urandom(16)
        elif len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        out = bytearray()
        iv_hi = iv[:8]
        ctr_val = int.from_bytes(iv[8:], byteorder="big")
        
        block_idx = 0
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            curr_ctr = (ctr_val + block_idx) & 0xFFFFFFFFFFFFFFFF
            ctr_bytes = iv_hi + curr_ctr.to_bytes(8, byteorder="big")
            keystream = self.encrypt_block(ctr_bytes)
            out.extend(_xor(chunk, keystream[:len(chunk)]))
            block_idx += 1
            
        return iv + bytes(out)

    def decrypt_ctr(self, data: bytes) -> bytes:
        """Decrypts CTR data (IV + ciphertext) according to GOST R 34.13-2015."""
        if len(data) < 16:
            raise ValueError("CTR data too short (must include 16-byte IV)")
        iv = data[:16]
        ct = data[16:]
        iv_hi = iv[:8]
        ctr_val = int.from_bytes(iv[8:], byteorder="big")
        out = bytearray()
        block_idx = 0
        for i in range(0, len(ct), 16):
            chunk = ct[i:i + 16]
            curr_ctr = (ctr_val + block_idx) & 0xFFFFFFFFFFFFFFFF
            ctr_bytes = iv_hi + curr_ctr.to_bytes(8, byteorder="big")
            keystream = self.encrypt_block(ctr_bytes)
            out.extend(_xor(chunk, keystream[:len(chunk)]))
            block_idx += 1
        return bytes(out)
