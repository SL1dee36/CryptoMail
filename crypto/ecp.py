# Description: Digital signature module implementing GOST R 34.10-2012 (256/512-bit) with Streebog digest, pure Python without cryptography library.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import datetime
import json
import os
import secrets
import uuid
from typing import Dict, List, Optional, Tuple, Union

from crypto.streebog import streebog256, streebog512

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


def _encode_bit_string(data: bytes) -> bytes:
    return _encode_tlv(0x03, b"\x00" + data)


def _encode_octet_string(data: bytes) -> bytes:
    return _encode_tlv(0x04, data)


def _encode_sequence(*items: bytes) -> bytes:
    return _encode_tlv(0x30, b"".join(items))


def _encode_set(*items: bytes) -> bytes:
    return _encode_tlv(0x31, b"".join(items))


def _encode_utf8_string(s: str) -> bytes:
    return _encode_tlv(0x0C, s.encode("utf-8"))


def _encode_printable_string(s: str) -> bytes:
    return _encode_tlv(0x13, s.encode("ascii"))


def _encode_utctime(dt: datetime.datetime) -> bytes:
    return _encode_tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _encode_boolean(val: bool) -> bytes:
    return _encode_tlv(0x01, b"\xFF" if val else b"\x00")


def _decode_der(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of DER data")
    tag = data[offset]
    offset += 1
    length_byte = data[offset]
    offset += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        num_len_bytes = length_byte & 0x7F
        length = int.from_bytes(data[offset:offset + num_len_bytes], "big")
        offset += num_len_bytes
    value = data[offset:offset + length]
    next_offset = offset + length
    return tag, value, next_offset


def _parse_sequence(data: bytes):
    items = []
    offset = 0
    while offset < len(data):
        tag, val, offset = _decode_der(data, offset)
        items.append((tag, val))
    return items


def _decode_oid(data: bytes) -> str:
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    idx = 1
    val = 0
    while idx < len(data):
        b = data[idx]
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
        idx += 1
    return ".".join(parts)


def _extract_all_oids(data_bytes: bytes) -> List[str]:
    oids = []
    try:
        offset = 0
        while offset < len(data_bytes):
            tag, val, offset = _decode_der(data_bytes, offset)
            if tag == 0x06:
                oids.append(_decode_oid(val))
            elif tag in (0x30, 0x31):
                oids.extend(_extract_all_oids(val))
    except Exception:
        pass
    return oids


def _der_decode_signature(der: bytes) -> Tuple[int, int]:
    tag, val, _ = _decode_der(der)
    if tag != 0x30:
        raise ValueError("Invalid DER signature: missing SEQUENCE tag")
    items = _parse_sequence(val)
    if len(items) != 2:
        raise ValueError("Invalid DER signature: expected 2 elements")
    r = int.from_bytes(items[0][1], "big", signed=True)
    s = int.from_bytes(items[1][1], "big", signed=True)
    return r, s

# GOST R 34.10-2012 Curve Parameters and Group Arithmetic

class GostCurve:
    """
    Represents an elliptic curve over a finite prime field GF(p)
    as defined in GOST R 34.10-2012 (canonical Weierstrass form: y^2 = x^3 + a*x + b mod p).
    """

    def __init__(
        self,
        name: str,
        alg_oid: str,
        param_oid: str,
        bit_len: int,
        p: int,
        a: int,
        b: int,
        q: int,
        px: int,
        py: int,
        hash_func,
    ):
        self.name = name
        self.alg_oid = alg_oid
        self.param_oid = param_oid
        self.bit_len = bit_len
        self.byte_len = bit_len // 8
        self.p = p
        self.a = a
        self.b = b
        self.q = q
        self.P = (px, py)
        self.hash_func = hash_func

    def is_on_curve(self, point: Optional[Tuple[int, int]]) -> bool:
        if point is None:
            return False
        x, y = point
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        return (pow(y, 2, self.p) - (pow(x, 3, self.p) + self.a * x + self.b)) % self.p == 0

    def point_add(
        self, P1: Optional[Tuple[int, int]], P2: Optional[Tuple[int, int]]
    ) -> Optional[Tuple[int, int]]:
        """Adds two points on the elliptic curve according to RFC 7091 equations (4) and (5)."""
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        x1, y1 = P1
        x2, y2 = P2
        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return None
            lam = ((3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p)) % self.p
        else:
            lam = ((y2 - y1) * pow(x2 - x1, -1, self.p)) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def point_mul(self, k: int, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """Multiplies point P by scalar k using double-and-add algorithm."""
        if P is None or k % self.q == 0:
            return None
        k = k % self.q
        R = None
        addend = P
        while k > 0:
            if k & 1:
                R = self.point_add(R, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return R

    def sign(self, d: int, message: bytes, k: Optional[int] = None) -> bytes:
        """
        GOST R 34.10-2012 Algorithm I: Digital Signature Generation Process.
        RFC 7091 Section 6.1.
        Returns binary signature zeta = (R || S).
        """
        # Step 1: H = h(M)
        H = self.hash_func(message)
        # Step 2: alpha = int(H), e = alpha mod q, if e == 0: e = 1
        alpha = int.from_bytes(H, byteorder="little")
        e = alpha % self.q
        if e == 0:
            e = 1

        while True:
            # Step 3: ephemeral random k in (0, q)
            if k is not None:
                ephemeral_k = k
            else:
                ephemeral_k = secrets.randbelow(self.q - 1) + 1

            # Step 4: C = k * P, r = x_C mod q
            C = self.point_mul(ephemeral_k, self.P)
            if C is None:
                if k is not None:
                    raise ValueError("Specified k yields point at infinity")
                continue
            r = C[0] % self.q
            if r == 0:
                if k is not None:
                    raise ValueError("Specified k yields r = 0")
                continue

            # Step 5: s = (r * d + k * e) mod q
            s = (r * d + ephemeral_k * e) % self.q
            if s == 0:
                if k is not None:
                    raise ValueError("Specified k yields s = 0")
                continue
            break

        # Step 6: R || S (both byte_len bytes big-endian)
        R_bytes = r.to_bytes(self.byte_len, byteorder="big")
        S_bytes = s.to_bytes(self.byte_len, byteorder="big")
        return R_bytes + S_bytes

    def verify(self, Q: Tuple[int, int], message: bytes, signature_bytes: bytes) -> bool:
        """
        GOST R 34.10-2012 Algorithm II: Digital Signature Verification Process.
        RFC 7091 Section 6.2 and RFC 9215 Section 2.
        Supports both R || S (RFC 7091 raw) and S || R (RFC 9215 CMS / PKI) formats.
        """
        # Step 1: Extract candidate integers (r, s)
        candidates = []
        if len(signature_bytes) == 2 * self.byte_len:
            val1 = int.from_bytes(signature_bytes[:self.byte_len], byteorder="big")
            val2 = int.from_bytes(signature_bytes[self.byte_len:], byteorder="big")
            # val1 could be R (RFC 7091) or S (RFC 9215)
            candidates.append((val1, val2))
            candidates.append((val2, val1))
            # Also check little-endian vector representation
            val1_le = int.from_bytes(signature_bytes[:self.byte_len], byteorder="little")
            val2_le = int.from_bytes(signature_bytes[self.byte_len:], byteorder="little")
            candidates.append((val1_le, val2_le))
            candidates.append((val2_le, val1_le))
        else:
            try:
                r_der, s_der = _der_decode_signature(signature_bytes)
                candidates.append((r_der, s_der))
                candidates.append((s_der, r_der))
            except Exception:
                return False

        if not self.is_on_curve(Q):
            return False

        # Step 2: H = h(M)
        H = self.hash_func(message)
        # Step 3: alpha = int(H) (little-endian byte mapping from Streebog), e = alpha mod q
        alpha = int.from_bytes(H, byteorder="little")
        e = alpha % self.q
        if e == 0:
            e = 1

        # Step 4: v = e^(-1) mod q
        v = pow(e, -1, self.q)

        for r_cand, s_cand in candidates:
            if not (0 < r_cand < self.q and 0 < s_cand < self.q):
                continue
            # Step 5: z1 = s * v mod q, z2 = -r * v mod q
            z1 = (s_cand * v) % self.q
            z2 = (-r_cand * v) % self.q
            p1 = self.point_mul(z1, self.P)
            p2 = self.point_mul(z2, Q)
            C = self.point_add(p1, p2)
            if C is not None and (C[0] % self.q) == r_cand:
                return True

        return False


# Standard curve definitions:

# 1. GOST R 34.10-2012 512-bit (RFC 7836 Appendix A.1 id-tc26-gost-3410-12-512-paramSetA)
CURVE_GOST_2012_512 = GostCurve(
    name="id-tc26-gost-3410-12-512-paramSetA",
    alg_oid="1.2.643.7.1.1.1.2",    # id-tc26-gost3410-2012-512
    param_oid="1.2.643.7.1.2.1.2.1",  # id-tc26-gost-3410-12-512-paramSetA
    bit_len=512,
    p=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", 16),
    a=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4", 16),
    b=int("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760", 16),
    q=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275", 16),
    px=3,
    py=int("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4", 16),
    hash_func=streebog512,
)

# 2. GOST R 34.10-2012 256-bit (RFC 7091 Section 7 / RFC 4357 CryptoPro-A / id-tc26-gost-3410-2012-256-paramSetA)
CURVE_GOST_2012_256 = GostCurve(
    name="id-tc26-gost-3410-2012-256-paramSetA",
    alg_oid="1.2.643.7.1.1.1.1",    # id-tc26-gost3410-2012-256
    param_oid="1.2.643.7.1.2.1.1.1",  # id-tc26-gost-3410-2012-256-paramSetA
    bit_len=256,
    p=0x8000000000000000000000000000000000000000000000000000000000000431,
    a=7,
    b=0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E,
    q=0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
    px=2,
    py=0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8,
    hash_func=streebog256,
)

OID_TO_CURVE = {
    CURVE_GOST_2012_512.param_oid: CURVE_GOST_2012_512,
    CURVE_GOST_2012_512.alg_oid: CURVE_GOST_2012_512,
    CURVE_GOST_2012_256.param_oid: CURVE_GOST_2012_256,
    CURVE_GOST_2012_256.alg_oid: CURVE_GOST_2012_256,
}


def get_curve(param: Union[int, str] = 512) -> GostCurve:
    """Returns GostCurve instance by bit length or parameter name."""
    if isinstance(param, int):
        if param == 256:
            return CURVE_GOST_2012_256
        return CURVE_GOST_2012_512
    s = str(param).lower()
    if "256" in s:
        return CURVE_GOST_2012_256
    return CURVE_GOST_2012_512


# ---------------------------------------------------------------------------
# Key Classes
# ---------------------------------------------------------------------------

class GostPublicKey:
    """Public key for GOST R 34.10-2012 digital signature verification."""

    def __init__(self, point: Tuple[int, int], curve: GostCurve):
        self.point = point
        self.curve = curve

    @property
    def x(self) -> int:
        return self.point[0]

    @property
    def y(self) -> int:
        return self.point[1]

    @property
    def key_size(self) -> int:
        return self.curve.bit_len

    def verify(self, signature_bytes: bytes, message: bytes) -> bool:
        return self.curve.verify(self.point, message, signature_bytes)

    def to_pem(self) -> str:
        return export_ecp_public_key_pem(self)

    def to_der(self) -> bytes:
        return _export_public_key_der(self)

    def public_bytes(self, *args, **kwargs) -> bytes:
        return self.to_pem().encode("utf-8")


class GostPrivateKey:
    """Private key for GOST R 34.10-2012 digital signature generation."""

    def __init__(self, d: int, curve: GostCurve):
        self.d = d
        self.curve = curve
        pub_point = curve.point_mul(d, curve.P)
        if pub_point is None:
            raise ValueError("Invalid private key: generated public point at infinity")
        self._pub = GostPublicKey(pub_point, curve)

    @property
    def key_size(self) -> int:
        return self.curve.bit_len

    def public_key(self) -> GostPublicKey:
        return self._pub

    def sign(self, message: bytes, k: Optional[int] = None) -> bytes:
        return self.curve.sign(self.d, message, k=k)

    def to_pem(self) -> str:
        return export_ecp_private_key_pem(self)

    def to_der(self) -> bytes:
        return _export_private_key_der(self)

    def private_bytes(self, *args, **kwargs) -> bytes:
        return self.to_pem().encode("utf-8")


# ---------------------------------------------------------------------------
# DER / PEM Serialization and Deserialization
# ---------------------------------------------------------------------------

def _export_public_key_der(public_key: GostPublicKey) -> bytes:
    # Standard RFC 9215 SubjectPublicKeyInfo format
    pub_bytes = (
        public_key.x.to_bytes(public_key.curve.byte_len, "little")
        + public_key.y.to_bytes(public_key.curve.byte_len, "little")
    )
    alg_id = _encode_sequence(
        _encode_oid(public_key.curve.alg_oid),
        _encode_sequence(_encode_oid(public_key.curve.param_oid)),
    )
    return _encode_sequence(alg_id, _encode_bit_string(_encode_octet_string(pub_bytes)))


def _export_private_key_der(private_key: GostPrivateKey) -> bytes:
    d_bytes = private_key.d.to_bytes(private_key.curve.byte_len, "big")
    alg_id = _encode_sequence(
        _encode_oid(private_key.curve.alg_oid),
        _encode_sequence(_encode_oid(private_key.curve.param_oid)),
    )
    return _encode_sequence(
        _encode_integer(0),  # version 0 (PKCS#8)
        alg_id,
        _encode_octet_string(_encode_octet_string(d_bytes)),
    )


def _load_public_key_der_or_json(raw: bytes) -> GostPublicKey:
    # 1. Try parsing JSON format
    try:
        obj = json.loads(raw.decode("utf-8"))
        if "x" in obj and "y" in obj:
            x = int(obj["x"], 16) if isinstance(obj["x"], str) else int(obj["x"])
            y = int(obj["y"], 16) if isinstance(obj["y"], str) else int(obj["y"])
            curve = get_curve(obj.get("bit_len", 512))
            return GostPublicKey((x, y), curve)
    except Exception:
        pass

    # 2. Parse ASN.1 DER SubjectPublicKeyInfo
    tag, val, _ = _decode_der(raw)
    if tag != 0x30:
        raise ValueError("Invalid public key DER: expected SEQUENCE")
    items = _parse_sequence(val)
    param_oid = None
    pub_bytes = None
    for item_tag, item_val in items:
        if item_tag == 0x30:
            for oid_str in _extract_all_oids(item_val):
                if oid_str in OID_TO_CURVE:
                    param_oid = oid_str
                    break
        elif item_tag == 0x03:
            pub_bytes = item_val[1:]  # strip leading unused bits byte
        elif item_tag == 0x04:
            pub_bytes = item_val

    if pub_bytes is None:
        raise ValueError("Could not extract public key coordinates from DER")

    # If pub_bytes contains an encapsulated OCTET STRING (tag 0x04), unwrap it
    if len(pub_bytes) > 2 and pub_bytes[0] == 0x04:
        try:
            _, inner_octets, _ = _decode_der(pub_bytes)
            pub_bytes = inner_octets
        except Exception:
            pass

    curve = OID_TO_CURVE.get(param_oid, CURVE_GOST_2012_512)
    if len(pub_bytes) == 1 + 2 * curve.byte_len and pub_bytes[0] == 0x04:
        pub_bytes = pub_bytes[1:]

    if len(pub_bytes) == 2 * curve.byte_len:
        # Check little-endian first (RFC 9215 standard), then big-endian
        x_le = int.from_bytes(pub_bytes[:curve.byte_len], "little")
        y_le = int.from_bytes(pub_bytes[curve.byte_len:], "little")
        if curve.is_on_curve((x_le, y_le)):
            return GostPublicKey((x_le, y_le), curve)
        x_be = int.from_bytes(pub_bytes[:curve.byte_len], "big")
        y_be = int.from_bytes(pub_bytes[curve.byte_len:], "big")
        if curve.is_on_curve((x_be, y_be)):
            return GostPublicKey((x_be, y_be), curve)
        return GostPublicKey((x_le, y_le), curve)
    elif len(pub_bytes) == 2 * CURVE_GOST_2012_256.byte_len:
        curve = CURVE_GOST_2012_256
        x_le = int.from_bytes(pub_bytes[:curve.byte_len], "little")
        y_le = int.from_bytes(pub_bytes[curve.byte_len:], "little")
        if curve.is_on_curve((x_le, y_le)):
            return GostPublicKey((x_le, y_le), curve)
        x_be = int.from_bytes(pub_bytes[:curve.byte_len], "big")
        y_be = int.from_bytes(pub_bytes[curve.byte_len:], "big")
        if curve.is_on_curve((x_be, y_be)):
            return GostPublicKey((x_be, y_be), curve)
        return GostPublicKey((x_le, y_le), curve)

    raise ValueError(f"Unexpected public key bytes length: {len(pub_bytes)}")


def _load_private_key_der_or_json(raw: bytes) -> GostPrivateKey:
    # 1. Try parsing JSON format
    try:
        obj = json.loads(raw.decode("utf-8"))
        if "d" in obj:
            d = int(obj["d"], 16) if isinstance(obj["d"], str) else int(obj["d"])
            curve = get_curve(obj.get("bit_len", 512))
            return GostPrivateKey(d, curve)
    except Exception:
        pass

    # 2. Parse ASN.1 DER PrivateKeyInfo (PKCS#8)
    tag, val, _ = _decode_der(raw)
    if tag != 0x30:
        raise ValueError("Invalid private key DER: expected SEQUENCE")
    items = _parse_sequence(val)
    param_oid = None
    d_bytes = None
    for item_tag, item_val in items:
        if item_tag == 0x30:
            for oid_str in _extract_all_oids(item_val):
                if oid_str in OID_TO_CURVE:
                    param_oid = oid_str
                    break
        elif item_tag == 0x04:
            if len(item_val) > 2 and item_val[0] == 0x04:
                _, inner_val, _ = _decode_der(item_val)
                d_bytes = inner_val
            else:
                d_bytes = item_val
        elif item_tag == 0x02 and len(items) == 2:
            d_bytes = item_val

    if d_bytes is None:
        raise ValueError("Could not extract private key scalar from DER")

    curve = OID_TO_CURVE.get(param_oid, CURVE_GOST_2012_512)
    d = int.from_bytes(d_bytes, "big")
    return GostPrivateKey(d, curve)


# ---------------------------------------------------------------------------
# Public Module API
# ---------------------------------------------------------------------------

def generate_ecp_keypair(
    mode: Union[int, str] = 512
) -> Tuple[GostPrivateKey, GostPublicKey]:
    """
    Generates a GOST R 34.10-2012 key pair.
    Default mode: 512-bit (GOST R 34.10-2012 with Streebog-512).
    Supported modes: 512, 256.
    """
    curve = get_curve(mode)
    d = secrets.randbelow(curve.q - 1) + 1
    priv = GostPrivateKey(d, curve)
    return priv, priv.public_key()


def export_ecp_private_key_pem(private_key: GostPrivateKey) -> str:
    """Exports GOST R 34.10-2012 private key in standard PEM (PKCS#8) format."""
    der = _export_private_key_der(private_key)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"


def export_ecp_public_key_pem(public_key: GostPublicKey) -> str:
    """Exports GOST R 34.10-2012 public key in standard PEM (SubjectPublicKeyInfo) format."""
    der = _export_public_key_der(public_key)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def load_ecp_private_key_pem(pem_data: Union[str, bytes]) -> GostPrivateKey:
    """Loads GOST R 34.10-2012 private key from PEM string or bytes."""
    if isinstance(pem_data, bytes):
        pem_data = pem_data.decode("utf-8", errors="replace")
    clean_lines = [
        line.strip()
        for line in pem_data.splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    raw = base64.b64decode("".join(clean_lines))
    return _load_private_key_der_or_json(raw)


def load_ecp_public_key_pem(pem_data: Union[str, bytes]) -> GostPublicKey:
    """Loads GOST R 34.10-2012 public key from PEM string or bytes."""
    if isinstance(pem_data, bytes):
        pem_data = pem_data.decode("utf-8", errors="replace")
    clean_lines = [
        line.strip()
        for line in pem_data.splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    raw = base64.b64decode("".join(clean_lines))
    return _load_public_key_der_or_json(raw)


def load_signature_from_file_or_data(sig_input: Union[str, bytes]) -> bytes:
    """
    Parses a signature from a Base64 string, raw bytes, or a .sig file path.
    Supports both raw binary signatures (64/128 bytes) and Base64-encoded signatures
    with or without PEM headers.
    """
    if isinstance(sig_input, str):
        if os.path.isfile(sig_input):
            with open(sig_input, "rb") as f:
                raw_file = f.read()
            return load_signature_from_file_or_data(raw_file)

        # String data
        clean = sig_input.strip()
        if "-----" in clean:
            lines = [l.strip() for l in clean.splitlines() if not l.strip().startswith("-----")]
            clean = "".join(lines)
        try:
            return base64.b64decode(clean)
        except Exception:
            return sig_input.encode("utf-8")

    if isinstance(sig_input, bytes):
        # Check if already binary DER sequence or binary raw signature
        if len(sig_input) in (64, 128) and not sig_input.startswith(b"MI") and not sig_input.startswith(b"=="):
            return sig_input
        if len(sig_input) > 2 and sig_input[0] == 0x30 and not sig_input.startswith(b"0"):
            return sig_input

        # Try decoding as Base64 / PEM bytes
        clean_b = sig_input.strip()
        if b"-----" in clean_b:
            lines_b = [l.strip() for l in clean_b.splitlines() if not l.strip().startswith(b"-----")]
            clean_b = b"".join(lines_b)
        try:
            decoded = base64.b64decode(clean_b, validate=False)
            if len(decoded) in (64, 128) or (len(decoded) > 2 and decoded[0] == 0x30):
                return decoded
        except Exception:
            pass
        return sig_input

    return sig_input


def create_x509_certificate_der(
    common_name: str,
    private_key: GostPrivateKey,
    public_key: Optional[GostPublicKey] = None,
    valid_days: int = 365,
    serial_number: Optional[int] = None,
    organization: str = "CryptoMail Secure Network",
) -> bytes:
    """
    Generates a standard self-signed X.509 v3 certificate (ASN.1 DER)
    for GOST R 34.10-2012 / GOST R 34.11-2012 according to RFC 9215 and RFC 5280.
    """
    if public_key is None:
        public_key = private_key.public_key()
    curve = private_key.curve
    byte_len = curve.byte_len

    # Issuer / Subject Name: CN=<common_name>, O=<organization>
    attr_cn = _encode_sequence(_encode_oid("2.5.4.3"), _encode_utf8_string(common_name))
    attr_org = _encode_sequence(_encode_oid("2.5.4.10"), _encode_utf8_string(organization))
    name_seq = _encode_sequence(_encode_set(attr_cn), _encode_set(attr_org))

    # Validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    after = now + datetime.timedelta(days=valid_days)
    validity = _encode_sequence(_encode_utctime(now), _encode_utctime(after))

    # SubjectPublicKeyInfo (RFC 9215)
    spki_alg = _encode_sequence(
        _encode_oid(curve.alg_oid),
        _encode_sequence(_encode_oid(curve.param_oid)),
    )
    x_le = public_key.x.to_bytes(byte_len, "little")
    y_le = public_key.y.to_bytes(byte_len, "little")
    pub_octets = _encode_octet_string(x_le + y_le)
    spki = _encode_sequence(spki_alg, _encode_bit_string(pub_octets))

    # Serial Number
    if serial_number is None:
        serial_number = secrets.randbits(64)
    serial_der = _encode_integer(serial_number)

    # Signature Algorithm: RFC 9215 parameters MUST be omitted
    sig_oid = "1.2.643.7.1.1.3.3" if curve.bit_len == 512 else "1.2.643.7.1.1.3.2"
    sig_alg = _encode_sequence(_encode_oid(sig_oid))

    # Extensions (RFC 5280):
    # 1. BasicConstraints: CA=True, critical
    ext_bc_val = _encode_sequence(_encode_boolean(True))
    ext_bc = _encode_sequence(
        _encode_oid("2.5.29.19"),
        _encode_boolean(True),
        _encode_octet_string(ext_bc_val),
    )

    # 2. KeyUsage: digitalSignature, nonRepudiation, keyCertSign, cRLSign (critical)
    ext_ku_val = _encode_tlv(0x03, b"\x01\xC6")
    ext_ku = _encode_sequence(
        _encode_oid("2.5.29.15"),
        _encode_boolean(True),
        _encode_octet_string(ext_ku_val),
    )

    # 3. SubjectKeyIdentifier: 20-byte hash of public key octets
    digest_func = streebog256 if curve.bit_len == 256 else streebog512
    ski_val = digest_func(pub_octets)[:20]
    ext_ski = _encode_sequence(
        _encode_oid("2.5.29.14"),
        _encode_octet_string(_encode_octet_string(ski_val)),
    )

    # 4. AuthorityKeyIdentifier: keyIdentifier [0] IMPLICIT
    ext_aki_val = _encode_sequence(_encode_tlv(0x80, ski_val))
    ext_aki = _encode_sequence(
        _encode_oid("2.5.29.35"),
        _encode_octet_string(ext_aki_val),
    )

    extensions = _encode_tlv(0xA3, _encode_sequence(ext_bc, ext_ku, ext_ski, ext_aki))

    tbs = _encode_sequence(
        _encode_tlv(0xA0, _encode_integer(2)),  # v3
        serial_der,
        sig_alg,
        name_seq,
        validity,
        name_seq,
        spki,
        extensions,
    )

    sig_tbs = private_key.sign(tbs)
    r_tbs = int.from_bytes(sig_tbs[:byte_len], "big")
    s_tbs = int.from_bytes(sig_tbs[byte_len:], "big")
    # RFC 9215: S || R
    cert_sig = s_tbs.to_bytes(byte_len, "big") + r_tbs.to_bytes(byte_len, "big")
    return _encode_sequence(tbs, sig_alg, _encode_bit_string(cert_sig))


def export_x509_certificate_pem(cert_der: bytes) -> str:
    """Exports X.509 certificate DER bytes in standard PEM format."""
    b64 = base64.b64encode(cert_der).decode("ascii")
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def load_x509_certificate_pem(pem_or_der: Union[str, bytes]) -> bytes:
    """Loads X.509 certificate DER bytes from PEM string or raw DER bytes."""
    if isinstance(pem_or_der, bytes):
        if pem_or_der.startswith(b"-----"):
            pem_or_der = pem_or_der.decode("utf-8", errors="replace")
        else:
            return pem_or_der
    clean = [
        l.strip()
        for l in pem_or_der.splitlines()
        if l.strip() and not l.strip().startswith("-----")
    ]
    return base64.b64decode("".join(clean))


def extract_public_key_from_x509_der(cert_der: bytes) -> Optional[GostPublicKey]:
    """Extracts GostPublicKey from an X.509 DER certificate."""
    try:
        tag, val, _ = _decode_der(cert_der)
        if tag == 0xA0:  # [0] IMPLICIT CertificateSet
            _, val, _ = _decode_der(val)
        cert_items = _parse_sequence(val)
        tbs_bytes = cert_items[0][1]
        tbs_items = _parse_sequence(tbs_bytes)
        for ttag, tval in tbs_items:
            if ttag == 0x30:
                sub_items = _parse_sequence(tval)
                if len(sub_items) == 2 and sub_items[1][0] == 0x03:
                    # Found SubjectPublicKeyInfo
                    bit_val = sub_items[1][1]
                    pub_octets = bit_val[1:]  # strip unused bits byte
                    if len(pub_octets) > 2 and pub_octets[0] == 0x04:
                        _, pub_octets, _ = _decode_der(pub_octets)
                    curve = CURVE_GOST_2012_512 if len(pub_octets) == 128 else CURVE_GOST_2012_256
                    byte_len = curve.byte_len
                    # Try little-endian first (RFC 9215 standard)
                    x_le = int.from_bytes(pub_octets[:byte_len], "little")
                    y_le = int.from_bytes(pub_octets[byte_len:], "little")
                    if curve.is_on_curve((x_le, y_le)):
                        return GostPublicKey((x_le, y_le), curve)
                    # Try big-endian
                    x_be = int.from_bytes(pub_octets[:byte_len], "big")
                    y_be = int.from_bytes(pub_octets[byte_len:], "big")
                    if curve.is_on_curve((x_be, y_be)):
                        return GostPublicKey((x_be, y_be), curve)
        return None
    except Exception:
        return None


def create_cms_signed_data(
    data_bytes: bytes,
    private_key: Union[GostPrivateKey, str, bytes],
    cert_der: Optional[bytes] = None,
    common_name: str = "Alice",
    detached: bool = True,
) -> bytes:
    """
    Creates a CMS (PKCS#7) SignedData container for a detached digital signature
    conforming to RFC 5652 and RFC 9215 (GOST R 34.10-2012 / GOST R 34.11-2012).
    Fully compatible with CryptoPro CSP, Gosuslugi, Diadoc, Kontur.
    """
    if isinstance(private_key, (str, bytes)):
        private_key = load_ecp_private_key_pem(private_key)

    curve = private_key.curve
    byte_len = curve.byte_len

    if cert_der is None:
        cert_der = create_x509_certificate_der(common_name, private_key)

    # Extract issuer and serial from cert_der for SignerIdentifier (IssuerAndSerialNumber)
    _, cert_body, _ = _decode_der(cert_der)
    cert_elements = _parse_sequence(cert_body)
    tbs_bytes = cert_elements[0][1]
    tbs_elements = _parse_sequence(tbs_bytes)
    idx = 0
    if tbs_elements[0][0] == 0xA0:  # version [0]
        idx = 1
    serial_der = _encode_tlv(0x02, tbs_elements[idx][1])
    issuer_der = _encode_tlv(0x30, tbs_elements[idx + 2][1])
    sid = _encode_sequence(issuer_der, serial_der)

    # Digest algorithm
    digest_func = streebog512 if curve.bit_len == 512 else streebog256
    digest_oid = "1.2.643.7.1.1.2.3" if curve.bit_len == 512 else "1.2.643.7.1.1.2.2"
    digest_alg = _encode_sequence(_encode_oid(digest_oid))

    # Compute Streebog hash of data
    data_hash = digest_func(data_bytes)

    # Signed Attributes (RFC 5652 / CAdES):
    # 1. contentType (1.2.840.113549.1.9.3) -> id-data (1.2.840.113549.1.7.1)
    # 2. messageDigest (1.2.840.113549.1.9.4) -> OCTET STRING
    # 3. signingTime (1.2.840.113549.1.9.5) -> UTCTime
    now = datetime.datetime.now(datetime.timezone.utc)
    attr_ct = _encode_sequence(
        _encode_oid("1.2.840.113549.1.9.3"),
        _encode_set(_encode_oid("1.2.840.113549.1.7.1")),
    )
    attr_md = _encode_sequence(
        _encode_oid("1.2.840.113549.1.9.4"),
        _encode_set(_encode_octet_string(data_hash)),
    )
    attr_st = _encode_sequence(
        _encode_oid("1.2.840.113549.1.9.5"),
        _encode_set(_encode_utctime(now)),
    )

    # For signing: SET OF SignedAttributes (tag 0x31) in ascending DER order (RFC 5652 / X.690)
    sorted_attrs = sorted([attr_ct, attr_md, attr_st])
    signed_attrs_set = _encode_set(*sorted_attrs)
    sig_raw = private_key.sign(signed_attrs_set)
    r = int.from_bytes(sig_raw[:byte_len], "big")
    s = int.from_bytes(sig_raw[byte_len:], "big")
    # RFC 9215 CMS signature is S || R
    cms_sig_bytes = s.to_bytes(byte_len, "big") + r.to_bytes(byte_len, "big")

    # In SignerInfo: signedAttrs has tag 0xA0 (IMPLICIT [0])
    signed_attrs_field = _encode_tlv(0xA0, b"".join(sorted_attrs))

    # Signature algorithm
    sig_oid = "1.2.643.7.1.1.3.3" if curve.bit_len == 512 else "1.2.643.7.1.1.3.2"
    sig_alg = _encode_sequence(_encode_oid(sig_oid))

    signer_info = _encode_sequence(
        _encode_integer(1),  # version 1
        sid,
        digest_alg,
        signed_attrs_field,
        sig_alg,
        _encode_octet_string(cms_sig_bytes),
    )

    if detached:
        encap_content = _encode_sequence(_encode_oid("1.2.840.113549.1.7.1"))
    else:
        encap_content = _encode_sequence(
            _encode_oid("1.2.840.113549.1.7.1"),
            _encode_tlv(0xA0, _encode_octet_string(data_bytes)),
        )

    certs_field = _encode_tlv(0xA0, cert_der)

    signed_data = _encode_sequence(
        _encode_integer(1),
        _encode_set(digest_alg),
        encap_content,
        certs_field,
        _encode_set(signer_info),
    )

    return _encode_sequence(
        _encode_oid("1.2.840.113549.1.7.2"),  # id-signedData
        _encode_tlv(0xA0, signed_data),
    )


def is_cms_signature(data: bytes) -> bool:
    """Checks if raw bytes represent a CMS (PKCS#7) ContentInfo structure."""
    try:
        if len(data) < 16:
            return False
        tag, val, _ = _decode_der(data)
        if tag != 0x30:
            return False
        items = _parse_sequence(val)
        if len(items) >= 2 and items[0][0] == 0x06:
            oid = _decode_oid(items[0][1])
            return oid in ("1.2.840.113549.1.7.2", "1.2.840.113549.1.7.1")
        return False
    except Exception:
        return False


def verify_cms_signed_data(
    cms_bytes: bytes,
    data_bytes: bytes,
    public_key: Optional[Union[GostPublicKey, str, bytes]] = None,
) -> bool:
    """
    Verifies a detached CMS (PKCS#7) SignedData digital signature.
    Automatically validates the embedded messageDigest against data_bytes and verifies
    signature against the public key (or the embedded X.509 certificate).
    """
    try:
        cms_bytes = load_signature_from_file_or_data(cms_bytes)
        tag, val, _ = _decode_der(cms_bytes)
        if tag != 0x30:
            return False
        items = _parse_sequence(val)
        if len(items) < 2 or _decode_oid(items[0][1]) != "1.2.840.113549.1.7.2":
            return False
        if items[1][0] != 0xA0:
            return False
        sd_tag, sd_val, _ = _decode_der(items[1][1])
        if sd_tag != 0x30:
            return False
        sd_items = _parse_sequence(sd_val)

        certs_val = None
        signer_infos_val = None
        for itag, ival in sd_items:
            if itag == 0xA0:
                certs_val = ival
            elif itag == 0x31:
                signer_infos_val = ival

        if not signer_infos_val:
            return False

        if isinstance(public_key, (str, bytes)):
            public_key = load_ecp_public_key_pem(public_key)

        # If public key not provided, extract from embedded certificate
        if public_key is None and certs_val:
            public_key = extract_public_key_from_x509_der(certs_val)

        if public_key is None:
            return False

        curve = public_key.curve
        byte_len = curve.byte_len

        si_items = _parse_sequence(signer_infos_val)
        first_si = si_items[0][1] if si_items[0][0] == 0x30 else _decode_der(si_items[0][1])[1]
        si_fields = _parse_sequence(first_si)

        signed_attrs_bytes = None
        sig_bytes = None
        for stag, sval in si_fields:
            if stag == 0xA0:
                signed_attrs_bytes = sval
            elif stag == 0x04:
                sig_bytes = sval

        if not sig_bytes or len(sig_bytes) != 2 * byte_len:
            return False

        s = int.from_bytes(sig_bytes[:byte_len], "big")
        r = int.from_bytes(sig_bytes[byte_len:], "big")

        if signed_attrs_bytes is not None:
            digest_func = streebog512 if curve.bit_len == 512 else streebog256
            expected_digest = digest_func(data_bytes)
            attrs = _parse_sequence(signed_attrs_bytes)
            md_found = False
            for atag, aval in attrs:
                if atag == 0x30:
                    a_items = _parse_sequence(aval)
                    if len(a_items) >= 2 and _decode_oid(a_items[0][1]) == "1.2.840.113549.1.9.4":
                        set_items = _parse_sequence(a_items[1][1])
                        if set_items and set_items[0][1] == expected_digest:
                            md_found = True
                            break
            if not md_found:
                return False

            msg_to_verify = _encode_tlv(0x31, signed_attrs_bytes)
        else:
            msg_to_verify = data_bytes

        zeta = r.to_bytes(byte_len, "big") + s.to_bytes(byte_len, "big")
        return curve.verify(public_key.point, msg_to_verify, zeta)
    except Exception:
        return False


def sign_message(
    private_key: Union[GostPrivateKey, str, bytes],
    message: Union[str, bytes],
    cms: bool = False,
) -> str:
    """
    Signs message using GOST R 34.10-2012 digital signature with Streebog digest.
    Returns base64 encoded signature.
    """
    if isinstance(private_key, (str, bytes)):
        private_key = load_ecp_private_key_pem(private_key)
    if isinstance(message, str):
        message = message.encode("utf-8")
    if cms:
        cms_der = create_cms_signed_data(message, private_key)
        return base64.b64encode(cms_der).decode("ascii")
    sig_bytes = private_key.sign(message)
    return base64.b64encode(sig_bytes).decode("ascii")


def sign_file(
    private_key: Union[GostPrivateKey, str, bytes],
    file_path: str,
    out_sig_path: Optional[str] = None,
    binary_format: bool = False,
    binary: Optional[bool] = None,
    cms: bool = True,
    common_name: str = "Alice",
    cert: Optional[Union[str, bytes]] = None,
) -> Union[str, bytes]:
    """
    Signs a file using GOST R 34.10-2012 digital signature.
    By default creates an official detached CMS (PKCS#7) SignedData signature (.sig)
    conforming to RFC 5652 / RFC 9215 compatible with Gosuslugi and CryptoPro CSP.
    If binary_format (or binary) is True, writes binary DER bytes.
    Otherwise writes Base64-encoded text.
    """
    if binary is not None:
        binary_format = binary
    if isinstance(private_key, (str, bytes)):
        private_key = load_ecp_private_key_pem(private_key)
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    if cms:
        cert_der = None
        if cert:
            cert_der = load_x509_certificate_pem(cert)
        sig_data = create_cms_signed_data(
            file_bytes, private_key, cert_der=cert_der, common_name=common_name
        )
        sig_b64 = base64.b64encode(sig_data).decode("ascii")
    else:
        sig_data = private_key.sign(file_bytes)
        sig_b64 = base64.b64encode(sig_data).decode("ascii")

    if out_sig_path:
        if binary_format:
            with open(out_sig_path, "wb") as f:
                f.write(sig_data)
        else:
            with open(out_sig_path, "w", encoding="utf-8") as f:
                f.write(sig_b64)

    return sig_data if binary_format else sig_b64


def verify_message_signature(
    public_key: Optional[Union[GostPublicKey, str, bytes]],
    message: Union[str, bytes],
    signature: Union[str, bytes],
) -> bool:
    """
    Verifies message signature against GOST R 34.10-2012 and public key.
    signature can be CMS (PKCS#7) SignedData (DER or Base64) or raw (R || S) signature.
    """
    try:
        if isinstance(message, str):
            message = message.encode("utf-8")
        sig_bytes = load_signature_from_file_or_data(signature)
        if is_cms_signature(sig_bytes):
            return verify_cms_signed_data(sig_bytes, message, public_key)
        if public_key is not None:
            if isinstance(public_key, (str, bytes)):
                public_key = load_ecp_public_key_pem(public_key)
            return public_key.verify(sig_bytes, message)
        return False
    except Exception:
        return False


def verify_file_signature(
    public_key: Optional[Union[GostPublicKey, str, bytes]],
    file_path: str,
    signature: Union[str, bytes],
) -> bool:
    """
    Verifies a detached digital signature for a file.
    signature can be CMS (PKCS#7) SignedData (DER or Base64) or raw signature.
    """
    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        sig_bytes = load_signature_from_file_or_data(signature)
        if is_cms_signature(sig_bytes):
            return verify_cms_signed_data(sig_bytes, file_bytes, public_key)
        if public_key is not None:
            if isinstance(public_key, (str, bytes)):
                public_key = load_ecp_public_key_pem(public_key)
            return public_key.verify(sig_bytes, file_bytes)
        return False
    except Exception:
        return False


def issue_self_signed_certificate(
    username: str,
    user_id: int,
    private_key: GostPrivateKey,
    public_key: GostPublicKey,
    valid_days: int = 365,
) -> Dict[str, Union[str, int]]:
    """
    Issues a structured self-signed digital certificate for the user with GOST R 34.10-2012 ЭЦП.
    Includes both structured JSON metadata and standard RFC 9215 X.509 certificate PEM/DER.
    """
    now = datetime.datetime.utcnow()
    expires = now + datetime.timedelta(days=valid_days)
    serial = uuid.uuid4().hex.upper()

    x509_der = create_x509_certificate_der(
        common_name=username,
        private_key=private_key,
        public_key=public_key,
        valid_days=valid_days,
        organization="CryptoMail Secure Network",
    )
    x509_pem = export_x509_certificate_pem(x509_der)

    cert_data = {
        "version": "1.0",
        "serial_number": serial,
        "subject": {
            "common_name": username,
            "user_id": user_id,
            "organization": "CryptoMail Secure Network",
        },
        "issuer": {
            "common_name": f"{username} (Self-Signed ЭЦП ГОСТ)",
            "user_id": user_id,
        },
        "valid_from": now.isoformat() + "Z",
        "valid_to": expires.isoformat() + "Z",
        "signature_algorithm": f"GOST-R-34.10-2012-{private_key.curve.bit_len} + GOST-R-34.11-2012-Streebog-{private_key.curve.bit_len}",
        "public_key_pem": export_ecp_public_key_pem(public_key),
        "x509_pem": x509_pem,
        "x509_der_b64": base64.b64encode(x509_der).decode("ascii"),
    }

    cert_canonical = json.dumps(cert_data, sort_keys=True).encode("utf-8")
    cert_data["signature"] = sign_message(private_key, cert_canonical)

    return cert_data


def verify_certificate(cert_data: Dict[str, Union[str, int]]) -> bool:
    """Verifies self-signature on the certificate and checks validity period."""
    try:
        data_to_verify = dict(cert_data)
        sig_b64 = data_to_verify.pop("signature", None)
        if not sig_b64:
            return False
        pub_key = load_ecp_public_key_pem(cert_data["public_key_pem"])

        # Validate certificate validity period
        valid_to_str = cert_data.get("valid_to")
        if valid_to_str:
            try:
                valid_to = datetime.datetime.fromisoformat(str(valid_to_str).rstrip("Z"))
                if datetime.datetime.utcnow() > valid_to:
                    return False
            except Exception:
                pass

        cert_canonical = json.dumps(data_to_verify, sort_keys=True).encode("utf-8")
        return verify_message_signature(pub_key, cert_canonical, sig_b64)
    except Exception:
        return False
