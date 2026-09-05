# Description: Digital signature module on SECP384R1 curve with Streebog-512 digest and self-signed certificates.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import datetime
import json
import uuid
from typing import Dict, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from crypto.streebog import streebog512


def generate_ecp_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generates an elliptic curve key pair for Digital Signature (SECP384R1 / SECP256R1)."""
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return private_key, private_key.public_key()


def export_ecp_private_key_pem(private_key: ec.EllipticCurvePrivateKey) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


def export_ecp_public_key_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def load_ecp_private_key_pem(pem_data: Union[str, bytes]) -> ec.EllipticCurvePrivateKey:
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())


def load_ecp_public_key_pem(pem_data: Union[str, bytes]) -> ec.EllipticCurvePublicKey:
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def issue_self_signed_certificate(
    username: str,
    user_id: int,
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
    valid_days: int = 365,
) -> Dict[str, Union[str, int]]:
    """
    Issues a structured self-signed digital certificate for the user.
    """
    now = datetime.datetime.utcnow()
    expires = now + datetime.timedelta(days=valid_days)
    serial = uuid.uuid4().hex.upper()

    cert_data = {
        "version": "1.0",
        "serial_number": serial,
        "subject": {
            "common_name": username,
            "user_id": user_id,
            "organization": "CryptoMail Secure Network",
        },
        "issuer": {
            "common_name": f"{username} (Self-Signed ЭЦП)",
            "user_id": user_id,
        },
        "valid_from": now.isoformat() + "Z",
        "valid_to": expires.isoformat() + "Z",
        "signature_algorithm": "GOST-R-34.11-2012-Streebog-512 + ECDSA",
        "public_key_pem": export_ecp_public_key_pem(public_key),
    }

    # Digest certificate payload with Streebog-512
    cert_canonical = json.dumps(cert_data, sort_keys=True).encode("utf-8")
    digest = streebog512(cert_canonical)

    # Sign digest with private key
    sig = private_key.sign(digest, ec.ECDSA(hashes.SHA384()))
    cert_data["signature"] = base64.b64encode(sig).decode("ascii")

    return cert_data


def verify_certificate(cert_data: Dict[str, Union[str, int]]) -> bool:
    """Verifies self-signature on the certificate."""
    try:
        data_to_verify = dict(cert_data)
        sig_b64 = data_to_verify.pop("signature", None)
        if not sig_b64:
            return False
        sig = base64.b64decode(sig_b64)
        pub_key = load_ecp_public_key_pem(cert_data["public_key_pem"])

        cert_canonical = json.dumps(data_to_verify, sort_keys=True).encode("utf-8")
        digest = streebog512(cert_canonical)
        pub_key.verify(sig, digest, ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:
        return False


def sign_message(private_key: ec.EllipticCurvePrivateKey, message: Union[str, bytes]) -> str:
    """
    Signs message using Streebog-512 digest and ECP private key.
    Returns base64 encoded signature.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    digest = streebog512(message)
    sig = private_key.sign(digest, ec.ECDSA(hashes.SHA384()))
    return base64.b64encode(sig).decode("ascii")


def verify_message_signature(
    public_key: ec.EllipticCurvePublicKey,
    message: Union[str, bytes],
    signature_b64: str,
) -> bool:
    """
    Verifies message signature against Streebog-512 digest and public key.
    """
    try:
        if isinstance(message, str):
            message = message.encode("utf-8")
        digest = streebog512(message)
        sig = base64.b64decode(signature_b64)
        public_key.verify(sig, digest, ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:
        return False
