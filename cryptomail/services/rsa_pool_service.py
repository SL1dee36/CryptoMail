# Description: Service for managing the pre-generated pool of 10 RSA-32K (32768-bit) keys.
# Author: Nazaryan Artem @Sl1dee36
# Date: 2026.

import json
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from crypto.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
)
from sqlalchemy.orm import Session

logger = logging.getLogger("cryptomail.rsa_pool")

POOL_DIR = os.path.join(ROOT_DIR, "data", "keys_32k")
JSON_PATH = os.path.join(POOL_DIR, "keys_32k.json")
TOTAL_POOL_KEYS = 10
KEY_SIZE_BITS = 32768

DEFAULT_USER_KEYS = {
    "admin": 1,
    "alice": 2,
    "bob": 3,
}

_POOL_CACHE: Optional[Dict] = None


def get_pool_dir() -> str:
    os.makedirs(POOL_DIR, exist_ok=True)
    return POOL_DIR


def get_pool_json_path() -> str:
    return JSON_PATH


def load_pool_catalog(force_reload: bool = False) -> Dict:
    """Loads and caches the 10-key RSA-32K catalog from JSON."""
    global _POOL_CACHE
    if _POOL_CACHE is not None and not force_reload:
        return _POOL_CACHE

    if not os.path.exists(JSON_PATH):
        raise FileNotFoundError(
            f"Каталог ключей RSA-32K не найден: {JSON_PATH}. "
            f"Запустите генерацию пула: python scripts/setup_32k_keys.py"
        )

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    _POOL_CACHE = data
    return data


def get_pool_key_by_id(key_id: int) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """Loads private and public keys for a specific key ID (1..10)."""
    if not (1 <= key_id <= TOTAL_POOL_KEYS):
        raise ValueError(f"Номер ключа должен быть от 1 до {TOTAL_POOL_KEYS}, получено: {key_id}")

    catalog = load_pool_catalog()
    for item in catalog.get("keys", []):
        if item.get("id") == key_id:
            priv = load_private_key_pem(item["private_key_pem"])
            pub = load_public_key_pem(item["public_key_pem"])
            return priv, pub

    # Fallback to direct PEM files if JSON is being reconstructed
    priv_path = os.path.join(POOL_DIR, f"key_{key_id:02d}_priv.pem")
    pub_path = os.path.join(POOL_DIR, f"key_{key_id:02d}_pub.pem")
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "r", encoding="utf-8") as f:
            priv = load_private_key_pem(f.read())
        with open(pub_path, "r", encoding="utf-8") as f:
            pub = load_public_key_pem(f.read())
        return priv, pub

    raise KeyError(f"Ключ #{key_id} не найден в пуле RSA-32K")


def get_key_for_username(username: str, db: Optional[Session] = None) -> Tuple[int, RSAPrivateKey, RSAPublicKey]:
    """
    Returns (key_id, priv, pub) assigned to a given user.
    - admin -> Key #1
    - alice -> Key #2
    - bob   -> Key #3
    - other -> Next available key from 4..10
    """
    uname_lower = username.strip().lower()
    if uname_lower in DEFAULT_USER_KEYS:
        key_id = DEFAULT_USER_KEYS[uname_lower]
        priv, pub = get_pool_key_by_id(key_id)
        return key_id, priv, pub

    # For other users, find available key from 4..10
    chosen_id = find_available_key_id(db=db)
    priv, pub = get_pool_key_by_id(chosen_id)
    return chosen_id, priv, pub


def find_available_key_id(db: Optional[Session] = None, exclude_user_id: Optional[int] = None) -> int:
    """Finds first available key ID among 4..10 that is not currently owned by any user."""
    used_ids = set(DEFAULT_USER_KEYS.values())  # 1, 2, 3 reserved

    if db is not None:
        try:
            from cryptomail.models.user import User
            catalog = load_pool_catalog()
            pub_to_id = {}
            for k in catalog.get("keys", []):
                pub_clean = "".join(k.get("public_key_pem", "").split())
                pub_to_id[pub_clean] = k["id"]

            users = db.query(User).all()
            for u in users:
                if exclude_user_id is not None and u.id == exclude_user_id:
                    continue
                if u.rsa_public_key:
                    u_pub_clean = "".join(u.rsa_public_key.split())
                    if u_pub_clean in pub_to_id:
                        used_ids.add(pub_to_id[u_pub_clean])
        except Exception as e:
            logger.warning("Ошибка проверки занятых ключей в БД: %s", e)

    # First attempt: find unused in 4..10
    for kid in range(4, TOTAL_POOL_KEYS + 1):
        if kid not in used_ids:
            return kid

    # Fallback if all 4..10 are taken: return 4
    return 4


def get_user_current_pool_key_id(user) -> Optional[int]:
    """Determines which pool key (1..10) the user currently holds."""
    if not user or not user.rsa_public_key:
        return None
    try:
        catalog = load_pool_catalog()
        target_clean = "".join(user.rsa_public_key.split())
        for k in catalog.get("keys", []):
            if "".join(k.get("public_key_pem", "").split()) == target_clean:
                return k["id"]
    except Exception:
        pass
    return None


def get_all_keys_status(db: Optional[Session] = None, current_user=None) -> List[Dict]:
    """
    Returns full information for all 10 keys:
    - id
    - key_size (32768)
    - default_owner ('admin', 'alice', 'bob' or None)
    - current_owner (username or None)
    - is_current_user (bool)
    - is_available (bool)
    """
    catalog = load_pool_catalog()
    status_list = []

    pub_to_owner = {}
    if db is not None:
        try:
            from cryptomail.models.user import User
            for u in db.query(User).all():
                if u.rsa_public_key:
                    pub_to_owner["".join(u.rsa_public_key.split())] = u.username
        except Exception as e:
            logger.warning("Ошибка сопоставления владельцев ключей: %s", e)

    for item in catalog.get("keys", []):
        kid = item["id"]
        default_owner = DEFAULT_USER_KEYS.get("admin" if kid == 1 else "alice" if kid == 2 else "bob" if kid == 3 else "")
        clean_pub = "".join(item.get("public_key_pem", "").split())
        owner = pub_to_owner.get(clean_pub, default_owner if kid in (1, 2, 3) else None)
        is_curr = False
        if current_user and current_user.rsa_public_key:
            if clean_pub == "".join(current_user.rsa_public_key.split()):
                is_curr = True

        status_list.append({
            "id": kid,
            "key_size": item.get("key_size", KEY_SIZE_BITS),
            "default_owner": default_owner,
            "current_owner": owner,
            "is_current_user": is_curr,
            "is_available": owner is None or is_curr,
            "public_key_pem": item.get("public_key_pem", ""),
            "n_hex": item.get("n_hex", "")[:32] + "...",
        })

    return status_list


def assign_pool_key_to_user(user, key_id: int, db: Session):
    """Assigns pre-generated RSA-32K key #key_id to the user and saves to DB."""
    priv, pub = get_pool_key_by_id(key_id)
    user.rsa_public_key = export_public_key_pem(pub)
    user.rsa_private_key = export_private_key_pem(priv)
    db.commit()
    return priv, pub

