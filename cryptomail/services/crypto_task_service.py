# Description: Asynchronous background task tracker for heavy cryptographic operations and decrypted memory cache.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from cryptomail.database import SessionLocal
from cryptomail.models.message import Message
from cryptomail.models.user import User
from crypto.rsa import load_public_key_pem
from cryptomail.services.message_service import decrypt_message_content, send_message

# In-memory store for crypto operations: task_id -> task_dict
CRYPTO_TASKS: Dict[str, Dict[str, Any]] = {}
TASKS_LOCK = threading.Lock()

# In-memory memory cache for decrypted messages: (user_id, message_id) -> dict
DECRYPTED_MEMORY_CACHE: Dict[Tuple[int, int], Dict[str, Any]] = {}
CACHE_LOCK = threading.Lock()


def get_cached_decrypted_message(user_id: int, message_id: int) -> Optional[Dict[str, Any]]:
    with CACHE_LOCK:
        cached = DECRYPTED_MEMORY_CACHE.get((user_id, message_id))
        if cached:
            return dict(cached)
    return None


def set_cached_decrypted_message(user_id: int, message_id: int, data: Dict[str, Any]):
    with CACHE_LOCK:
        DECRYPTED_MEMORY_CACHE[(user_id, message_id)] = dict(data)


def clear_cached_decrypted_message(user_id: int, message_id: int):
    with CACHE_LOCK:
        DECRYPTED_MEMORY_CACHE.pop((user_id, message_id), None)


def calculate_crypto_work_metrics(data_bytes: bytes, alg: str, rsa_bits: int = 2048) -> Tuple[int, int]:
    """
    Calculates the exact planned cryptographic rounds and work units (candidates/bytes):
    - Kuznyechik cipher: 32 key schedule rounds + 10 rounds per 16-byte block.
    - Streebog-512 digest: 12 transformation rounds in compression function g_N per 64-byte block.
    - PBKDF2: 1000 HMAC rounds.
    - RSA: OAEP padding and modular exponentiation complexity proportional to key bit length.
    - ECP digital signature: Streebog hashing rounds + SECP384R1 scalar multiplication.
    - DB encryption at rest: Kuznyechik-CBC rounds over database records.
    Returns (total_iterations, total_candidates_or_bytes).
    """
    length = len(data_bytes)
    alg_upper = (alg or "").upper()

    kuz_blocks = max(1, (length + 15) // 16)
    kuz_rounds = 32 + 10 * kuz_blocks

    stree_blocks = max(1, (length + 64) // 64)
    stree_rounds = 12 * (stree_blocks + 2)

    ecp_rounds = stree_rounds + 384

    if "RSA" in alg_upper:
        bits = 32768 if "32K" in alg_upper else rsa_bits
        rsa_rounds = bits // 8
        total_iter = rsa_rounds + kuz_rounds + ecp_rounds + 64
        total_candidates = length + (bits // 8) + 96 + (kuz_blocks * 16)
    elif "STREEBOG" in alg_upper or "СТРИБОГ" in alg_upper:
        total_iter = 1000 + kuz_rounds + (2 * stree_rounds) + ecp_rounds + 64
        total_candidates = length + 64 + 48 + (kuz_blocks * 16)
    elif "KUZNYECHIK" in alg_upper or "КУЗНЕЧИК" in alg_upper:
        total_iter = 1000 + kuz_rounds + ecp_rounds + 64
        total_candidates = length + 32 + 48 + (kuz_blocks * 16)
    else:
        total_iter = kuz_rounds + ecp_rounds + 256
        total_candidates = length + 128

    return total_iter, total_candidates


def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    with TASKS_LOCK:
        task = CRYPTO_TASKS.get(task_id)
        if task:
            return dict(task)
    return None


get_task_status = get_task



def get_user_tasks(user_id: int) -> List[Dict[str, Any]]:
    with TASKS_LOCK:
        return [
            dict(t) for t in CRYPTO_TASKS.values()
            if t.get("user_id") == user_id
        ]


def _cleanup_old_tasks():
    now = time.time()
    with TASKS_LOCK:
        expired = [
            tid for tid, t in CRYPTO_TASKS.items()
            if now - t.get("created_at", now) > 3600  # 1 hour retention
        ]
        for tid in expired:
            del CRYPTO_TASKS[tid]


def start_encryption_task(
    user_id: int,
    recipient_id: int,
    subject: str,
    body: str,
    encryption_type: str,
    kuz_passphrase: Optional[str] = None,
) -> str:
    _cleanup_old_tasks()
    task_id = str(uuid.uuid4())
    body_bytes = body.encode("utf-8")
    max_iter, candidates_est = calculate_crypto_work_metrics(body_bytes, encryption_type)

    with TASKS_LOCK:
        CRYPTO_TASKS[task_id] = {
            "task_id": task_id,
            "user_id": user_id,
            "type": "encryption",
            "algorithm": encryption_type,
            "subject": subject,
            "status": "running",
            "progress_percent": 10,
            "iterations": 0,
            "max_iterations": max_iter,
            "candidates": candidates_est,
            "start_time": time.time(),
            "created_at": time.time(),
            "elapsed_seconds": 0.0,
            "stage": "Инициализация параметров шифрования...",
            "message_id": None,
            "error": None,
            "result": None,
        }

    thread = threading.Thread(
        target=_run_encryption_worker,
        args=(task_id, user_id, recipient_id, subject, body, encryption_type, kuz_passphrase),
        daemon=True,
    )
    thread.start()
    return task_id


def _run_encryption_worker(
    task_id: str,
    user_id: int,
    recipient_id: int,
    subject: str,
    body: str,
    encryption_type: str,
    kuz_passphrase: Optional[str] = None,
):
    db = SessionLocal()
    t0 = time.time()
    body_bytes = body.encode("utf-8")

    try:
        sender = db.query(User).filter(User.id == user_id).first()
        recipient = db.query(User).filter(User.id == recipient_id).first()

        if not recipient:
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = "Получатель сообщения не найден."
            return

        rsa_bits = 2048
        if recipient.rsa_public_key:
            try:
                rsa_bits = load_public_key_pem(recipient.rsa_public_key).key_size
            except Exception:
                pass

        max_iter, total_candidates = calculate_crypto_work_metrics(body_bytes, encryption_type, rsa_bits)

        # Stage 1: Key material generation and entropy collection
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["max_iterations"] = max_iter
            CRYPTO_TASKS[task_id]["stage"] = "Сбор энтропии и инициализация криптографических параметров..."
            CRYPTO_TASKS[task_id]["iterations"] = 32
            CRYPTO_TASKS[task_id]["candidates"] = len(body_bytes) + 48
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 3)
            CRYPTO_TASKS[task_id]["progress_percent"] = 30

        # Stage 2: Digital Signature ECP (Streebog-512 + SECP384R1)
        stree_blocks = max(1, (len(body_bytes) + 64) // 64)
        ecp_rounds = 12 * (stree_blocks + 2) + 384
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = "Формирование цифровой подписи ЭЦП (ГОСТ Стрибог-512 + SECP384R1)..."
            CRYPTO_TASKS[task_id]["iterations"] = 32 + ecp_rounds
            CRYPTO_TASKS[task_id]["candidates"] = len(body_bytes) + 96
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 3)
            CRYPTO_TASKS[task_id]["progress_percent"] = 55

        # Stage 3: Real cryptographic encryption execution
        alg_label = encryption_type.upper()
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = f"Криптографическое запечатывание пакета ({alg_label})..."
            CRYPTO_TASKS[task_id]["progress_percent"] = 80

        # Real message send execution (computes real signatures, hybrid enc, db enc at rest)
        msg, err = send_message(db, sender, recipient_id, subject, body, encryption_type, kuz_passphrase=kuz_passphrase)
        if err:
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = err
            return

        # Stage 4: Completion and Database encryption at rest verification
        ct_len = len(msg.ciphertext or "")
        bundle_len = len(msg.key_bundle or "")
        final_candidates = len(body_bytes) + ct_len + bundle_len + 128

        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["iterations"] = max_iter
            CRYPTO_TASKS[task_id]["candidates"] = final_candidates
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 3)
            CRYPTO_TASKS[task_id]["progress_percent"] = 100
            CRYPTO_TASKS[task_id]["stage"] = "Шифрование успешно завершено"
            CRYPTO_TASKS[task_id]["message_id"] = msg.id
            CRYPTO_TASKS[task_id]["status"] = "completed"

    except Exception as ex:
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["status"] = "error"
            CRYPTO_TASKS[task_id]["error"] = f"Непредвиденная ошибка: {ex}"
    finally:
        db.close()


def start_decryption_task(user_id: int, message_id: int) -> str:
    _cleanup_old_tasks()
    task_id = str(uuid.uuid4())

    with TASKS_LOCK:
        CRYPTO_TASKS[task_id] = {
            "task_id": task_id,
            "user_id": user_id,
            "type": "decryption",
            "algorithm": "Определение...",
            "subject": f"Сообщение #{message_id}",
            "status": "running",
            "progress_percent": 10,
            "iterations": 0,
            "max_iterations": 256,
            "candidates": 0,
            "start_time": time.time(),
            "created_at": time.time(),
            "elapsed_seconds": 0.0,
            "stage": "Чтение зашифрованного пакета из базы данных...",
            "message_id": message_id,
            "error": None,
            "result": None,
        }

    thread = threading.Thread(
        target=_run_decryption_worker,
        args=(task_id, user_id, message_id),
        daemon=True,
    )
    thread.start()
    return task_id


def _run_decryption_worker(task_id: str, user_id: int, message_id: int):
    db = SessionLocal()
    t0 = time.time()

    try:
        user = db.query(User).filter(User.id == user_id).first()
        msg = db.query(Message).filter(Message.id == message_id).first()

        if not msg:
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = "Сообщение не найдено."
            return

        if user.role != "admin" and user.id not in (msg.sender_id, msg.recipient_id):
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = "Доступ к расшифрованию запрещен."
            return

        ct_bytes = (msg.ciphertext or "").encode("utf-8")
        max_iter, total_candidates = calculate_crypto_work_metrics(ct_bytes, msg.encryption_type)

        # Stage 1: Load and parse bundle from DB
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["algorithm"] = msg.encryption_type
            CRYPTO_TASKS[task_id]["subject"] = msg.subject
            CRYPTO_TASKS[task_id]["max_iterations"] = max_iter
            CRYPTO_TASKS[task_id]["stage"] = "Загрузка ключа и валидация формата пакета..."
            CRYPTO_TASKS[task_id]["iterations"] = 64
            CRYPTO_TASKS[task_id]["candidates"] = len(msg.ciphertext or "") + len(msg.key_bundle or "")
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 3)
            CRYPTO_TASKS[task_id]["progress_percent"] = 35

        # Stage 2: Inverse crypto transformation rounds
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = f"Обратное криптографическое преобразование ({msg.encryption_type})..."
            CRYPTO_TASKS[task_id]["progress_percent"] = 70

        # Real message decryption & signature verification
        decrypted_text, is_sig_valid, sig_status, *_ = decrypt_message_content(db, msg, user)

        if decrypted_text is None:
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = sig_status or "Не удалось расшифровать содержимое."
            return

        # Stage 3: Verification of integrity & ECP
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = "Проверка имитовставки HMAC и верификация подписи ЭЦП..."
            CRYPTO_TASKS[task_id]["progress_percent"] = 90

        # Store in memory cache for subsequent instant access without re-decrypting
        set_cached_decrypted_message(user_id, message_id, {
            "decrypted_content": decrypted_text,
            "is_sig_valid": is_sig_valid,
            "sig_status": sig_status,
            "timestamp": time.time(),
        })

        dec_bytes_len = len(decrypted_text.encode("utf-8"))
        final_candidates = len(msg.ciphertext or "") + dec_bytes_len + 96

        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["iterations"] = max_iter
            CRYPTO_TASKS[task_id]["candidates"] = final_candidates
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 3)
            CRYPTO_TASKS[task_id]["progress_percent"] = 100
            CRYPTO_TASKS[task_id]["stage"] = "Дешифрование успешно завершено"
            CRYPTO_TASKS[task_id]["status"] = "completed"
            CRYPTO_TASKS[task_id]["result"] = {
                "decrypted_content": decrypted_text,
                "is_sig_valid": is_sig_valid,
                "sig_status": sig_status,
            }

    except Exception as ex:
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["status"] = "error"
            CRYPTO_TASKS[task_id]["error"] = f"Непредвиденная ошибка при дешифровании: {ex}"
    finally:
        db.close()
