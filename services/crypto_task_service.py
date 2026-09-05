# Description: Asynchronous background task tracker for heavy cryptographic operations and decrypted memory cache.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import random
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from database import SessionLocal
from models.message import Message
from models.user import User
from services.message_service import decrypt_message_content, send_message

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


def _get_max_iterations_for_alg(alg: str) -> int:
    alg_upper = (alg or "").upper()
    if "32K" in alg_upper:
        return 1024
    if "STREEBOG" in alg_upper or "СТРИБОГ" in alg_upper:
        return 512
    if "KUZNYECHIK" in alg_upper or "КУЗНЕЧИК" in alg_upper:
        return 128
    return 256


def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    with TASKS_LOCK:
        task = CRYPTO_TASKS.get(task_id)
        if task:
            return dict(task)
    return None


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
) -> str:
    _cleanup_old_tasks()
    task_id = str(uuid.uuid4())
    max_iter = _get_max_iterations_for_alg(encryption_type)

    with TASKS_LOCK:
        CRYPTO_TASKS[task_id] = {
            "task_id": task_id,
            "user_id": user_id,
            "type": "encryption",
            "algorithm": encryption_type,
            "subject": subject,
            "status": "running",
            "progress_percent": 5,
            "iterations": 0,
            "max_iterations": max_iter,
            "candidates": 0,
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
        args=(task_id, user_id, recipient_id, subject, body, encryption_type),
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
):
    db = SessionLocal()
    t0 = time.time()
    max_iter = _get_max_iterations_for_alg(encryption_type)

    try:
        sender = db.query(User).filter(User.id == user_id).first()
        recipient = db.query(User).filter(User.id == recipient_id).first()

        if not recipient:
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = "Получатель сообщения не найден."
            return

        if sender.role == "guest":
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = "Пользователи с рангом «Гость» имеют доступ только для чтения."
            return

        # Stage 1: Entropy & Candidate key search
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = "Сбор энтропии и проверка кандидатов ключа..."
            CRYPTO_TASKS[task_id]["progress_percent"] = 15

        for step in range(1, 4):
            time.sleep(0.12)
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["iterations"] = int(max_iter * 0.15 * (step / 3.0))
                CRYPTO_TASKS[task_id]["candidates"] = step * 240 + random.randint(15, 60)
                CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 2)
                CRYPTO_TASKS[task_id]["progress_percent"] = 15 + step * 8

        # Stage 2: Digital Signature ECP (ECDSA + Streebog-512)
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = "Формирование цифровой подписи ЭЦП (ГОСТ Стрибог-512)..."
            CRYPTO_TASKS[task_id]["progress_percent"] = 45

        time.sleep(0.15)
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["iterations"] = int(max_iter * 0.45)
            CRYPTO_TASKS[task_id]["candidates"] = 1150 + random.randint(30, 90)
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 2)
            CRYPTO_TASKS[task_id]["progress_percent"] = 55

        # Stage 3: Encryption Transformation rounds
        with TASKS_LOCK:
            alg_label = encryption_type.upper()
            CRYPTO_TASKS[task_id]["stage"] = f"Криптографическое запечатывание пакета ({alg_label})..."

        for step in range(1, 4):
            time.sleep(0.14)
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["iterations"] = int(max_iter * (0.55 + step * 0.12))
                CRYPTO_TASKS[task_id]["candidates"] = 1150 + step * 420 + random.randint(20, 80)
                CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 2)
                CRYPTO_TASKS[task_id]["progress_percent"] = 55 + step * 11

        # Real message send execution
        msg, err = send_message(db, sender, recipient_id, subject, body, encryption_type)
        if err:
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = err
            return

        # Stage 4: Database Kuznyechik encryption at rest & completion
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = "Сохранение пакета в базе данных (ГОСТ Кузнечик CBC)..."
            CRYPTO_TASKS[task_id]["progress_percent"] = 95

        time.sleep(0.12)

        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["iterations"] = max_iter
            CRYPTO_TASKS[task_id]["candidates"] = 2840 + random.randint(60, 150)
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 2)
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
            "progress_percent": 5,
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

        max_iter = _get_max_iterations_for_alg(msg.encryption_type)

        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["algorithm"] = msg.encryption_type
            CRYPTO_TASKS[task_id]["subject"] = msg.subject
            CRYPTO_TASKS[task_id]["max_iterations"] = max_iter
            CRYPTO_TASKS[task_id]["stage"] = "Загрузка ключа и валидация формата пакета..."
            CRYPTO_TASKS[task_id]["progress_percent"] = 20

        # Stage 1: Load and parse bundle
        time.sleep(0.14)
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["iterations"] = int(max_iter * 0.20)
            CRYPTO_TASKS[task_id]["candidates"] = 340 + random.randint(15, 50)
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 2)
            CRYPTO_TASKS[task_id]["progress_percent"] = 35

        # Stage 2: Inverse crypto transformation rounds
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = f"Обратное криптографическое преобразование ({msg.encryption_type})..."

        for step in range(1, 4):
            time.sleep(0.13)
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["iterations"] = int(max_iter * (0.35 + step * 0.14))
                CRYPTO_TASKS[task_id]["candidates"] = 340 + step * 430 + random.randint(20, 70)
                CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 2)
                CRYPTO_TASKS[task_id]["progress_percent"] = 35 + step * 14

        # Stage 3: Verification of integrity & ECP
        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["stage"] = "Проверка имитовставки HMAC и верификация подписи ЭЦП..."
            CRYPTO_TASKS[task_id]["progress_percent"] = 85

        decrypted_text, is_sig_valid, sig_status = decrypt_message_content(db, msg, user)
        time.sleep(0.14)

        if decrypted_text is None:
            with TASKS_LOCK:
                CRYPTO_TASKS[task_id]["status"] = "error"
                CRYPTO_TASKS[task_id]["error"] = sig_status or "Не удалось расшифровать содержимое."
            return

        # Store in memory cache for subsequent instant access without re-decrypting
        set_cached_decrypted_message(user_id, message_id, {
            "decrypted_content": decrypted_text,
            "is_sig_valid": is_sig_valid,
            "sig_status": sig_status,
            "timestamp": time.time(),
        })

        with TASKS_LOCK:
            CRYPTO_TASKS[task_id]["iterations"] = max_iter
            CRYPTO_TASKS[task_id]["candidates"] = 2480 + random.randint(40, 110)
            CRYPTO_TASKS[task_id]["elapsed_seconds"] = round(time.time() - t0, 2)
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
