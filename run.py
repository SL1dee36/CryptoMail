# Description: All-in-one launcher for CryptoMail: initializes crypto core, database,
#              RSA-32K key pool, embedded SMTP server, FastAPI web server, and opens the browser.
# Author: Nazaryan Artem @Sl1dee36
# Date: 2026.

import os
import socket
import sys
import threading
import time
import webbrowser

# 1. Critical environment setting for 32768-bit RSA arithmetic
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

HOST = "127.0.0.1"
PORT = 8000
BASE_URL = f"http://{HOST}:{PORT}"


def wait_for_server_and_open_browser(url: str, timeout: float = 15.0):
    """Pings the web server until it starts responding, then opens the browser."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.5):
                # Server is accepting connections; give it a tiny moment to finish setup
                time.sleep(0.3)
                print(f"\n[+] Сервер готов к работе! Открываю браузер: {url}")
                webbrowser.open_new(url)
                return
        except (OSError, ConnectionRefusedError):
            time.sleep(0.2)
    # Fallback in case of timeout
    print(f"\n[!] Время ожидания ответа сервера истекло, открываю браузер напрямую: {url}")
    webbrowser.open_new(url)


def print_banner():
    """Prints system startup banner with credentials and crypto core status."""
    banner = f"""
================================================================================
                    CryptoMail Secure Mailing Platform
         ГОСТ Р 34.12-2015 (Кузнечик)   |   ГОСТ Р 34.11-2012 (Стрибог)
         ГОСТ Р 34.10-2012 (ЭЦП 512)    |   RSA-32K (Фиксированный пул)
================================================================================
[*] Веб-интерфейс:     {BASE_URL}
[*] Локальный SMTP:    127.0.0.1:1025 (Перехват 3FA кодов / MailTrap)
[*] База данных:       data/cryptomail.db (Kuznyechik-256 at-rest encryption)
[*] Пул ключей RSA:    10 независимых пар по 32768 бит (data/keys_32k)
--------------------------------------------------------------------------------
[i] Учетные записи по умолчанию:
    • admin (Администратор) — admin@cryptomail.local / AdminPassword123! [RSA-32K #1]
    • alice (Пользователь)  — alice@cryptomail.local / AlicePassword123! [RSA-32K #2]
    • bob   (Пользователь)  — bob@cryptomail.local   / BobPassword123!   [RSA-32K #3]
    • guest (Гостевой вход) — 1 клик на странице входа (без пароля)
--------------------------------------------------------------------------------
[*] Запуск всех модулей и ожидание готовности сервера...
"""
    print(banner)


def verify_and_prep_environment():
    """Pre-flight check for database, default users, and the 10-key RSA-32K pool."""
    from cryptomail.app import init_db
    from cryptomail.database import SessionLocal
    from cryptomail.services.auth_service import seed_default_users

    # 1. Initialize DB schema
    init_db()

    # 2. Check RSA-32K key pool
    from cryptomail.services.rsa_pool_service import JSON_PATH, load_pool_catalog
    if not os.path.exists(JSON_PATH):
        print("[!] Каталог ключей RSA-32K не найден, запускаю сборку пула...")
        import subprocess
        subprocess.run([sys.executable, os.path.join(ROOT_DIR, "scripts", "setup_32k_keys.py")], check=True)

    try:
        catalog = load_pool_catalog()
        print(f"[+] Пул RSA-32K загружен: {catalog.get('pool_size', 0)} пар ключей по 32768 бит.")
    except Exception as e:
        print(f"[!] Предупреждение при чтении пула ключей: {e}")

    # 3. Seed / sync default users with keys 1, 2, 3
    db = SessionLocal()
    try:
        seed_default_users(db)
    finally:
        db.close()


def main():
    print_banner()

    # Pre-flight check
    try:
        verify_and_prep_environment()
    except Exception as e:
        print(f"[-] Ошибка предварительной инициализации: {e}")

    # Start browser opener in background thread
    opener_thread = threading.Thread(
        target=wait_for_server_and_open_browser,
        args=(BASE_URL,),
        daemon=True,
    )
    opener_thread.start()

    # Launch FastAPI + Uvicorn server (which in turn launches SMTP and background services via lifespan)
    import uvicorn
    from cryptomail.app import app

    try:
        uvicorn.run(
            app,
            host=HOST,
            port=PORT,
            log_level="info",
            access_log=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Завершение работы CryptoMail... Все сервисы остановлены.")


if __name__ == "__main__":
    main()

