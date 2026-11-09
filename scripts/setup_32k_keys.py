# Description: Generator and pool manager for 10 distinct 32768-bit RSA keys.
# Author: Nazaryan Artem @Sl1dee36
# Date: 2026.

import concurrent.futures
import json
import os
import subprocess
import sys
import time

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from crypto.rsa import (
    load_private_key_pem,
    export_private_key_pem,
    export_public_key_pem,
    RSAPublicKey,
)

POOL_DIR = os.path.join(ROOT_DIR, "data", "keys_32k")
JSON_PATH = os.path.join(POOL_DIR, "keys_32k.json")
TOTAL_KEYS = 10
KEY_BITS = 32768

ASSIGNMENTS = {
    1: "admin",
    2: "alice",
    3: "bob",
}


def generate_single_key_openssl(key_idx: int, out_pem_path: str):
    """Generate 32768-bit RSA private key via OpenSSL CLI."""
    t0 = time.time()
    cmd = ["openssl", "genrsa", "-out", out_pem_path, str(KEY_BITS)]
    print(f"[*] [Key #{key_idx:02d}] Запуск генерации RSA-32K (32768 бит) через OpenSSL...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"OpenSSL failed for key #{key_idx}: {res.stderr}")
    elapsed = time.time() - t0
    print(f"[+] [Key #{key_idx:02d}] Успешно сгенерирован за {elapsed:.1f} сек")
    return out_pem_path, elapsed


def build_key_entry(key_idx: int, priv_pem_path: str, pub_pem_path: str):
    """Parses generated PEM and constructs full metadata entry."""
    with open(priv_pem_path, "r", encoding="utf-8") as f:
        priv_pem = f.read()

    priv = load_private_key_pem(priv_pem)
    pub = RSAPublicKey(n=priv.n, e=priv.e)
    pub_pem = export_public_key_pem(pub)

    with open(pub_pem_path, "w", encoding="utf-8") as f:
        f.write(pub_pem)

    assigned = ASSIGNMENTS.get(key_idx)
    status = "in_use" if assigned else "available"

    return {
        "id": key_idx,
        "key_size": priv.key_size,
        "assigned_to": assigned,
        "status": status,
        "priv_path": os.path.relpath(priv_pem_path, ROOT_DIR).replace("\\", "/"),
        "pub_path": os.path.relpath(pub_pem_path, ROOT_DIR).replace("\\", "/"),
        "public_key_pem": pub_pem,
        "private_key_pem": priv_pem,
        "n_hex": hex(priv.n),
        "e": priv.e,
        "p_hex": hex(priv.p) if priv.p else None,
        "q_hex": hex(priv.q) if priv.q else None,
        "dmp1_hex": hex(priv.dmp1) if priv.dmp1 else None,
        "dmq1_hex": hex(priv.dmq1) if priv.dmq1 else None,
        "iqmp_hex": hex(priv.iqmp) if priv.iqmp else None,
    }


def main():
    os.makedirs(POOL_DIR, exist_ok=True)
    print(f"[*] Целевая директория пула: {POOL_DIR}")

    # Check existing keys or keys in progress
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=TOTAL_KEYS) as executor:
        future_map = {}
        for i in range(1, TOTAL_KEYS + 1):
            priv_pem_path = os.path.join(POOL_DIR, f"key_{i:02d}_priv.pem")
            if os.path.exists(priv_pem_path) and os.path.getsize(priv_pem_path) > 100:
                print(f"[i] Ключ #{i:02d} уже существует ({priv_pem_path}), генерация не требуется.")
                continue

            # If key 1: check if test_32k.pem is ready or being generated
            if i == 1:
                test_file = os.path.join(ROOT_DIR, "test_32k.pem")
                def wait_or_gen_key1():
                    t_w0 = time.time()
                    print(f"[*] [Key #01] Ожидание завершения текущей генерации test_32k.pem...")
                    while time.time() - t_w0 < 300:
                        if os.path.exists(test_file) and os.path.getsize(test_file) > 100:
                            os.replace(test_file, priv_pem_path)
                            print(f"[+] [Key #01] Успешно получен из test_32k.pem!")
                            return priv_pem_path, time.time() - t_w0
                        # Check if process is still alive
                        check_proc = subprocess.run(["tasklist", "/FI", "IMAGENAME eq openssl.exe"], capture_output=True, text=True)
                        if "openssl.exe" not in check_proc.stdout:
                            time.sleep(1)
                            if os.path.exists(test_file) and os.path.getsize(test_file) > 100:
                                os.replace(test_file, priv_pem_path)
                                return priv_pem_path, time.time() - t_w0
                            break
                        time.sleep(2)
                    # If not obtained from test_32k.pem, generate normally
                    return generate_single_key_openssl(1, priv_pem_path)

                fut = executor.submit(wait_or_gen_key1)
                future_map[fut] = (1, priv_pem_path)
                continue

            fut = executor.submit(generate_single_key_openssl, i, priv_pem_path)
            future_map[fut] = (i, priv_pem_path)

        for fut in concurrent.futures.as_completed(future_map):
            idx, path = future_map[fut]
            try:
                fut.result()
            except Exception as e:
                print(f"[-] Ошибка при генерации ключа #{idx}: {e}")

    # Now verify all 10 keys and build JSON
    print("[*] Сборка и валидация 10 ключевых пар...")
    keys_data = []
    for i in range(1, TOTAL_KEYS + 1):
        priv_pem_path = os.path.join(POOL_DIR, f"key_{i:02d}_priv.pem")
        pub_pem_path = os.path.join(POOL_DIR, f"key_{i:02d}_pub.pem")
        if not os.path.exists(priv_pem_path) or os.path.getsize(priv_pem_path) < 100:
            print(f"[-] ОШИБКА: Ключ #{i:02d} отсутствует!")
            sys.exit(1)

        entry = build_key_entry(i, priv_pem_path, pub_pem_path)
        keys_data.append(entry)
        print(f"    [+] Ключ #{i:02d}: размер {entry['key_size']} бит | Назначен: {entry['assigned_to'] or 'Свободен'}")

    catalog = {
        "pool_size": TOTAL_KEYS,
        "key_size": KEY_BITS,
        "description": "Pre-generated distinct RSA-32K (32768-bit) key pairs for CryptoMail",
        "keys": keys_data,
    }

    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)

    print(f"[+] Все {TOTAL_KEYS} ключей успешно сохранены в:")
    print(f"    Каталог: {POOL_DIR}")
    print(f"    JSON файл: {JSON_PATH}")


if __name__ == "__main__":
    main()
