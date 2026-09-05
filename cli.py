# Description: Command-Line Interface (CLI) and modular API for cryptographic operations (RSA-32K, Kuznyechik, Streebog, ECP).
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import argparse
import base64
import json
import os
import sys
import time
from typing import Dict, Optional, Tuple, Union

# Increase max integer string conversion digits for 32768-bit keys
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from crypto.ecp import (
    export_ecp_private_key_pem,
    export_ecp_public_key_pem,
    generate_ecp_keypair,
    issue_self_signed_certificate,
    load_ecp_private_key_pem,
    load_ecp_public_key_pem,
    sign_message,
    verify_certificate,
    verify_message_signature,
)
from crypto.kuznyechik import Kuznyechik
from crypto.rsa_parallel import find_prime_parallel, generate_rsa_keypair_parallel
from crypto.rsa32k import (
    build_rsa_keypair_from_primes,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    load_private_key_pem,
    load_public_key_pem,
    rsa_decrypt_hybrid,
    rsa_encrypt_hybrid,
)
from crypto.streebog import hmac_streebog512, streebog256, streebog512


class PregenResult(dict):
    """Container for pregenerated RSA primes with dict and tuple unpacking support."""
    def __iter__(self):
        yield self["p"]
        yield self["q"]
        yield self["json_path"]


def generate_and_save_pq(
    bits: int = 32768,
    out_dir: str = "data/rsa_pregen",
    threads: int = None,
    verbose: bool = True,
) -> PregenResult:
    """
    Генерирует два простых числа p и q (по bits // 2 бит) и сохраняет их в указанную директорию (по умолчанию data/rsa_pregen).
    """
    if threads is None or threads < 1:
        threads = max(1, os.cpu_count() or 4)

    prime_bits = bits // 2
    t_start = time.time()

    def format_time(seconds: float) -> str:
        m = int(seconds // 60)
        s = int(seconds % 60)
        ms = int((seconds * 10) % 10)
        return f"{m:02d}:{s:02d}.{ms}"

    if verbose:
        print(f"[*] Генерация параметров p и q для RSA-{bits} (многопоток: {threads} ядер CPU)")
        print(f"[*] Длина каждого простого числа: {prime_bits} бит")

    # Step 1: Find p
    def progress_p(cands: int, el: float):
        if verbose:
            speed = cands / el if el > 0 else 0
            sys.stdout.write(
                f"\r[*] [{format_time(el)}] Поиск p ({prime_bits} бит) | Ядер: {threads} | Проверено: {cands:,} канд ({speed:.0f} канд/с)   "
            )
            sys.stdout.flush()

    p, cands_p, el_p = find_prime_parallel(prime_bits, num_workers=threads, progress_callback=progress_p)
    if verbose:
        sys.stdout.write(f"\r[+] [{format_time(el_p)}] Простое число p найдено за {el_p:.2f} сек! (Кандидатов: {cands_p:,})\n")
        sys.stdout.flush()

    # Step 2: Find q (must be distinct from p)
    def progress_q(cands: int, el: float):
        if verbose:
            el_tot = time.time() - t_start
            speed = (cands_p + cands) / el_tot if el_tot > 0 else 0
            sys.stdout.write(
                f"\r[*] [{format_time(el_tot)}] Поиск q ({prime_bits} бит) | Ядер: {threads} | Проверено: {(cands_p + cands):,} канд ({speed:.0f} канд/с)   "
            )
            sys.stdout.flush()

    q = p
    cands_q_total = 0
    while q == p or (p * q).bit_length() != bits:
        q, cands_q, el_q = find_prime_parallel(prime_bits, num_workers=threads, progress_callback=progress_q)
        cands_q_total += cands_q

    total_time = time.time() - t_start
    if verbose:
        sys.stdout.write(f"\r[+] [{format_time(total_time)}] Простое число q найдено за {el_q:.2f} сек! (Кандидатов: {cands_q_total:,})\n")
        sys.stdout.flush()

    if p < q:
        p, q = q, p

    if not os.path.isabs(out_dir):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        target_dir = os.path.join(base_dir, out_dir)
    else:
        target_dir = out_dir

    os.makedirs(target_dir, exist_ok=True)

    json_file = os.path.join(target_dir, "primes.json")
    json_named_file = os.path.join(
        target_dir,
        f"rsa{bits // 1024}k_primes.json" if bits % 1024 == 0 else f"rsa_{bits}_primes.json"
    )
    p_file = os.path.join(target_dir, "p.txt")
    q_file = os.path.join(target_dir, "q.txt")

    data = {
        "key_size": bits,
        "prime_bits": prime_bits,
        "p": str(p),
        "q": str(q),
        "p_hex": hex(p),
        "q_hex": hex(q),
        "created_at": time.time(),
        "elapsed_seconds": total_time,
        "candidates_tested": cands_p + cands_q_total,
    }

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    with open(json_named_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    with open(p_file, "w", encoding="utf-8") as f:
        f.write(str(p) + "\n")

    with open(q_file, "w", encoding="utf-8") as f:
        f.write(str(q) + "\n")

    if verbose:
        print(f"[+] Параметры p и q успешно сохранены в: {target_dir}")
        print(f"    - Основной JSON: {json_file}")
        print(f"    - Именованный JSON: {json_named_file}")
        print(f"    - Текстовые файлы: p.txt, q.txt")
        print(f"[+] Полное время генерации: {total_time:.2f} сек")

    return PregenResult({
        "p": p,
        "q": q,
        "key_size": bits,
        "prime_bits": prime_bits,
        "dir": target_dir,
        "json_path": json_file,
        "elapsed_seconds": total_time,
    })


# Алиасы для прямого импорта и совместимости
pregenerate_pq = generate_and_save_pq
generate_rsa_pregen = generate_and_save_pq


def load_pregen_primes(source: str = "data/rsa_pregen") -> Tuple[int, int]:
    """
    Загружает предварительно сгенерированные простые числа p и q из файла или директории.
    """
    path = source
    if not os.path.exists(path):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(base_dir, source)
        if os.path.exists(alt_path):
            path = alt_path
        else:
            raise FileNotFoundError(f"Каталог или файл '{source}' не найден.")

    if os.path.isdir(path):
        candidates = [
            os.path.join(path, "primes.json"),
            os.path.join(path, "rsa32k_primes.json"),
            os.path.join(path, "pq.json"),
            os.path.join(path, "primes_32k.json"),
        ]
        for cand in candidates:
            if os.path.isfile(cand):
                with open(cand, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return int(data["p"], 0), int(data["q"], 0)

        p_file = os.path.join(path, "p.txt")
        q_file = os.path.join(path, "q.txt")
        if os.path.isfile(p_file) and os.path.isfile(q_file):
            with open(p_file, "r", encoding="utf-8") as f:
                p = int(f.read().strip(), 0)
            with open(q_file, "r", encoding="utf-8") as f:
                q = int(f.read().strip(), 0)
            return p, q

        raise FileNotFoundError(f"В каталоге '{path}' не найдены primes.json или p.txt / q.txt.")

    elif os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        try:
            data = json.loads(content)
            return int(data["p"], 0), int(data["q"], 0)
        except json.JSONDecodeError:
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            if len(lines) >= 2:
                return int(lines[0], 0), int(lines[1], 0)
            raise ValueError(f"Не удалось распознать формат файла '{path}'. Ожидался JSON с ключами 'p' и 'q'.")
    else:
        raise FileNotFoundError(f"Путь '{path}' не существует.")


def cmd_rsa(args):
    threads = getattr(args, "threads", None)

    if getattr(args, "pregen_pq", False) or getattr(args, "generate_pq", False):
        bits = args.bits or 32768
        out_dir = getattr(args, "pregen_dir", "data/rsa_pregen") or "data/rsa_pregen"
        generate_and_save_pq(bits=bits, out_dir=out_dir, threads=threads, verbose=True)
        return

    use_pregen = (
        getattr(args, "pregen", None) is not None
        or getattr(args, "use_pregen", False)
        or bool(getattr(args, "p", None) and getattr(args, "q", None))
    )

    if args.demo:
        bits = args.bits or 4096
        if use_pregen:
            print(f"[*] Запуск демонстрации RSA (размер ключа: {bits} бит) с использованием pregen параметров...")
            t0 = time.time()
            if getattr(args, "p", None) and getattr(args, "q", None):
                p_val, q_val = args.p, args.q
                p = int(open(p_val, "r").read().strip(), 0) if os.path.isfile(p_val) else int(p_val, 0)
                q = int(open(q_val, "r").read().strip(), 0) if os.path.isfile(q_val) else int(q_val, 0)
            else:
                pregen_src = args.pregen if (isinstance(args.pregen, str) and args.pregen != "data/rsa_pregen") else getattr(args, "pregen_dir", "data/rsa_pregen")
                if not pregen_src or pregen_src is True:
                    pregen_src = "data/rsa_pregen"
                try:
                    p, q = load_pregen_primes(pregen_src)
                except Exception as e:
                    print(f"[-] Ошибка загрузки предварительно сгенерированных параметров: {e}")
                    print("    Сначала выполните генерацию: python cli.py rsa-pregen")
                    sys.exit(1)
            priv, pub = build_rsa_keypair_from_primes(p, q)
            print(f"[+] Ключ RSA-{priv.key_size} мгновенно собран за {time.time() - t0:.4f} сек!")
        else:
            print(f"[*] Запуск демонстрации RSA (размер ключа: {bits} бит)...")
            priv, pub, stats = generate_rsa_keypair_parallel(key_size=bits, num_workers=threads, verbose=True)

        data = args.data or "Тестовое секретное сообщение для RSA модуля"
        print(f"[*] Исходные данные: {data}")
        enc = rsa_encrypt_hybrid(pub, data)
        print(f"[+] Зашифрованный бандл (длина {len(enc)} байт):")
        print(f"    {enc[:120]}...")
        dec = rsa_decrypt_hybrid(priv, enc).decode("utf-8")
        print(f"[+] Расшифрованные данные: {dec}")
        print(f"[+] Успешность совпадения: {dec == data}")
        return

    if args.generate:
        bits = args.bits or 4096
        if use_pregen:
            if getattr(args, "p", None) and getattr(args, "q", None):
                p_val, q_val = args.p, args.q
                p = int(open(p_val, "r").read().strip(), 0) if os.path.isfile(p_val) else int(p_val, 0)
                q = int(open(q_val, "r").read().strip(), 0) if os.path.isfile(q_val) else int(q_val, 0)
                print("[*] Используются параметры p и q из аргументов командной строки")
            else:
                pregen_src = args.pregen if (isinstance(args.pregen, str) and args.pregen != "data/rsa_pregen") else getattr(args, "pregen_dir", "data/rsa_pregen")
                if not pregen_src or pregen_src is True:
                    pregen_src = "data/rsa_pregen"
                print(f"[*] Загрузка предварительно сгенерированных параметров p и q из '{pregen_src}'...")
                try:
                    p, q = load_pregen_primes(pregen_src)
                except Exception as e:
                    print(f"[-] Ошибка загрузки предварительно сгенерированных параметров: {e}")
                    print("    Сначала выполните генерацию: python cli.py rsa-pregen (или python cli.py rsa --pregen-pq)")
                    sys.exit(1)

            t0 = time.time()
            priv, pub = build_rsa_keypair_from_primes(p, q)
            el = time.time() - t0
            print(f"[+] Ключевая пара RSA-{priv.key_size} мгновенно собрана из параметров p и q за {el:.4f} сек!")
        else:
            if args.bits is None:
                print("[*] Размер ключа не указан, используется значение по умолчанию: 4096 бит (для 32K укажите --bits 32768)")
            priv, pub, stats = generate_rsa_keypair_parallel(key_size=bits, num_workers=threads, verbose=True)

        priv_pem = export_private_key_pem(priv)
        pub_pem = export_public_key_pem(pub)

        if args.out_priv:
            with open(args.out_priv, "w", encoding="utf-8") as f:
                f.write(priv_pem)
            print(f"[+] Закрытый ключ сохранен в {args.out_priv}")
        else:
            print("[*] Закрытый ключ (PEM):")
            print(priv_pem[:300] + "\n... [сокращено] ...\n" + priv_pem[-150:])

        if args.out_pub:
            with open(args.out_pub, "w", encoding="utf-8") as f:
                f.write(pub_pem)
            print(f"[+] Открытый ключ сохранен в {args.out_pub}")
        else:
            print("[*] Открытый ключ (PEM):")
            print(pub_pem[:300] + "\n... [сокращено] ...\n" + pub_pem[-150:])
        return


    if args.encrypt:
        if not args.pub:
            print("[-] Ошибка: укажите файл открытого ключа через --pub")
            sys.exit(1)
        with open(args.pub, "r", encoding="utf-8") as f:
            pub_pem = f.read()
        pub = load_public_key_pem(pub_pem)
        data = args.data
        if not data and args.in_file:
            with open(args.in_file, "r", encoding="utf-8") as f:
                data = f.read()
        if not data:
            print("[-] Ошибка: укажите данные через --data или --in-file")
            sys.exit(1)
        encrypted_bundle = rsa_encrypt_hybrid(pub, data)
        if args.out_file:
            with open(args.out_file, "w", encoding="utf-8") as f:
                f.write(encrypted_bundle)
            print(f"[+] Зашифрованный бандл сохранен в {args.out_file}")
        else:
            print("[+] Результат шифрования (JSON Bundle):")
            print(encrypted_bundle)
        return

    if args.decrypt:
        if not args.priv:
            print("[-] Ошибка: укажите файл закрытого ключа через --priv")
            sys.exit(1)
        with open(args.priv, "r", encoding="utf-8") as f:
            priv_pem = f.read()
        priv = load_private_key_pem(priv_pem)
        bundle_str = args.data
        if not bundle_str and args.in_file:
            with open(args.in_file, "r", encoding="utf-8") as f:
                bundle_str = f.read()
        if not bundle_str:
            print("[-] Ошибка: укажите зашифрованный бандл через --data или --in-file")
            sys.exit(1)
        decrypted = rsa_decrypt_hybrid(priv, bundle_str)
        text = decrypted.decode("utf-8", errors="replace")
        if args.out_file:
            with open(args.out_file, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"[+] Расшифрованный текст сохранен в {args.out_file}")
        else:
            print("[+] Расшифрованные данные:")
            print(text)
        return

    print("[-] Укажите операцию: --generate, --encrypt, --decrypt или --demo")


def cmd_kuznyechik(args):
    if args.demo:
        print("[*] Тест контрольного примера RFC 7801 ГОСТ «Кузнечик»...")
        k = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        pt = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
        cipher = Kuznyechik(k)
        ct = cipher.encrypt_block(pt)
        exp = "7f679d90bebc24305a468d42b9d4edcd"
        print(f"[+] Шифротекст: {ct.hex()}")
        print(f"[+] Соответствие стандарту RFC 7801: {ct.hex() == exp}")
        dt = cipher.decrypt_block(ct)
        print(f"[+] Расшифрование: {dt.hex()} (совпадает: {dt == pt})")
        return

    if not args.key:
        print("[-] Ошибка: укажите 32-байтный hex-ключ через --key (64 символа)")
        sys.exit(1)
    try:
        key_bytes = bytes.fromhex(args.key.strip())
        if len(key_bytes) != 32:
            raise ValueError("Длина ключа должна быть ровно 32 байта")
    except Exception as e:
        print(f"[-] Неверный ключ: {e}")
        sys.exit(1)

    cipher = Kuznyechik(key_bytes)

    if args.encrypt:
        data = (args.data or "").encode("utf-8")
        if not data and args.in_file:
            with open(args.in_file, "rb") as f:
                data = f.read()
        mode = args.mode or "cbc"
        if mode == "cbc":
            res = cipher.encrypt_cbc(data)
        else:
            res = cipher.encrypt_ctr(data)
        res_b64 = base64.b64encode(res).decode("ascii")
        print(f"[+] Зашифровано ({mode.upper()}, base64):")
        print(res_b64)
        return

    if args.decrypt:
        data_b64 = args.data or ""
        if not data_b64 and args.in_file:
            with open(args.in_file, "r", encoding="utf-8") as f:
                data_b64 = f.read().strip()
        raw = base64.b64decode(data_b64)
        mode = args.mode or "cbc"
        if mode == "cbc":
            res = cipher.decrypt_cbc(raw)
        else:
            res = cipher.decrypt_ctr(raw)
        print(f"[+] Расшифровано ({mode.upper()}):")
        print(res.decode("utf-8", errors="replace"))
        return


def cmd_streebog(args):
    if args.demo:
        print("[*] Тест контрольного примера RFC 6986 ГОСТ «Стрибог-512»...")
        m1 = bytes.fromhex("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130")
        h = streebog512(m1)
        exp = "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b"
        print(f"[+] Хэш Стрибог-512: {h.hex()}")
        print(f"[+] Соответствие стандарту RFC 6986: {h.hex() == exp}")
        return

    data = (args.data or "").encode("utf-8")
    if not data and args.in_file:
        with open(args.in_file, "rb") as f:
            data = f.read()

    if args.hmac:
        if not args.key:
            print("[-] Ошибка: для HMAC укажите ключ через --key")
            sys.exit(1)
        k = args.key.encode("utf-8")
        res = hmac_streebog512(k, data)
        print(f"[+] HMAC-Стрибог-512: {res.hex()}")
        return

    bits = args.bits or 512
    if bits == 256:
        h = streebog256(data)
        print(f"[+] Хэш Стрибог-256: {h.hex()}")
    else:
        h = streebog512(data)
        print(f"[+] Хэш Стрибог-512: {h.hex()}")


def cmd_ecp(args):
    if args.generate_cert:
        username = args.name or "User"
        user_id = args.user_id or 1
        priv, pub = generate_ecp_keypair()
        cert = issue_self_signed_certificate(username, user_id, priv, pub)
        print(f"[+] Выпущен сертификат ЭЦП для пользователя {username}:")
        print(json.dumps(cert, indent=2, ensure_ascii=False))

        if args.out_priv:
            with open(args.out_priv, "w", encoding="utf-8") as f:
                f.write(export_ecp_private_key_pem(priv))
            print(f"[+] Закрытый ключ ЭЦП сохранен в {args.out_priv}")
        if args.out_pub:
            with open(args.out_pub, "w", encoding="utf-8") as f:
                f.write(export_ecp_public_key_pem(pub))
            print(f"[+] Открытый ключ ЭЦП сохранен в {args.out_pub}")
        if args.out_cert:
            with open(args.out_cert, "w", encoding="utf-8") as f:
                json.dump(cert, f, indent=2, ensure_ascii=False)
            print(f"[+] Сертификат сохранен в {args.out_cert}")
        return

    if args.sign:
        if not args.priv:
            print("[-] Ошибка: укажите файл закрытого ключа через --priv")
            sys.exit(1)
        with open(args.priv, "r", encoding="utf-8") as f:
            priv_pem = f.read()
        priv = load_ecp_private_key_pem(priv_pem)
        data = args.data or ""
        if not data and args.in_file:
            with open(args.in_file, "r", encoding="utf-8") as f:
                data = f.read()
        sig = sign_message(priv, data)
        print(f"[+] Цифровая подпись (ЭЦП ГОСТ Стрибог-512, base64):")
        print(sig)
        return

    if args.verify:
        if not args.pub or not args.sig:
            print("[-] Ошибка: укажите --pub и --sig для проверки")
            sys.exit(1)
        with open(args.pub, "r", encoding="utf-8") as f:
            pub_pem = f.read()
        pub = load_ecp_public_key_pem(pub_pem)
        data = args.data or ""
        if not data and args.in_file:
            with open(args.in_file, "r", encoding="utf-8") as f:
                data = f.read()
        valid = verify_message_signature(pub, data, args.sig)
        print(f"[+] Результат проверки ЭЦП: {'ПОДЛИННАЯ (ВЕРНА)' if valid else 'НЕДЕЙСТВИТЕЛЬНА'}")
        return

    print("[-] Укажите операцию для ecp: --generate-cert, --sign или --verify")


def main():
    parser = argparse.ArgumentParser(description="CryptoMail Modular CLI & API Utility")
    subparsers = parser.add_subparsers(dest="subcommand", help="Модули")

    # RSA Subparser
    p_rsa = subparsers.add_parser("rsa", help="Модуль RSA (включая RSA-32768)")
    p_rsa.add_argument("--generate", action="store_true", help="Сгенерировать ключевую пару")
    p_rsa.add_argument("--bits", type=int, default=None, help="Размер ключа в битах (2048, 4096, 8192, 32768)")
    p_rsa.add_argument("--threads", type=int, default=None, help="Количество параллельных потоков/ядер CPU (по умолчанию: все доступные)")
    p_rsa.add_argument("--out-priv", type=str, help="Файл для сохранения закрытого ключа PEM")
    p_rsa.add_argument("--out-pub", type=str, help="Файл для сохранения открытого ключа PEM")
    p_rsa.add_argument("--pregen", nargs="?", const="data/rsa_pregen", default=None, help="Использовать заранее сгенерированные p и q (по умолчанию из data/rsa_pregen или указанного пути)")
    p_rsa.add_argument("--use-pregen", action="store_true", help="Использовать заранее сгенерированные p и q из data/rsa_pregen")
    p_rsa.add_argument("--p", type=str, help="Значение p или путь к файлу с p")
    p_rsa.add_argument("--q", type=str, help="Значение q или путь к файлу с q")
    p_rsa.add_argument("--pregen-pq", "--generate-pq", action="store_true", help="Сгенерировать p и q и сохранить их в data/rsa_pregen")
    p_rsa.add_argument("--pregen-dir", type=str, default="data/rsa_pregen", help="Каталог для сохранения/загрузки предвычисленных p и q (по умолчанию: data/rsa_pregen)")
    p_rsa.add_argument("--encrypt", action="store_true", help="Зашифровать данные")
    p_rsa.add_argument("--decrypt", action="store_true", help="Расшифровать данные")
    p_rsa.add_argument("--pub", type=str, help="Путь к открытому ключу PEM")
    p_rsa.add_argument("--priv", type=str, help="Путь к закрытому ключу PEM")
    p_rsa.add_argument("--data", type=str, help="Данные для обработки")
    p_rsa.add_argument("--in-file", type=str, help="Входной файл с данными")
    p_rsa.add_argument("--out-file", type=str, help="Выходной файл для результата")
    p_rsa.add_argument("--demo", action="store_true", help="Демонстрационный сквозной запуск")

    # RSA Pregen Subparser
    p_pregen = subparsers.add_parser("rsa-pregen", help="Генерация p и q для RSA-32K и сохранение в data/rsa_pregen")
    p_pregen.add_argument("--bits", type=int, default=32768, help="Размер ключа в битах (по умолчанию 32768, т.е. p и q по 16384 бит)")
    p_pregen.add_argument("--threads", type=int, default=None, help="Количество параллельных потоков/ядер CPU")
    p_pregen.add_argument("--out-dir", type=str, default="data/rsa_pregen", help="Директория для сохранения p и q (по умолчанию: data/rsa_pregen)")

    p_pregen_alias = subparsers.add_parser("pregen", help="Алиас для rsa-pregen")
    p_pregen_alias.add_argument("--bits", type=int, default=32768, help="Размер ключа в битах (по умолчанию 32768)")
    p_pregen_alias.add_argument("--threads", type=int, default=None, help="Количество параллельных потоков/ядер CPU")
    p_pregen_alias.add_argument("--out-dir", type=str, default="data/rsa_pregen", help="Директория для сохранения p и q (по умолчанию: data/rsa_pregen)")

    # Kuznyechik Subparser
    p_kuz = subparsers.add_parser("kuznyechik", help="Модуль ГОСТ Р 34.12-2015 «Кузнечик»")
    p_kuz.add_argument("--encrypt", action="store_true", help="Зашифровать")
    p_kuz.add_argument("--decrypt", action="store_true", help="Расшифровать")
    p_kuz.add_argument("--key", type=str, help="256-битный ключ (64 hex-символа)")
    p_kuz.add_argument("--data", type=str, help="Строка данных")
    p_kuz.add_argument("--in-file", type=str, help="Входной файл")
    p_kuz.add_argument("--mode", choices=["cbc", "ctr"], default="cbc", help="Режим шифрования")
    p_kuz.add_argument("--demo", action="store_true", help="Тест эталона RFC 7801")

    # Streebog Subparser
    p_stree = subparsers.add_parser("streebog", help="Модуль ГОСТ Р 34.11-2012 «Стрибог»")
    p_stree.add_argument("--data", type=str, help="Строка данных для хэширования")
    p_stree.add_argument("--in-file", type=str, help="Входной файл")
    p_stree.add_argument("--bits", type=int, choices=[256, 512], default=512, help="Разрядность хэша")
    p_stree.add_argument("--hmac", action="store_true", help="Вычислить HMAC")
    p_stree.add_argument("--key", type=str, help="Ключ для HMAC")
    p_stree.add_argument("--demo", action="store_true", help="Тест эталона RFC 6986")

    # ECP Subparser
    p_ecp = subparsers.add_parser("ecp", help="Модуль Электронной Цифровой Подписи")
    p_ecp.add_argument("--generate-cert", action="store_true", help="Выпустить сертификат ЭЦП")
    p_ecp.add_argument("--name", type=str, help="Имя владельца сертификата")
    p_ecp.add_argument("--user-id", type=int, help="ID пользователя")
    p_ecp.add_argument("--sign", action="store_true", help="Подписать данные")
    p_ecp.add_argument("--verify", action="store_true", help="Проверить подпись")
    p_ecp.add_argument("--priv", type=str, help="Файл закрытого ключа ЭЦП")
    p_ecp.add_argument("--pub", type=str, help="Файл открытого ключа ЭЦП")
    p_ecp.add_argument("--sig", type=str, help="Цифровая подпись в base64")
    p_ecp.add_argument("--data", type=str, help="Данные для подписи/проверки")
    p_ecp.add_argument("--in-file", type=str, help="Файл с данными")
    p_ecp.add_argument("--out-priv", type=str, help="Файл для сохранения закрытого ключа")
    p_ecp.add_argument("--out-pub", type=str, help="Файл для сохранения открытого ключа")
    p_ecp.add_argument("--out-cert", type=str, help="Файл для сохранения сертификата")

    # Shortcut demo command
    p_demo4 = subparsers.add_parser("demo-rsa-4k", help="Быстрая демонстрация работы RSA-4096")
    p_demo4.add_argument("--bits", type=int, default=4096, help="Размер ключа (2048, 4096, 8192, 32768, по умолчанию 4096)")
    p_demo4.add_argument("--threads", type=int, default=None, help="Количество параллельных потоков/ядер CPU")

    p_demo32 = subparsers.add_parser("demo-rsa-32k", help="Быстрая демонстрация работы RSA-32K")
    p_demo32.add_argument("--bits", type=int, default=32768, help="Размер ключа (2048, 4096, 8192, 32768, по умолчанию 32768)")
    p_demo32.add_argument("--threads", type=int, default=None, help="Количество параллельных потоков/ядер CPU")
    p_demo32.add_argument("--pregen", nargs="?", const="data/rsa_pregen", default=None, help="Использовать заранее сгенерированные p и q (по умолчанию из data/rsa_pregen)")

    args = parser.parse_args()

    if args.subcommand == "rsa":
        cmd_rsa(args)
    elif args.subcommand in ("rsa-pregen", "pregen"):
        generate_and_save_pq(
            bits=args.bits or 32768,
            out_dir=args.out_dir or "data/rsa_pregen",
            threads=getattr(args, "threads", None),
            verbose=True,
        )

    elif args.subcommand == "kuznyechik":
        cmd_kuznyechik(args)
    elif args.subcommand == "streebog":
        cmd_streebog(args)
    elif args.subcommand == "ecp":
        cmd_ecp(args)
    elif args.subcommand == "demo-rsa-4k":
        args.bits = getattr(args, "bits", 4096) or 4096
        args.demo = True
        args.data = "Секретное сообщение для демонстрации RSA"
        cmd_rsa(args)
    elif args.subcommand == "demo-rsa-32k":
        args.bits = getattr(args, "bits", 32768) or 32768
        args.demo = True
        args.data = "Секретное сообщение для демонстрации RSA"
        cmd_rsa(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
