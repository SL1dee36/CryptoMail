# Description: Multiprocessing RSA key generator with parallel Miller-Rabin prime searches and live candidate counter.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import math
import multiprocessing as mp
import os
import secrets
import sys
import time
from typing import Callable, Dict, Optional, Tuple

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from crypto.rsa import RSAPrivateKey, RSAPublicKey, build_rsa_keypair_from_primes


# Precomputed small primes sieve up to 2000 for ultra-fast candidate filtering
def _sieve_primes(limit: int = 2000):
    sieve = [True] * limit
    sieve[0] = sieve[1] = False
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            for j in range(i * i, limit, i):
                sieve[j] = False
    return [i for i, is_p in enumerate(sieve) if is_p]

SMALL_PRIMES = _sieve_primes(2000)


def is_probable_prime(n: int, rounds: int = 6) -> bool:
    """
    Miller-Rabin primality test with pre-sieve.
    Rounds = 6 provides probability of false positive < 2^-128 for numbers >= 1024 bits.
    """
    if n < 2 or n % 2 == 0:
        return False
    # Quick trial division by first 303 primes
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p

    # Write n - 1 as 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Miller-Rabin test
    for _ in range(rounds):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _worker_search_prime(
    prime_bits: int,
    shared_counter: mp.Value,
    stop_event: mp.Event,
    result_queue: mp.Queue,
    worker_id: int,
):
    """Worker process: continuously tests candidate numbers until stop_event is set."""
    local_tested = 0
    batch_size = 20

    while not stop_event.is_set():
        cand = secrets.randbits(prime_bits) | (1 << (prime_bits - 1)) | (1 << (prime_bits - 2)) | 1
        # Public exponent gcd check (e=65537)
        if (cand - 1) % 65537 == 0:
            local_tested += 1
            continue

        local_tested += 1
        if local_tested >= batch_size:
            with shared_counter.get_lock():
                shared_counter.value += local_tested
            local_tested = 0

        if is_probable_prime(cand, rounds=6):
            if not stop_event.is_set():
                stop_event.set()
                with shared_counter.get_lock():
                    shared_counter.value += local_tested
                result_queue.put(cand)
            return

    # Flush remaining counts before exiting
    if local_tested > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_tested


def find_prime_parallel(
    prime_bits: int,
    num_workers: Optional[int] = None,
    progress_callback: Optional[Callable[[int, float], None]] = None,
) -> Tuple[int, int, float]:
    """
    Finds a prime number of prime_bits using multiprocessing.
    Returns: (prime, total_candidates_tested, elapsed_seconds)
    """
    if num_workers is None or num_workers < 1:
        num_workers = max(1, os.cpu_count() or 4)

    shared_counter = mp.Value("q", 0)  # 64-bit unsigned/signed counter
    stop_event = mp.Event()
    result_queue = mp.Queue()

    t_start = time.time()

    workers = []
    for i in range(num_workers):
        p = mp.Process(
            target=_worker_search_prime,
            args=(prime_bits, shared_counter, stop_event, result_queue, i),
            daemon=True,
        )
        p.start()
        workers.append(p)

    prime = None
    try:
        while prime is None:
            try:
                prime = result_queue.get(timeout=0.08)
            except Exception:
                pass

            now = time.time()
            with shared_counter.get_lock():
                cands = shared_counter.value

            if progress_callback:
                progress_callback(cands, now - t_start)
    except KeyboardInterrupt:
        stop_event.set()
        for p in workers:
            try:
                p.terminate()
            except Exception:
                pass
        raise
    finally:
        stop_event.set()
        for p in workers:
            p.join(timeout=0.3)
            if p.is_alive():
                try:
                    p.terminate()
                except Exception:
                    pass

    elapsed = time.time() - t_start
    with shared_counter.get_lock():
        total_cands = shared_counter.value

    return prime, total_cands, elapsed


def generate_rsa_keypair_parallel(
    key_size: int = 4096,
    num_workers: Optional[int] = None,
    verbose: bool = True,
) -> Tuple[RSAPrivateKey, RSAPublicKey, Dict]:
    """
    Generates an RSA key pair using all CPU cores in parallel.
    Displays live real-time candidate count and elapsed timer in the terminal.
    """
    if num_workers is None or num_workers < 1:
        num_workers = max(1, os.cpu_count() or 4)

    prime_bits = key_size // 2
    t_global_start = time.time()
    total_candidates_all = 0

    def format_time(seconds: float) -> str:
        m = int(seconds // 60)
        s = int(seconds % 60)
        ms = int((seconds * 10) % 10)
        return f"{m:02d}:{s:02d}.{ms}"

    if verbose:
        print(f"[*] Начало параллельной генерации RSA-{key_size} (многопоток: {num_workers} ядер CPU)")
        print(f"[*] Длина простых чисел p и q: по {prime_bits} бит каждое")

    # Step 1: Find p
    def progress_p(cands: int, el: float):
        if verbose:
            speed = cands / el if el > 0 else 0
            sys.stdout.write(
                f"\r[*] [{format_time(el)}] Поиск p ({prime_bits} бит) | Ядер: {num_workers} | Проверено: {cands:,} канд ({speed:.0f} канд/с)   "
            )
            sys.stdout.flush()

    p, cands_p, el_p = find_prime_parallel(prime_bits, num_workers=num_workers, progress_callback=progress_p)
    total_candidates_all += cands_p
    if verbose:
        sys.stdout.write(f"\r[+] [{format_time(el_p)}] Простое число p найдено за {el_p:.2f} сек! (Кандидатов: {cands_p:,})\n")
        sys.stdout.flush()

    # Step 2: Find q (must be distinct from p)
    t_q_start = time.time()

    def progress_q(cands: int, el: float):
        if verbose:
            total_now = total_candidates_all + cands
            el_tot = time.time() - t_global_start
            speed = total_now / el_tot if el_tot > 0 else 0
            sys.stdout.write(
                f"\r[*] [{format_time(el_tot)}] Поиск q ({prime_bits} бит) | Ядер: {num_workers} | Проверено: {total_now:,} канд ({speed:.0f} канд/с)   "
            )
            sys.stdout.flush()

    q = p
    min_diff = 1 << max(1, prime_bits - 100)
    while q == p or abs(p - q) < min_diff or (p * q).bit_length() != key_size:
        q, cands_q, el_q = find_prime_parallel(prime_bits, num_workers=num_workers, progress_callback=progress_q)
        total_candidates_all += cands_q

    el_tot = time.time() - t_global_start
    if verbose:
        sys.stdout.write(f"\r[+] [{format_time(el_tot)}] Простое число q найдено за {el_q:.2f} сек! (Кандидатов: {cands_q:,})\n")
        sys.stdout.flush()

    # Ensure p > q for standard CRT representation
    if p < q:
        p, q = q, p

    if verbose:
        sys.stdout.write("[*] Сборка параметров RSA (модуль n, закрытый экспонент d, CRT компоненты)... \n")
        sys.stdout.flush()

    # Math assembly
    priv_key, pub_key = build_rsa_keypair_from_primes(p, q, public_exponent=65537)

    total_time = time.time() - t_global_start
    speed_overall = total_candidates_all / total_time if total_time > 0 else 0

    stats = {
        "key_size": key_size,
        "prime_bits": prime_bits,
        "workers": num_workers,
        "total_candidates": total_candidates_all,
        "elapsed_seconds": total_time,
        "candidates_per_second": speed_overall,
    }

    if verbose:
        print(f"[+] Ключевая пара RSA-{key_size} успешно сгенерирована!")
        print(f"[+] Полное затраченное время: {total_time:.2f} сек ({format_time(total_time)})")
        print(f"[+] Всего проверено кандидатов: {total_candidates_all:,} (средняя скорость: {speed_overall:.0f} канд/сек)")
        print(f"[+] Задействовано ядер CPU: {num_workers}")

    return priv_key, pub_key, stats
