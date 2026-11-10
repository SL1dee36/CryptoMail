#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import time

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def separator(char="=", length=80):
    print(char * length)


def print_compare_field(name: str, gost_val: str, algo_val: str):
    eq = gost_val.strip().lower() == algo_val.strip().lower()
    print(f"{name}:")
    print(f"  ГОСТ:      {gost_val}")
    print(f"  Программа: {algo_val}")
    print(f"  Равно:     {eq}")


# =============================================================================
# 1. ГОСТ Р 34.12-2015 («Кузнечик» / RFC 7801)
# =============================================================================
def run_kuznyechik():
    from crypto.kuznyechik import (
        ROUND_CONSTANTS,
        _L,
        _L_inv,
        _S,
        _S_inv,
        _xor,
        expand_key,
    )

    separator("=")
    print("ГОСТ Р 34.12-2015 («КУЗНЕЧИК» / RFC 7801)")
    separator("=")

    # 1. Стартовые данные ГОСТ
    master_key_hex = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
    plaintext_hex = "1122334455667700ffeeddccbbaa9988"

    print("\n[1. СТАРТОВЫЕ ДАННЫЕ ГОСТ]")
    print(f"Мастер-ключ (256 бит): {master_key_hex}")
    print(f"Открытый текст (128 бит): {plaintext_hex}")

    # 2. Результат ГОСТ (Эталон)
    gost_round_keys = [
        "8899aabbccddeeff0011223344556677",
        "fedcba98765432100123456789abcdef",
        "db31485315694343228d6aef8cc78c44",
        "3d4553d8e9cfec6815ebadc40a9ffd04",
        "57646468c44a5e28d3e59246f429f1ac",
        "bd079435165c6432b532e82834da581b",
        "51e640757e8745de705727265a0098b1",
        "5a7925017b9fdd3ed72a91a22286f984",
        "bb44e25378c73123a5f32f73cdb6e517",
        "72e9dd7416bcf45b755dbaa88e4a4043",
    ]
    gost_ciphertext_hex = "7f679d90bebc24305a468d42b9d4edcd"
    gost_decrypted_hex = plaintext_hex

    print("\n[2. ЭТАЛОННЫЙ РЕЗУЛЬТАТ ГОСТ]")
    print("Раундовые ключи K_01 .. K_10:")
    for i, k in enumerate(gost_round_keys, 1):
        print(f"  K_{i:02d} = {k}")
    print(f"Шифртекст:               {gost_ciphertext_hex}")
    print(f"Расшифрованный текст:    {gost_decrypted_hex}")

    # 3. Стартовые данные алгоритма
    algo_input_key = master_key_hex
    algo_input_pt = plaintext_hex

    print("\n[3. СТАРТОВЫЕ ДАННЫЕ АЛГОРИТМА]")
    print(f"Входной ключ (256 бит):   {algo_input_key}")
    print(f"Входной текст (128 бит):  {algo_input_pt}")

    # 4. Результат работы алгоритма
    print("\n[4. РЕЗУЛЬТАТ РАБОТЫ АЛГОРИТМА]")

    print("Раундовые константы C_01 .. C_32:")
    for i, c in enumerate(ROUND_CONSTANTS, 1):
        print(f"  C_{i:02d} = {c.hex()}")

    algo_round_keys = expand_key(bytes.fromhex(algo_input_key))
    print("\nВычисленные раундовые ключи K_01 .. K_10:")
    for i, rk in enumerate(algo_round_keys, 1):
        print(f"  K_{i:02d} = {rk.hex()}")

    print("\nПошаговое шифрование:")
    state = bytes.fromhex(algo_input_pt)
    for r in range(9):
        x_val = _xor(state, algo_round_keys[r])
        s_val = _S(x_val)
        l_val = _L(s_val)
        print(f"Раунд {r+1:02d}:")
        print(f"  Вход:     {state.hex()}")
        print(f"  После X:  {x_val.hex()}")
        print(f"  После S:  {s_val.hex()}")
        print(f"  После L:  {l_val.hex()}")
        state = l_val

    algo_ciphertext = _xor(state, algo_round_keys[9]).hex()
    print("Раунд 10 (Финальный):")
    print(f"  После X (Шифртекст): {algo_ciphertext}")

    print("\nПошаговое расшифрование:")
    state = _xor(bytes.fromhex(algo_ciphertext), algo_round_keys[9])
    print(f"Инициализация (После X с K_10): {state.hex()}")

    for r in range(8, 0, -1):
        inv_l = _L_inv(state)
        inv_s = _S_inv(inv_l)
        state = _xor(inv_s, algo_round_keys[r])
        print(f"Обратный раунд {r:02d}:")
        print(f"  После L^-1: {inv_l.hex()}")
        print(f"  После S^-1: {inv_s.hex()}")
        print(f"  После X:    {state.hex()}")

    inv_l = _L_inv(state)
    inv_s = _S_inv(inv_l)
    algo_decrypted = _xor(inv_s, algo_round_keys[0]).hex()
    print("Обратный раунд 01 (Финальный):")
    print(f"  После L^-1: {inv_l.hex()}")
    print(f"  После S^-1: {inv_s.hex()}")
    print(f"  После X:    {algo_decrypted}")

    # 5. Сравнение результатов
    print("\n[5. СРАВНЕНИЕ РЕЗУЛЬТАТОВ]")
    print("Раундовые ключи:")
    for i in range(10):
        print_compare_field(f"K_{i+1:02d}", gost_round_keys[i], algo_round_keys[i].hex())
    print()
    print_compare_field("Шифртекст", gost_ciphertext_hex, algo_ciphertext)
    print()
    print_compare_field("Расшифрованный текст", gost_decrypted_hex, algo_decrypted)


# =============================================================================
# 2. ГОСТ Р 34.11-2012 («Стрибог» / RFC 6986)
# =============================================================================
def run_streebog():
    from crypto.streebog import (
        ITERATION_CONSTANTS,
        _LPS,
        _key_schedule,
        _xor,
        streebog256,
        streebog512,
    )

    separator("=")
    print("ГОСТ Р 34.11-2012 («СТРИБОГ» / RFC 6986)")
    separator("=")

    # 1. Стартовые данные ГОСТ
    m1_hex = "303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132"
    m1_bytes = bytes.fromhex(m1_hex)
    m1_pad = (m1_bytes + b"\x01").rjust(64, b"\x00")

    m2_hex = "d0e5e1e5e4e820eff0eeeceee2e820eaeef0eef1e5ec20f0e0e4eee1e0eb2c20e4ebff20efeff0eef8e5e3eee2e0edf820d1f2f0e8e1eee3e020f1eef2e8"
    m2_bytes = bytes.fromhex(m2_hex)

    print("\n[1. СТАРТОВЫЕ ДАННЫЕ ГОСТ]")
    print(f"Вектор M1 (63 байта) ASCII: \"{m1_bytes.decode('ascii')}\"")
    print(f"Вектор M1 (63 байта) HEX:   {m1_hex}")
    print(f"Дополнение M1 (M||01||0*):   {m1_pad.hex()}")
    print(f"Вектор M2 (72 байта) HEX:   {m2_hex}")

    # 2. Результат ГОСТ (Эталон)
    gost_512_m1 = "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
    gost_256_m1 = "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
    gost_512_m2 = "0b1d78600f99c71bfe3b365cc3fab0e0e2c8193ddb6f1fd9a0683fabf62b24f4bf1f5d00bd6a7b55e351d855e86859d986a5c99e487ef1b205add99d31bcca9a"
    gost_256_m2 = "6fe9b5adda62b91fb689ffe4e8c4614ffd87dfe24b5d3c2d25e5a3a9469e780f"

    print("\n[2. ЭТАЛОННЫЙ РЕЗУЛЬТАТ ГОСТ]")
    print(f"Стрибог-512 (M1): {gost_512_m1}")
    print(f"Стрибог-256 (M1): {gost_256_m1}")
    print(f"Стрибог-512 (M2): {gost_512_m2}")
    print(f"Стрибог-256 (M2): {gost_256_m2}")

    # 3. Стартовые данные алгоритма
    algo_input_m1 = m1_bytes
    algo_input_m2 = m2_bytes

    print("\n[3. СТАРТОВЫЕ ДАННЫЕ АЛГОРИТМА]")
    print(f"Вход M1 (HEX): {algo_input_m1.hex()}")
    print(f"Вход M2 (HEX): {algo_input_m2.hex()}")

    # 4. Результат работы алгоритма
    print("\n[4. РЕЗУЛЬТАТ РАБОТЫ АЛГОРИТМА]")
    print("Итерационные константы C_01 .. C_12:")
    for i, c in enumerate(ITERATION_CONSTANTS, 1):
        print(f"  C_{i:02d} = {c.hex()}")

    h0 = bytes(64)
    n0 = bytes(64)
    k0 = _LPS(_xor(h0, n0))
    round_keys_e = _key_schedule(k0)

    print("\nРаундовые ключи функции сжатия E(K, m) для блока 1:")
    for i, rk in enumerate(round_keys_e):
        print(f"  K_{i:02d} = {rk.hex()}")

    algo_512_m1 = streebog512(algo_input_m1).hex()
    algo_256_m1 = streebog256(algo_input_m1).hex()
    algo_512_m2 = streebog512(algo_input_m2).hex()
    algo_256_m2 = streebog256(algo_input_m2).hex()

    print(f"\nВычисленный Стрибог-512 (M1): {algo_512_m1}")
    print(f"Вычисленный Стрибог-256 (M1): {algo_256_m1}")
    print(f"Вычисленный Стрибог-512 (M2): {algo_512_m2}")
    print(f"Вычисленный Стрибог-256 (M2): {algo_256_m2}")

    # 5. Сравнение результатов
    print("\n[5. СРАВНЕНИЕ РЕЗУЛЬТАТОВ]")
    print_compare_field("Стрибог-512 (M1)", gost_512_m1, algo_512_m1)
    print()
    print_compare_field("Стрибог-256 (M1)", gost_256_m1, algo_256_m1)
    print()
    print_compare_field("Стрибог-512 (M2)", gost_512_m2, algo_512_m2)
    print()
    print_compare_field("Стрибог-256 (M2)", gost_256_m2, algo_256_m2)


# =============================================================================
# 3. ГОСТ Р 34.10-2012 (ЭЦП / RFC 7091)
# =============================================================================
def run_ecp():
    from crypto.ecp import CURVE_GOST_2012_256, GostPrivateKey

    separator("=")
    print("ГОСТ Р 34.10-2012 (ЭЦП / RFC 7091)")
    separator("=")

    curve = CURVE_GOST_2012_256

    # 1. Стартовые данные ГОСТ
    d_rfc = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
    e_rfc = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
    k_rfc = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3

    print("\n[1. СТАРТОВЫЕ ДАННЫЕ ГОСТ (RFC 7091)]")
    print(f"p:                {hex(curve.p)[2:]}")
    print(f"a:                {hex(curve.a)[2:]}")
    print(f"b:                {hex(curve.b)[2:]}")
    print(f"q:                {hex(curve.q)[2:]}")
    print(f"P.x:              {hex(curve.P[0])[2:]}")
    print(f"P.y:              {hex(curve.P[1])[2:]}")
    print(f"Секретный ключ d: {hex(d_rfc)[2:]}")
    print(f"Хеш-код e:        {hex(e_rfc)[2:]}")
    print(f"Число k:          {hex(k_rfc)[2:]}")

    # 2. Результат ГОСТ (Эталон)
    gost_xq = "7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b"
    gost_yq = "26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da"
    gost_cx = "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"
    gost_cy = "489c375a9941a3049e33b34361dd204172ad98c3e5916de27695d22a61fae46e"
    gost_r = "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"
    gost_s = "1456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40"

    print("\n[2. ЭТАЛОННЫЙ РЕЗУЛЬТАТ ГОСТ]")
    print(f"Q.x: {gost_xq}")
    print(f"Q.y: {gost_yq}")
    print(f"C.x: {gost_cx}")
    print(f"C.y: {gost_cy}")
    print(f"r:   {gost_r}")
    print(f"s:   {gost_s}")

    # 3. Стартовые данные алгоритма
    algo_input_d = d_rfc
    algo_input_e = e_rfc
    algo_input_k = k_rfc

    print("\n[3. СТАРТОВЫЕ ДАННЫЕ АЛГОРИТМА]")
    print(f"Входной d: {hex(algo_input_d)[2:]}")
    print(f"Входной e: {hex(algo_input_e)[2:]}")
    print(f"Входной k: {hex(algo_input_k)[2:]}")

    # 4. Результат работы алгоритма
    priv = GostPrivateKey(algo_input_d, curve)
    pub = priv.public_key()
    algo_xq = hex(pub.x)[2:]
    algo_yq = hex(pub.y)[2:]

    C = curve.point_mul(algo_input_k, curve.P)
    algo_cx = hex(C[0])[2:]
    algo_cy = hex(C[1])[2:]

    r = C[0] % curve.q
    s = (r * algo_input_d + algo_input_k * algo_input_e) % curve.q
    algo_r = hex(r)[2:]
    algo_s = hex(s)[2:]

    v = pow(algo_input_e, -1, curve.q)
    z1 = (s * v) % curve.q
    z2 = (-r * v) % curve.q
    C_ver = curve.point_add(curve.point_mul(z1, curve.P), curve.point_mul(z2, (pub.x, pub.y)))
    r_ver = C_ver[0] % curve.q
    algo_r_ver = hex(r_ver)[2:]

    print("\n[4. РЕЗУЛЬТАТ РАБОТЫ АЛГОРИТМА]")
    print(f"Вычисленный Q.x: {algo_xq}")
    print(f"Вычисленный Q.y: {algo_yq}")
    print(f"Вычисленная точка C.x: {algo_cx}")
    print(f"Вычисленная точка C.y: {algo_cy}")
    print(f"Вычисленная компонента r: {algo_r}")
    print(f"Вычисленная компонента s: {algo_s}")
    print(f"v = e^-1 mod q:  {hex(v)[2:]}")
    print(f"z1 = s*v mod q:  {hex(z1)[2:]}")
    print(f"z2 = -r*v mod q: {hex(z2)[2:]}")
    print(f"C'.x:            {hex(C_ver[0])[2:]}")
    print(f"C'.y:            {hex(C_ver[1])[2:]}")
    print(f"r' = C'.x mod q: {algo_r_ver}")

    # 5. Сравнение результатов
    print("\n[5. СРАВНЕНИЕ РЕЗУЛЬТАТОВ]")
    print_compare_field("Q.x", gost_xq, algo_xq)
    print()
    print_compare_field("Q.y", gost_yq, algo_yq)
    print()
    print_compare_field("C.x", gost_cx, algo_cx)
    print()
    print_compare_field("C.y", gost_cy, algo_cy)
    print()
    print_compare_field("Компонента r", gost_r, algo_r)
    print()
    print_compare_field("Компонента s", gost_s, algo_s)
    print()
    print_compare_field("Проверка r' == r", hex(r)[2:], algo_r_ver)


# =============================================================================
# 4. RSA-32768 (32768 БИТ С УСКОРЕНИЕМ CRT)
# =============================================================================
def run_rsa_32k():
    from crypto.rsa import rsa_decrypt_hybrid, rsa_encrypt_hybrid
    from cryptomail.services.rsa_pool_service import get_pool_key_by_id

    separator("=")
    print("RSA-32768 (32768 БИТ С УСКОРЕНИЕМ CRT)")
    separator("=")

    priv, pub = get_pool_key_by_id(1)

    # 1. Стартовые данные
    p_hex = hex(priv.p)[2:]
    q_hex = hex(priv.q)[2:]
    n_hex = hex(priv.n)[2:]
    test_text = "Тестовое сообщение RSA-32768 + Кузнечик CBC."

    print("\n[1. СТАРТОВЫЕ ДАННЫЕ]")
    print(f"Разрядность модуля N:   {priv.n.bit_length()} бит")
    print(f"Разрядность простого p: {priv.p.bit_length()} бит")
    print(f"Разрядность простого q: {priv.q.bit_length()} бит")
    print(f"Открытая экспонента e:  {pub.e}")
    print(f"p (hex): {p_hex[:32]}...{p_hex[-32:]} (всего {len(str(priv.p))} дес. знаков)")
    print(f"q (hex): {q_hex[:32]}...{q_hex[-32:]} (всего {len(str(priv.q))} дес. знаков)")
    print(f"N (hex): {n_hex[:32]}...{n_hex[-32:]} (всего {len(str(priv.n))} дес. знаков)")
    print(f"Открытый текст: \"{test_text}\"")

    # 2. Эталонный результат
    expected_text = test_text
    print("\n[2. ЭТАЛОННЫЙ РЕЗУЛЬТАТ]")
    print(f"Ожидаемый восстановленный текст: \"{expected_text}\"")

    # 3. Стартовые данные алгоритма
    print("\n[3. СТАРТОВЫЕ ДАННЫЕ АЛГОРИТМА]")
    print(f"Входной текст: \"{test_text}\"")
    print(f"Ключ: ID #1 из rsa_keys_pool.json (32768 бит)")

    # 4. Результат работы алгоритма
    dp = priv.dmp1 if priv.dmp1 is not None else priv.d % (priv.p - 1)
    dq = priv.dmq1 if priv.dmq1 is not None else priv.d % (priv.q - 1)
    qinv = priv.iqmp if priv.iqmp is not None else pow(priv.q, -1, priv.p)

    t0 = time.perf_counter()
    encrypted_bundle = rsa_encrypt_hybrid(pub, test_text)
    t_enc = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    decrypted_raw = rsa_decrypt_hybrid(priv, encrypted_bundle)
    t_dec = (time.perf_counter() - t0) * 1000
    decrypted_str = decrypted_raw.decode("utf-8") if isinstance(decrypted_raw, bytes) else decrypted_raw

    print("\n[4. РЕЗУЛЬТАТ РАБОТЫ АЛГОРИТМА]")
    print(f"dp = d mod (p-1):  {hex(dp)[2:][:32]}... ({dp.bit_length()} бит)")
    print(f"dq = d mod (q-1):  {hex(dq)[2:][:32]}... ({dq.bit_length()} бит)")
    print(f"qinv = q^-1 mod p: {hex(qinv)[2:][:32]}... ({qinv.bit_length()} бит)")
    print(f"Время шифрования:  {t_enc:.2f} мс")
    print(f"Время расшифрования (CRT): {t_dec:.2f} мс")
    print(f"Зашифрованный пакет: {encrypted_bundle[:60]}...")
    print(f"Восстановленный текст: \"{decrypted_str}\"")

    # 5. Сравнение результатов
    print("\n[5. СРАВНЕНИЕ РЕЗУЛЬТАТОВ]")
    print_compare_field("Восстановленный текст", expected_text, decrypted_str)


# =============================================================================
# Запуск
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="Сверка криптографических стандартов ГОСТ и RSA-32K")
    parser.add_argument("--kuznyechik", action="store_true", help="ГОСТ Р 34.12-2015 (Кузнечик)")
    parser.add_argument("--streebog", action="store_true", help="ГОСТ Р 34.11-2012 (Стрибог)")
    parser.add_argument("--ecp", action="store_true", help="ГОСТ Р 34.10-2012 (ЭЦП)")
    parser.add_argument("--rsa", action="store_true", help="RSA-32768")
    parser.add_argument("--all", action="store_true", help="Все стандарты")

    args = parser.parse_args()

    has_filter = args.kuznyechik or args.streebog or args.ecp or args.rsa
    run_all = args.all or (not has_filter)

    if run_all or args.kuznyechik:
        run_kuznyechik()
        print()

    if run_all or args.streebog:
        run_streebog()
        print()

    if run_all or args.ecp:
        run_ecp()
        print()

    if run_all or args.rsa:
        run_rsa_32k()
        print()


if __name__ == "__main__":
    main()
