# Description: Background generator script for precomputing 32768-bit RSA keys for fast pool allocation.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import json
import os
import sys
import time

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from crypto.rsa import generate_rsa_keypair, export_private_key_pem, export_public_key_pem

def main():
    pool_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "rsa_pool")
    os.makedirs(pool_dir, exist_ok=True)
    out_file = os.path.join(pool_dir, "precomputed_32k.json")

    print("[*] Generating 32768-bit RSA key for pool...")
    t0 = time.time()
    priv, pub = generate_rsa_keypair(32768)
    elapsed = time.time() - t0
    print(f"[+] 32768-bit RSA key generated in {elapsed:.2f}s")

    data = {
        "key_size": 32768,
        "priv_pem": export_private_key_pem(priv),
        "pub_pem": export_public_key_pem(pub),
        "gen_time_sec": elapsed,
        "created_at": time.time(),
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Successfully saved pool key to {out_file}")

if __name__ == "__main__":
    main()
