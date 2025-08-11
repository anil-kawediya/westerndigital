#!/usr/bin/env python3

"""
    Simulated Symmetric vs Asymmetric Crypto for IPsec

    1.  Simulates IKE asymmetric crypto (RSA, ECDSA).
	2.	Simulates ESP symmetric crypto (AES-GCM, ChaCha20-Poly1305).
	3.	Measures “handshake” time (asymmetric-heavy) vs. “data transfer” time (symmetric-heavy) in simulation mode.
	4.	Works similarly to the Basic Protocol Testing script we did earlier, but without requiring root/IPsec kernel configuration.
	5.	Lets you run tunnel vs. transport mode variants too.
    Simulates asymmetric (IKE) and symmetric (ESP) crypto effects for IPsec.
    Produces per-test CSV and summary JSON, and prints a pretty table.

Usage:
    ipsec_crypto_sim.py --data-size 200 --seed 42 --output-csv ipsec_crypto.csv
    ipsec_crypto_sim.py --data-size 300 --seed 42 --handshake-factor 1.1 --throttle-factor 0.9
"""

import argparse
import csv
import json
import random
import time
from datetime import datetime
import os
import math

# Default parameters (can be overridden via CLI)
DEFAULTS = {
    "asyms": {
        "RSA-2048": 0.8,
        "RSA-4096": 1.6,
        "ECDSA-P256": 0.3,
        "ECDSA-P384": 0.5
    },
    "syms": {
        "AES-GCM-128": 500,      # MB/s
        "AES-GCM-256": 450,
        "ChaCha20-Poly1305": 480
    },
    "modes": ["Tunnel", "Transport"],
    "data_size_mb": 200,
    "seed": None,
    "output_csv": "ipsec_crypto_results.csv",
    "summary_json": "ipsec_crypto_summary.json"
}

# ---------------------------------------
# Simulation primitives
# ---------------------------------------
def now_ts():
    return datetime.now().isoformat()

def simulate_handshake(alg, base_map, handshake_factor=1.0):
    """Return simulated handshake time (seconds)."""
    base = base_map.get(alg, 0.5)
    # factor may be used to scale handshake times globally
    jitter = random.uniform(-0.1 * base, 0.1 * base)
    t = max(0.01, (base * handshake_factor) + jitter)
    # keep it snappy
    time.sleep(min(t, 1.2))
    return round(t, 3)

def simulate_encrypt_time(alg, sym_map, data_mb, throttle_factor=1.0):
    """Return simulated symmetric encryption time (seconds) for data_mb."""
    throughput = sym_map.get(alg, 300) * throttle_factor  # MB/s
    t = data_mb / throughput
    jitter = random.uniform(-0.03 * t, 0.05 * t)
    total = max(0.001, t + jitter)
    time.sleep(min(total, 2.5))
    return round(total, 3)

# ---------------------------------------
# Results helpers
# ---------------------------------------
CSV_FIELDS = ["timestamp","mode","ike_alg","esp_alg","data_mb","handshake_s","encrypt_s","total_s","throughput_MBps"]

def write_csv_rows(path, rows):
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        for r in rows:
            writer.writerow(r)

def aggregate_summary(rows, out_json):
    # Aggregate by ike_alg+esp_alg+mode
    stats = {}
    for r in rows:
        key = (r["mode"], r["ike_alg"], r["esp_alg"])
        kstr = "|".join(key)
        stats.setdefault(kstr, {"count":0, "total_time":0.0, "total_throughput":0.0, "min_throughput":math.inf, "max_throughput":0.0})
        stats[kstr]["count"] += 1
        stats[kstr]["total_time"] += float(r["total_s"])
        stats[kstr]["total_throughput"] += float(r["throughput_MBps"])
        tp = float(r["throughput_MBps"])
        stats[kstr]["min_throughput"] = min(stats[kstr]["min_throughput"], tp)
        stats[kstr]["max_throughput"] = max(stats[kstr]["max_throughput"], tp)
    # Convert to nice JSON structure
    out = {}
    for k, v in stats.items():
        mode, ike, esp = k.split("|")
        out.setdefault(mode, {})
        out[mode].setdefault(ike, {})
        out[mode][ike][esp] = {
            "count": v["count"],
            "avg_time_s": round(v["total_time"]/v["count"], 3),
            "avg_throughput_MBps": round(v["total_throughput"]/v["count"], 3),
            "min_throughput_MBps": round(v["min_throughput"], 3),
            "max_throughput_MBps": round(v["max_throughput"], 3)
        }
    with open(out_json, "w") as f:
        json.dump(out, f, indent=2)
    return out

def print_pretty_summary(summary):
    print("\n=== Simulation Summary ===")
    for mode, ike_map in summary.items():
        print(f"\nMode: {mode}")
        for ike_alg, esp_map in ike_map.items():
            for esp_alg, s in esp_map.items():
                print(f"  IKE={ike_alg:12s} | ESP={esp_alg:20s} | avg_tp={s['avg_throughput_MBps']:8.2f} MB/s | avg_time={s['avg_time_s']:6.3f}s | n={s['count']}")

# ---------------------------------------
# Orchestrator
# ---------------------------------------
def run_simulation(args):
    # Configure RNG
    if args.seed is not None:
        random.seed(args.seed)
    else:
        random.seed()

    asym_map = DEFAULTS["asyms"]
    sym_map = DEFAULTS["syms"]
    modes = DEFAULTS["modes"]

    rows = []
    for mode in modes:
        for ike_alg in asym_map.keys():
            for esp_alg in sym_map.keys():
                handshake = simulate_handshake(ike_alg, asym_map, handshake_factor=args.handshake_factor)
                encrypt = simulate_encrypt_time(esp_alg, sym_map, args.data_size, throttle_factor=args.throttle_factor)
                total = round(handshake + encrypt, 3)
                throughput = round(args.data_size / total, 3) if total > 0 else 0.0
                row = {
                    "timestamp": now_ts(),
                    "mode": mode,
                    "ike_alg": ike_alg,
                    "esp_alg": esp_alg,
                    "data_mb": args.data_size,
                    "handshake_s": handshake,
                    "encrypt_s": encrypt,
                    "total_s": total,
                    "throughput_MBps": throughput
                }
                rows.append(row)
                print(f"[{now_ts()}] mode={mode} IKE={ike_alg} ESP={esp_alg} total_s={total} tp={throughput}MB/s")
    # write CSV
    write_csv_rows(args.output_csv, rows)
    # generate summary JSON and print
    summary = aggregate_summary(rows, args.summary_json)
    print_pretty_summary(summary)
    print(f"\nWrote {len(rows)} rows to {args.output_csv} and summary to {args.summary_json}")

# ---------------------------------------
# CLI
# ---------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="IPSec crypto sim (asymmetric vs symmetric) - macOS simulation")
    p.add_argument("--data-size", type=int, default=DEFAULTS["data_size_mb"], help="Data size in MB for encryption simulation")
    p.add_argument("--seed", type=int, default=DEFAULTS["seed"], help="Random seed (optional)")
    p.add_argument("--output-csv", default=DEFAULTS["output_csv"], help="CSV output file")
    p.add_argument("--summary-json", default=DEFAULTS["summary_json"], help="Summary JSON output file")
    p.add_argument("--handshake-factor", type=float, default=1.0, help="Scale factor to multiply handshake times (simulates slower/faster IKE)")
    p.add_argument("--throttle-factor", type=float, default=1.0, help="Scale factor to multiply symmetric throughput (simulate loaded crypto engine)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_simulation(args)