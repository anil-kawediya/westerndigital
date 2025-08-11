#!/usr/bin/env python3

"""
What it simulates
- Tunnel vs Transport mode
- Multiple ESP cipher suites (simulated AES-GCM, AES-CBC+HMAC, ChaCha20-Poly1305)
- IKE (SA) negotiation and rekey events (asymmetric handshake delays are optionally simulated)
- Inbound vs outbound flows (read-after-write verification simulated)
- Anti-replay behavior under packet loss/reorder (simulated effects)
- SA lifetime expiry and rekey during active I/O
- Produces a CSV with structured results and prints progress logs
- Simulated Basic Protocol IPsec tests (Tunnel vs Transport + ESP suites + IKE algs)
How to run:
- Edit SIM_PARAMS at top or pass command-line flags (script includes CLI flags) to change data size, runtime, or random seed.
Usage:
    ipsec_protocol_sim.py --data-size 200 --seed 123 --output-csv ipsec_protocol.csv
"""

import argparse
import csv
import json
import random
import time
from datetime import datetime
import os
import math

# Defaults
DEFAULTS = {
    "esp_map": {
        "AES-GCM-128": {"throughput":600},
        "AES-CBC-HMAC-SHA256": {"throughput":420},
        "ChaCha20-Poly1305": {"throughput":520}
    },
    "ike_algs": {
        "ECDSA-P256": 0.3,
        "RSA-2048": 0.8
    },
    "modes": ["tunnel","transport"],
    "data_size_mb": 200,
    "seed": None,
    "rekey_delay_s": 8,
    "fail_rate_base": 0.05,
    "output_csv": "ipsec_protocol_results.csv",
    "summary_json": "ipsec_protocol_summary.json"
}

CSV_FIELDS = ["timestamp","mode","ike_alg","esp_alg","data_mb","handshake_s","encrypt_s","rekey_happened","rekey_success","loss_pct","reorder_pct","io_result","throughput_MBps"]

# Utilities
def now_ts():
    return datetime.now().isoformat()

def write_csv_rows(path, rows):
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        for r in rows:
            writer.writerow(r)

def aggregate_summary(rows, out_json):
    stats = {}
    for r in rows:
        key = (r["mode"], r["ike_alg"], r["esp_alg"])
        kstr = "|".join(key)
        stats.setdefault(kstr, {"count":0,"total_tp":0.0,"min_tp":math.inf,"max_tp":0.0,"passes":0})
        stats[kstr]["count"] += 1
        tp = float(r["throughput_MBps"])
        stats[kstr]["total_tp"] += tp
        stats[kstr]["min_tp"] = min(stats[kstr]["min_tp"], tp)
        stats[kstr]["max_tp"] = max(stats[kstr]["max_tp"], tp)
        if r["io_result"] == "PASS":
            stats[kstr]["passes"] += 1
    out = {}
    for k,v in stats.items():
        mode, ike, esp = k.split("|")
        out.setdefault(mode, {})
        out[mode].setdefault(ike, {})
        out[mode][ike][esp] = {
            "count": v["count"],
            "pass_rate": round(v["passes"]/v["count"], 3),
            "avg_throughput_MBps": round(v["total_tp"]/v["count"], 3),
            "min_throughput_MBps": round(v["min_tp"], 3),
            "max_throughput_MBps": round(v["max_tp"], 3)
        }
    with open(out_json, "w") as f:
        json.dump(out, f, indent=2)
    return out

def print_pretty_summary(summary):
    print("\n=== Protocol Simulation Summary ===")
    for mode, ike_map in summary.items():
        print(f"\nMode: {mode}")
        for ike_alg, esp_map in ike_map.items():
            for esp_alg, s in esp_map.items():
                print(f"  IKE={ike_alg:12s} | ESP={esp_alg:20s} | pass_rate={s['pass_rate']*100:5.1f}% | avg_tp={s['avg_throughput_MBps']:7.2f} MB/s")

# Simulation helpers
def simulate_ike_handshake(alg_delay_map, alg, handshake_scale=1.0):
    base = alg_delay_map.get(alg, 0.5)
    jitter = random.uniform(-0.15*base, 0.15*base)
    t = max(0.01, (base*handshake_scale)+jitter)
    time.sleep(min(t, 1.2))
    return round(t,3)

def simulate_encrypt(esp_map, esp_alg, data_mb, throttle=1.0):
    throughput = esp_map.get(esp_alg, {}).get("throughput", 300) * throttle
    t = data_mb / throughput
    jitter = random.uniform(-0.03*t, 0.05*t)
    total = max(0.001, t + jitter)
    time.sleep(min(total, 2.5))
    return round(total,3)

def simulate_rekey_chance():
    # 90% success probability by default
    succ = random.random() < 0.9
    return succ

def simulate_io_verify(base_fail_rate, rekey_success, loss_pct, reorder_pct):
    fail_rate = base_fail_rate
    # worsen if rekey failed
    if not rekey_success:
        fail_rate += 0.25
    # worsen with loss/reorder
    fail_rate += min(0.25, loss_pct / 10.0) + min(0.1, reorder_pct / 100.0)
    ok = random.random() > fail_rate
    return ok, round(fail_rate, 3)

# Orchestrator
def run_simulation(args):
    if args.seed is not None:
        random.seed(args.seed)
    else:
        random.seed()

    esp_map = DEFAULTS["esp_map"]
    ike_map = DEFAULTS["ike_algs"]
    modes = DEFAULTS["modes"]
    rows = []

    for mode in modes:
        for ike_alg in ike_map.keys():
            for esp_alg in esp_map.keys():
                handshake = simulate_ike_handshake(ike_map, ike_alg, handshake_scale=args.handshake_scale)
                # simulate encrypt part; reflect splitting around rekey (but we approximate)
                encrypt = simulate_encrypt(esp_map, esp_alg, args.data_size, throttle=args.throttle)
                # simulate rekey
                rekey = simulate_rekey_chance()
                loss = args.loss_pct
                reorder = args.reorder_pct
                ok, effective_fail_rate = simulate_io_verify(args.fail_rate, rekey, loss, reorder)
                total = round(handshake + encrypt, 3)
                tp = round(args.data_size / total, 3) if total>0 else 0.0
                row = {
                    "timestamp": now_ts(),
                    "mode": mode,
                    "ike_alg": ike_alg,
                    "esp_alg": esp_alg,
                    "data_mb": args.data_size,
                    "handshake_s": handshake,
                    "encrypt_s": encrypt,
                    "rekey_happened": True,
                    "rekey_success": rekey,
                    "loss_pct": loss,
                    "reorder_pct": reorder,
                    "io_result": "PASS" if ok else "FAIL",
                    "throughput_MBps": tp
                }
                rows.append(row)
                print(f"[{now_ts()}] {mode} | IKE={ike_alg} | ESP={esp_alg} -> {row['io_result']} tp={tp}MB/s (fail_rate~{effective_fail_rate})")

    write_csv_rows(args.output_csv, rows)
    summary = aggregate_summary(rows, args.summary_json)
    print_pretty_summary(summary)
    print(f"\nWrote {len(rows)} rows to {args.output_csv} and summary to {args.summary_json}")

# CLI
def parse_args():
    p = argparse.ArgumentParser(description="Simulated IPsec Basic Protocol tests (macOS-friendly, enhanced)")
    p.add_argument("--data-size", type=int, default=DEFAULTS["data_size_mb"], help="Data size MB to simulate")
    p.add_argument("--seed", type=int, default=DEFAULTS["seed"], help="Random seed")
    p.add_argument("--handshake-scale", type=float, default=1.0, help="Scale factor for IKE handshake times")
    p.add_argument("--throttle", type=float, default=1.0, help="Throttle factor for symmetric throughput")
    p.add_argument("--loss-pct", type=float, default=0.0, help="Simulated packet loss percent for anti-replay scenario")
    p.add_argument("--reorder-pct", type=float, default=0.0, help="Simulated packet reorder percent")
    p.add_argument("--fail-rate", type=float, default=DEFAULTS["fail_rate_base"], help="Base failure rate for IO verification")
    p.add_argument("--output-csv", default=DEFAULTS["output_csv"], help="CSV output file")
    p.add_argument("--summary-json", default=DEFAULTS["summary_json"], help="Summary JSON output file")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_simulation(args)
