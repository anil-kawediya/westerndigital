#!/usr/bin/env python3
"""
error_edge_cases.py

Simulated test harness for Section 3: Error & Edge Case Handling (macOS simulation).

Scenarios simulated:
 - SA expiration during active I/O (rekey behavior)
 - Key mismatch / authentication failure
 - Packet drop / reorder (netem-like)
 - Partial offload fallback (firmware->software)
 - DMA error injection (simulated cleanup/rollback)

Output CSV: error_edge_cases_results.csv
"""

import csv
import random
import time
from datetime import datetime
import os

CSV_FILE = "error_edge_cases_results.csv"
MODES = ["tunnel", "transport"]
SCENARIOS = [
    "SA Expiration Mid-I/O",
    "Key Mismatch / Auth Failure",
    "Packet Drop/Reorder",
    "Partial Offload Fallback",
    "DMA Error Injection"
]

SIMULATE = True  # always True for macOS simulation

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_row(mode, scenario, result, details):
    write_header = not os.path.exists(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["Timestamp", "Mode", "Scenario", "Result", "Details"])
        writer.writerow([timestamp(), mode, scenario, result, details])

def simulate_sa_expiration():
    # Simulate whether in-flight I/O survives rekey (80% success)
    time.sleep(1)
    survived = random.random() < 0.8
    return survived, "rekey simulated; new SA installed" if survived else "rekey failed mid-IO; some ops retried"

def simulate_key_mismatch():
    time.sleep(0.5)
    # 70% chance device rejects, 30% chance graceful drop
    outcome = random.random()
    if outcome < 0.7:
        return False, "authentication failure; packets dropped"
    else:
        return True, "authentication warned; fallback to software path"

def simulate_packet_drop_reorder():
    time.sleep(0.8)
    # High chance anti-replay holds but reordering causes retransmits (85% pass)
    ok = random.random() < 0.85
    details = "loss=2%, reorder=10%, small retransmits" if ok else "severe loss; retransmit storm"
    return ok, details

def simulate_offload_fallback():
    time.sleep(0.6)
    # Simulate firmware offload fails and driver falls back (95% successful fallback)
    fallback_ok = random.random() < 0.95
    return fallback_ok, "fallback to SW crypto" if fallback_ok else "fallback failed; driver error"

def simulate_dma_error():
    time.sleep(0.5)
    # DMA errors are rare: 5% chance; if occurs, cleanup may succeed 80% of the time
    if random.random() < 0.05:
        cleanup_ok = random.random() < 0.8
        return False, "DMA error occurred; cleanup succeeded" if cleanup_ok else "DMA error occurred; cleanup failed -> potential leak"
    else:
        return True, "no DMA error"

SCENARIO_FUNCTIONS = {
    "SA Expiration Mid-I/O": simulate_sa_expiration,
    "Key Mismatch / Auth Failure": simulate_key_mismatch,
    "Packet Drop/Reorder": simulate_packet_drop_reorder,
    "Partial Offload Fallback": simulate_offload_fallback,
    "DMA Error Injection": simulate_dma_error
}

def run_tests():
    print(f"[{timestamp()}] Starting Error & Edge Case simulations (CSV: {CSV_FILE})")
    for mode in MODES:
        print(f"\n--- Mode: {mode} ---")
        for scenario in SCENARIOS:
            print(f"[{timestamp()}] Running scenario: {scenario}")
            func = SCENARIO_FUNCTIONS[scenario]
            try:
                ok, details = func()
                result = "PASS" if ok else "FAIL"
                print(f"  -> Result: {result}; details: {details}")
                log_row(mode, scenario, result, details)
            except Exception as e:
                print(f"  -> Exception during simulation: {e}")
                log_row(mode, scenario, "ERROR", str(e))
    print(f"[{timestamp()}] Completed Error & Edge Case simulations.")

if __name__ == "__main__":
    run_tests()