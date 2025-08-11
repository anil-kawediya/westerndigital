#!/usr/bin/env python3
"""
performance_resource_handling.py

Simulated test harness for Section 4: Performance & Resource Handling (macOS simulation).

Scenarios simulated:
 - Long-duration throughput consistency (time-series)
 - CPU offload efficiency (compare offload vs software)
 - Firmware resource exhaustion (SA / crypto engine limits)
 - Throughput vs queue depth sweep

Output CSV: perf_resource_results.csv
"""

import csv
import random
import time
from datetime import datetime
import os

CSV_FILE = "perf_resource_results.csv"
MODES = ["tunnel", "transport"]
SCENARIOS = [
    "Throughput Consistency (long-run)",
    "Offload Efficiency (CPU vs SW)",
    "Firmware Resource Exhaustion",
    "Queue Depth Sweep"
]

SIMULATE = True

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_row(mode, scenario, metric_name, metric_value, notes=""):
    write_header = not os.path.exists(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["Timestamp", "Mode", "Scenario", "Metric", "Value", "Notes"])
        writer.writerow([timestamp(), mode, scenario, metric_name, metric_value, notes])

def simulate_long_run(duration_seconds=30):
    """
    Simulate throughput over time; returns list of (t, throughput_MiB_s).
    We'll sample every 5 seconds.
    """
    samples = []
    t = 0
    base = random.uniform(300, 900)  # MB/s baseline
    while t < duration_seconds:
        # simulate occasional dips
        dip = -random.uniform(0, base*0.3) if random.random() < 0.15 else random.uniform(-base*0.05, base*0.05)
        throughput = max(0.0, base + dip)
        samples.append((t, round(throughput, 2)))
        t += 5
        time.sleep(0.1)  # keep test snappy on mac
    return samples

def simulate_offload_efficiency():
    """
    Compare CPU usage: offload (low CPU) vs software (higher CPU).
    Returns dict with throughput and cpu percentages.
    """
    throughput = random.uniform(400, 1000)
    cpu_offload = random.uniform(5, 20)   # %
    cpu_software = cpu_offload + random.uniform(30, 60)
    return {"throughput": round(throughput,2), "cpu_offload": round(cpu_offload,2), "cpu_software": round(cpu_software,2)}

def simulate_resource_exhaustion():
    """
    Simulate firmware running out of 'SA slots' or crypto contexts.
    Returns whether graceful handling occurred and number of rejected sessions.
    """
    total_requests = random.randint(50, 500)
    # chance of exhaustion
    exhausted = random.random() < 0.25
    rejected = random.randint(0, total_requests//4) if exhausted else 0
    handled_gracefully = random.random() < 0.8
    return exhausted, rejected, handled_gracefully

def simulate_queue_depth_sweep():
    """
    Sweep queue depths and show IOPS/latency tradeoff (simulated).
    Return list of (qdepth, iops, latency_ms)
    """
    results = []
    for q in [1, 4, 8, 16, 32, 64]:
        base_iops = random.uniform(5000, 200000)
        iops = max(100, base_iops * (1 - (q/200)))  # arbitrary curve
        latency = max(0.1, random.uniform(0.1, 5.0) * (q/8))
        results.append((q, round(iops), round(latency,2)))
        time.sleep(0.05)
    return results

def run_tests():
    print(f"[{timestamp()}] Starting Performance & Resource Handling simulations (CSV: {CSV_FILE})")
    for mode in MODES:
        print(f"\n--- Mode: {mode} ---")
        # 1) long-run throughput consistency
        print(f"[{timestamp()}] Scenario: Throughput Consistency (sampling)")
        samples = simulate_long_run(duration_seconds=20)
        for t, th in samples:
            log_row(mode, "Throughput Consistency (long-run)", f"throughput_sample_t{t}s_MBps", th)
        avg_throughput = sum(s for _, s in samples)/len(samples)
        log_row(mode, "Throughput Consistency (long-run)", "average_throughput_MBps", round(avg_throughput,2),
                notes="simulated baseline and random dips")

        # 2) offload efficiency
        print(f"[{timestamp()}] Scenario: Offload Efficiency")
        off = simulate_offload_efficiency()
        log_row(mode, "Offload Efficiency (CPU vs SW)", "throughput_MBps", off["throughput"])
        log_row(mode, "Offload Efficiency (CPU vs SW)", "cpu_offload_pct", off["cpu_offload"])
        log_row(mode, "Offload Efficiency (CPU vs SW)", "cpu_software_pct", off["cpu_software"],
                notes="higher CPU when using software crypto")

        # 3) firmware resource exhaustion
        print(f"[{timestamp()}] Scenario: Firmware Resource Exhaustion")
        exhausted, rejected, handled = simulate_resource_exhaustion()
        log_row(mode, "Firmware Resource Exhaustion", "exhausted", exhausted, notes=f"rejected={rejected}, handled_gracefully={handled}")

        # 4) queue depth sweep
        print(f"[{timestamp()}] Scenario: Queue Depth Sweep")
        sweep = simulate_queue_depth_sweep()
        for q, iops, lat in sweep:
            log_row(mode, "Queue Depth Sweep", f"q{q}_iops", iops, notes=f"lat_ms={lat}")
    print(f"[{timestamp()}] Completed Performance & Resource simulations.")

if __name__ == "__main__":
    run_tests()