"""
    Simulated Symmetric vs Asymmetric Crypto for IPsec

    1. Simulates IKE asymmetric crypto (RSA, ECDSA).
	2.	Simulates ESP symmetric crypto (AES-GCM, ChaCha20-Poly1305).
	3.	Measures “handshake” time (asymmetric-heavy) vs. “data transfer” time (symmetric-heavy) in simulation mode.
	4.	Works similarly to the Basic Protocol Testing script we did earlier, but without requiring root/IPsec kernel configuration.
	5.	Lets you run tunnel vs. transport mode variants too.
"""


import time
import random
import csv
from datetime import datetime

# -----------------------------
# Simulation parameters
# -----------------------------
ASYM_CRYPTO_HANDSHAKE = {
    "RSA-2048": 0.8,      # seconds
    "RSA-4096": 1.6,
    "ECDSA-P256": 0.3,
    "ECDSA-P384": 0.5
}

SYM_CRYPTO_SPEED_MBPS = {
    "AES-GCM-128": 500,   # MB/sec simulated
    "AES-GCM-256": 450,
    "ChaCha20-Poly1305": 480
}

IPSEC_MODES = ["Tunnel", "Transport"]

# -----------------------------
# Simulated encryption workload
# -----------------------------
def simulate_symmetric_encryption(crypto_algo, data_size_mb):
    """Simulate encryption time based on throughput."""
    speed = SYM_CRYPTO_SPEED_MBPS[crypto_algo]
    encrypt_time = data_size_mb / speed
    time.sleep(encrypt_time)
    return encrypt_time

def simulate_asymmetric_handshake(crypto_algo):
    """Simulate handshake/auth delay."""
    delay = ASYM_CRYPTO_HANDSHAKE[crypto_algo]
    time.sleep(delay)
    return delay

# -----------------------------
# Main simulation
# -----------------------------
def run_simulation(data_size_mb=100):
    results = []
    for mode in IPSEC_MODES:
        for ike_crypto in ASYM_CRYPTO_HANDSHAKE.keys():
            for esp_crypto in SYM_CRYPTO_SPEED_MBPS.keys():
                print(f"\n[TEST] Mode: {mode}, IKE: {ike_crypto}, ESP: {esp_crypto}")

                handshake_time = simulate_asymmetric_handshake(ike_crypto)
                encrypt_time = simulate_symmetric_encryption(esp_crypto, data_size_mb)

                total_time = handshake_time + encrypt_time
                throughput_mbps = data_size_mb / total_time

                print(f"  Handshake Time: {handshake_time:.3f}s")
                print(f"  Encrypt Time: {encrypt_time:.3f}s for {data_size_mb} MB")
                print(f"  Total Time: {total_time:.3f}s")
                print(f"  Throughput: {throughput_mbps:.2f} MB/s")

                results.append({
                    "timestamp": datetime.now().isoformat(),
                    "mode": mode,
                    "ike_crypto": ike_crypto,
                    "esp_crypto": esp_crypto,
                    "data_size_mb": data_size_mb,
                    "handshake_time_s": handshake_time,
                    "encrypt_time_s": encrypt_time,
                    "total_time_s": total_time,
                    "throughput_MBps": throughput_mbps
                })

    save_results(results)

# -----------------------------
# Save results
# -----------------------------
def save_results(results, filename="ipsec_crypto_results.csv"):
    keys = results[0].keys()
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[INFO] Results saved to {filename}")

# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    run_simulation(data_size_mb=200)  # You can change test size here