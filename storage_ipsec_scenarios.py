#!/usr/bin/env python3

"""
storage_nvme_tests.py

Real storage tests for NVMe (local namespace OR NVMe over TCP) with fio.
Covers:
- Basic randrw verify (io_uring)
- Misaligned buffers (offset/buffer alignment)
- Scatter/gather behavior (variable block sizes, higher queue depths)
- Queue-depth sweep
- Large sequential throughput

Prereqs:
  sudo apt-get install -y nvme-cli fio
Run examples:
  # Local device already present (/dev/nvme0n1), existing filesystem:
  sudo ./storage_nvme_tests.py --device /dev/nvme0n1 --mount /mnt/nvme_test

  # NVMe/TCP connect (destructive mkfs):
  sudo ./storage_nvme_tests.py --nvme-tcp --nqn nqn.2014-08.org.nvmexpress:uuid:1234 \
       --traddr 192.168.1.50 --trsvcid 4420 --mount /mnt/nvme_test --mkfs
"""

import argparse, os, shlex, subprocess, sys, time, json, re

# ---------- helpers ----------
def run(cmd, check=True, capture=True):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    res = subprocess.run(cmd, check=check, text=True,
                         capture_output=capture)
    return res.stdout if capture else ""

def ensure_root():
    if os.geteuid() != 0:
        sys.exit("This script must be run as root (sudo).")

def info(msg): print(f"[INFO] {msg}")
def warn(msg): print(f"[WARN] {msg}")
def err(msg):  print(f"[ERR ] {msg}")

# ---------- nvme discovery/connect ----------
def nvme_list():
    out = run(["nvme", "list"])
    return out

def find_namespace_for_nqn(nqn):
    # Parse `nvme list` and match the NQN in the "Subsystem NQN" column (nvme-cli prints it per controller)
    out = nvme_list()
    # try a quick heuristic: after a device line, look ahead for "Subsystem NQN"
    dev = None
    lines = out.splitlines()
    devs = []
    current = {}
    for ln in lines:
        m = re.match(r"^(/dev/nvme\dn\d)\s+", ln)
        if m:
            # start of a device row
            dev = m.group(1)
            current = {"dev": dev}
            devs.append(current)
        if "Subsystem NQN" in ln and current:
            current["nqn"] = ln.split(":", 1)[-1].strip()
    for d in devs:
        if d.get("nqn") and nqn in d["nqn"]:
            return d["dev"]
    return None

def nvme_connect_tcp(nqn, traddr, trsvcid="4420",	hostnqn=None, retries=10, wait_s=1.0):
    cmd = ["nvme", "connect", "-t", "tcp", "-a", traddr, "-s", str(trsvcid), "-n", nqn]
    if hostnqn:
        cmd += ["-q", hostnqn]
    info(f"Connecting NVMe/TCP: {' '.join(cmd)}")
    run(cmd, capture=False)
    # Wait for device to appear
    for _ in range(retries):
        dev = find_namespace_for_nqn(nqn)
        if dev:
            info(f"Connected: {dev} for NQN {nqn}")
            return dev
        time.sleep(wait_s)
    raise RuntimeError("NVMe/TCP device not found after connect")

def nvme_disconnect(dev_or_nqn):
    # Accept either a controller/device or nqn; use broad disconnect to be safe
    try:
        run(["nvme", "disconnect", "-n", dev_or_nqn], capture=False)
    except subprocess.CalledProcessError:
        pass

# ---------- filesystem & mount ----------
def mkfs(device, fstype="ext4", label="nvmetest"):
    warn(f"Making filesystem ({fstype}) on {device} (DESTRUCTIVE).")
    if fstype == "ext4":
        run(["mkfs.ext4", "-F", "-L", label, device], capture=False)
    elif fstype == "xfs":
        run(["mkfs.xfs", "-f", "-L", label, device], capture=False)
    else:
        raise ValueError("Unsupported fstype (use ext4 or xfs)")

def mount_fs(device, mountpoint, fstype=None, opts="noatime,nodiratime"):
    os.makedirs(mountpoint, exist_ok=True)
    cmd = ["mount", "-o", opts, device, mountpoint] if not fstype else \
          ["mount", "-t", fstype, "-o", opts, device, mountpoint]
    info(f"Mount: {' '.join(cmd)}")
    run(cmd, capture=False)

def umount_fs(mountpoint):
    try:
        run(["umount", "-f", mountpoint], capture=False)
    except subprocess.CalledProcessError:
        pass

# ---------- fio wrappers ----------
def fio_cmd(base):
    return shlex.split(base)

def fio_run(cmd):
    """
    Run fio with --output-format=json and return parsed dict plus a compact summary tuple.
    """
    if "--output-format=json" not in cmd:
        cmd += ["--output-format=json"]
    info("fio: " + " ".join(cmd))
    out = run(cmd)
    data = json.loads(out)
    # Pull a compact summary from the first job
    j = data["jobs"][0]
    rw = j.get("job options", {}).get("rw", "unknown")
    read_bw = j["read"]["bw"] if "read" in j else 0
    write_bw = j["write"]["bw"] if "write" in j else 0
    read_iops = j["read"]["iops"] if "read" in j else 0
    write_iops = j["write"]["iops"] if "write" in j else 0
    return data, (rw, read_bw, write_bw, read_iops, write_iops)

def kbps_to_str(kbps):
    # fio reports BW (KB/s). Convert to MB/s.
    return f"{kbps/1024:.1f} MB/s"

# ---------- scenarios ----------
def scenario_basic_randrw(mountpoint, size="4G"):
    """
    Basic correctness under encryption/storage stack:
      - ioengine=io_uring
      - 4k random read/write, verify data
    """
    path = os.path.join(mountpoint, "basic_randrw.bin")
    cmd = [
        "fio",
        f"--name=basic",
        f"--filename={path}",
        "--rw=randrw",
        "--bs=4k",
        f"--size={size}",
        "--ioengine=io_uring",
        "--iodepth=32",
        "--numjobs=4",
        "--direct=1",
        "--time_based=1",
        "--runtime=45",
        "--verify=crc32",
        "--verify_fatal=1",
        "--group_reporting"
    ]
    return fio_run(cmd)

def scenario_misaligned(mountpoint, size="2G"):
    """
    Misaligned buffers & offsets:
      - offset=1 (forces misalignment)
      - buffer_align=3 (odd alignment)
    """
    path = os.path.join(mountpoint, "misaligned.bin")
    cmd = [
        "fio",
        "--name=misaligned",
        f"--filename={path}",
        "--rw=randwrite",
        "--bs=4k",
        f"--size={size}",
        "--ioengine=io_uring",
        "--iodepth=16",
        "--direct=1",
        "--verify=crc32",
        "--verify_fatal=1",
        "--group_reporting",
        "--offset=1",
        "--buffer_align=3"
    ]
    return fio_run(cmd)

def scenario_scatter_gather(mountpoint, size="4G"):
    """
    Exercise scatter/gather via:
      - Variable block sizes (4k..256k)
      - Higher iodepth + multiple jobs
    """
    path = os.path.join(mountpoint, "sg.bin")
    cmd = [
        "fio",
        "--name=sg",
        f"--filename={path}",
        "--rw=randrw",
        "--bsrange=4k-256k",
        f"--size={size}",
        "--ioengine=io_uring",
        "--iodepth=64",
        "--numjobs=4",
        "--direct=1",
        "--time_based=1",
        "--runtime=60",
        "--verify=crc32",
        "--verify_fatal=1",
        "--group_reporting"
    ]
    return fio_run(cmd)

def scenario_qd_sweep(mountpoint, size="2G"):
    """
    Sweep queue depth to see IOPS/latency tradeoffs.
    """
    summaries = []
    for qd in [1, 4, 8, 16, 32, 64]:
        path = os.path.join(mountpoint, f"qd{qd}.bin")
        cmd = [
            "fio",
            f"--name=qd{qd}",
            f"--filename={path}",
            "--rw=randread",
            "--bs=4k",
            f"--size={size}",
            "--ioengine=io_uring",
            f"--iodepth={qd}",
            "--numjobs=1",
            "--direct=1",
            "--time_based=1",
            "--runtime=20",
            "--group_reporting"
        ]
        data, summary = fio_run(cmd)
        summaries.append((qd, summary))
    return summaries

def scenario_large_seq(mountpoint, size="8G"):
    """
    Large sequential throughput test (read & write).
    """
    path = os.path.join(mountpoint, "large_seq.bin")
    cmd = [
        "fio",
        "--name=large_seq",
        f"--filename={path}",
        "--rw=readwrite",
        "--rwmixread=50",
        "--bs=256k",
        f"--size={size}",
        "--ioengine=io_uring",
        "--iodepth=32",
        "--numjobs=2",
        "--direct=1",
        "--time_based=1",
        "--runtime=60",
        "--group_reporting"
    ]
    return fio_run(cmd)

# ---------- main ----------
def main():
    ensure_root()
    ap = argparse.ArgumentParser(description="NVMe storage tests with fio (real, Linux-only).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--device", help="Existing local NVMe namespace device, e.g., /dev/nvme0n1")
    g.add_argument("--nvme-tcp", action="store_true", help="Connect to NVMe over TCP target")

    ap.add_argument("--nqn", help="NVMe/TCP NQN (required with --nvme-tcp)")
    ap.add_argument("--traddr", help="NVMe/TCP target IP/host (required with --nvme-tcp)")
    ap.add_argument("--trsvcid", default="4420", help="NVMe/TCP service (port), default 4420")
    ap.add_argument("--hostnqn", help="Optional host NQN override")

    ap.add_argument("--mount", required=True, help="Mount point directory, e.g., /mnt/nvme_test")
    ap.add_argument("--mkfs", action="store_true", help="Make filesystem on device (DESTRUCTIVE). If omitted, expects already formatted.")
    ap.add_argument("--fstype", default="ext4", choices=["ext4","xfs"], help="Filesystem type for --mkfs")

    ap.add_argument("--skip-basic", action="store_true")
    ap.add_argument("--skip-misaligned", action="store_true")
    ap.add_argument("--skip-sg", action="store_true")
    ap.add_argument("--skip-qd", action="store_true")
    ap.add_argument("--skip-seq", action="store_true")

    args = ap.parse_args()

    dev = None
    connected_nqn = None
    try:
        if args.nvme_tcp:
            if not (args.nqn and args.traddr):
                sys.exit("--nqn and --traddr are required with --nvme-tcp")
            dev = nvme_connect_tcp(args.nqn, args.traddr, args.trsvcid, args.hostnqn)
            connected_nqn = args.nqn
        else:
            dev = args.device
            if not os.path.exists(dev):
                sys.exit(f"Device not found: {dev}")

        if args.mkfs:
            mkfs(dev, fstype=args.fstype)

        mount_fs(dev, args.mount)

        print("\n================ RUNNING TESTS ================\n")

        if not args.skip_basic:
            info("Scenario: basic randrw verify")
            data, (rw, rbw, wbw, riops, wiops) = scenario_basic_randrw(args.mount)
            print(f"  rw={rw}  R={kbps_to_str(rbw)}  W={kbps_to_str(wbw)}  RIOPS={int(riops)}  WIOPS={int(wiops)}")

        if not args.skip_misaligned:
            info("Scenario: misaligned buffers/offset")
            data, (rw, rbw, wbw, riops, wiops) = scenario_misaligned(args.mount)
            print(f"  rw={rw}  W={kbps_to_str(wbw)}  WIOPS={int(wiops)} (verify on)")

        if not args.skip_sg:
            info("Scenario: scatter/gather (variable bs, higher depth)")
            data, (rw, rbw, wbw, riops, wiops) = scenario_scatter_gather(args.mount)
            print(f"  rw={rw}  R={kbps_to_str(rbw)}  W={kbps_to_str(wbw)}  RIOPS={int(riops)}  WIOPS={int(wiops)}")

        if not args.skip_qd:
            info("Scenario: queue depth sweep (4k randread)")
            summaries = scenario_qd_sweep(args.mount)
            for qd, (rw, rbw, wbw, riops, wiops) in summaries:
                print(f"  qd={qd:>2}  R={kbps_to_str(rbw)}  RIOPS={int(riops)}")

        if not args.skip_seq:
            info("Scenario: large sequential read/write")
            data, (rw, rbw, wbw, riops, wiops) = scenario_large_seq(args.mount)
            print(f"  rw={rw}  R={kbps_to_str(rbw)}  W={kbps_to_str(wbw)}")

        print("\n================   DONE   =====================\n")

    except Exception as e:
        err(str(e))
        sys.exit(2)
    finally:
        # Always try to unmount
        try:
            umount_fs(args.mount)
        except Exception:
            pass
        # Disconnect NVMe/TCP if used
        if connected_nqn:
            try:
                nvme_disconnect(connected_nqn)
            except Exception:
                pass

if __name__ == "__main__":
    main()


"""
Section #2: Storage I/O Specific Scenarios (Simulation Mode)

These are functional, not just performance-based. The goal is to make sure encryption doesn’t break fundamental storage workflows.

Key scenarios we should script:
	1.	Basic I/O Read/Write Test under IPsec (tunnel & transport modes).
	2.	Mixed I/O Pattern: random/sequential, small/large block sizes.
	3.	Filesystem Operations: create, delete, rename, sync files under encryption.
	4.	Firmware Stress Trigger: force firmware cache flush and verify data consistency.
	5.	Error Injection: simulate storage disconnect or packet loss, verify graceful recovery.


import csv
import random
import time
from datetime import datetime

# Config
simulate = True  # Set to False on Linux real run
modes = ["tunnel", "transport"]
scenarios = [
    "Basic Read/Write I/O",
    "Mixed I/O Patterns",
    "Filesystem Operations",
    "Firmware Cache Flush",
    "Error Injection / Recovery"
]

log_file = "storage_ipsec_results.csv"

def log_result(mode, scenario, iops, latency_ms, status):
    """Log test result to CSV"""
    with open(log_file, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now(), mode, scenario, iops, latency_ms, status])

def simulate_io_test(scenario):
    """Simulate storage I/O test results"""
    time.sleep(1)  # pretend we're running a test
    iops = random.randint(5000, 150000)
    latency_ms = round(random.uniform(0.2, 10.0), 2)
    status = "PASS" if random.random() > 0.1 else "FAIL"  # 10% failure chance
    return iops, latency_ms, status

def run_storage_tests():
    """Main test loop for all modes and scenarios"""
    # Write CSV header
    with open(log_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Mode", "Scenario", "IOPS", "Latency(ms)", "Status"])
    
    for mode in modes:
        print(f"\n=== Testing in {mode.upper()} mode ===")
        for scenario in scenarios:
            print(f"Running scenario: {scenario}")
            if simulate:
                iops, latency_ms, status = simulate_io_test(scenario)
            else:
                # TODO: Replace with real Linux commands for storage I/O
                raise NotImplementedError("Real mode not implemented in simulation script.")
            
            print(f"  Result: {status}, IOPS={iops}, Latency={latency_ms} ms")
            log_result(mode, scenario, iops, latency_ms, status)

if __name__ == "__main__":
    run_storage_tests()
    print(f"\nAll results logged to {log_file}")

    
"""
    
  