#!/usr/bin/env python3
"""
performance_resource_linux.py

Section 4: Performance & Resource Handling (real Linux).
Runs fio workloads against a mounted path, captures CPU utilization, IPsec stats,
and optional NIC stats, and writes results to CSV.

Scenarios:
  - seq_throughput : large sequential read/write throughput
  - qd_sweep       : 4k random read IOPS vs iodepth sweep
  - bs_sweep       : throughput across block sizes
  - longevity      : long-duration mixed I/O to shake out leaks

CSV output: perf_results.csv

Example runs:
  # Run all with NIC stats
  sudo ./performance_resource_linux.py --mount /mnt/nvme_test --iface eth0

  # Just QD sweep, dry-run preview
  sudo ./performance_resource_linux.py --mount /mnt/nvme_test --only qd_sweep --dry-run

  # Longer longevity run (10 minutes)
  sudo ./performance_resource_linux.py --mount /mnt/nvme_test --only longevity --longevity-runtime 600
"""

import argparse, csv, json, os, shlex, subprocess, sys, time
from datetime import datetime

CSV_FILE = "perf_results.csv"

# -------------------- helpers --------------------

def run(cmd, check=True, capture=True, dry=False):
    """
    Execute a shell command with optional dry-run.

    Example final command:
      ip -s xfrm state show
    """
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    printable = " ".join(cmd)
    if dry:
        print(f"[DRY] {printable}")
        return ""
    res = subprocess.run(cmd, text=True, check=check, capture_output=capture)
    return res.stdout if capture else ""

def ensure_root():
    if os.geteuid() != 0:
        sys.exit("Run as root (sudo).")

def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def info(m): print(f"[INFO] {m}")
def warn(m): print(f"[WARN] {m}")
def err(m):  print(f"[ERR ] {m}")

# -------------------- system metrics --------------------

def read_proc_stat():
    """
    Read /proc/stat aggregate CPU jiffies.

    Example access (no external command):
      cat /proc/stat
    """
    with open("/proc/stat","r") as f:
        line = f.readline()
    # "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
    parts = line.split()
    vals = list(map(int, parts[1:8]))  # user..softirq
    idle = vals[3] + vals[4]           # idle + iowait
    non_idle = vals[0] + vals[1] + vals[2] + vals[5] + vals[6]
    total = idle + non_idle
    return total, idle

def cpu_util_percent_during(duration_s=1.0):
    """
    Measure average CPU utilization between two /proc/stat samples.

    Example sequence (no external command):
      read /proc/stat -> sleep -> read /proc/stat
    """
    t1, i1 = read_proc_stat()
    time.sleep(duration_s)
    t2, i2 = read_proc_stat()
    totald = t2 - t1
    idled = i2 - i1
    if totald <= 0: return 0.0
    return 100.0 * (1.0 - (idled / totald))

def xfrm_stats_snapshot():
    """
    Snapshot IPsec (xfrm) stats from /proc/net/xfrm_stat.

    Example access:
      cat /proc/net/xfrm_stat
    """
    path = "/proc/net/xfrm_stat"
    stats = {}
    if not os.path.exists(path):
        return stats
    with open(path,"r") as f:
        for line in f:
            if ":" in line:
                k,v = line.strip().split(":",1)
                try: stats[k.strip()] = int(v.strip())
                except: pass
    return stats

def dict_delta(after: dict, before: dict) -> dict:
    keys = set(before.keys()) | set(after.keys())
    return {k: (after.get(k,0) - before.get(k,0)) for k in keys}

def ethtool_features(iface, dry=False):
    """
    Get NIC features/offloads.

    Example final command:
      ethtool -k eth0
    """
    try:
        return run(["ethtool","-k",iface], dry=dry)
    except Exception:
        return ""

def ethtool_stats(iface, dry=False):
    """
    Get NIC driver statistics.

    Example final command:
      ethtool -S eth0
    """
    try:
        return run(["ethtool","-S",iface], dry=dry)
    except Exception:
        return ""

# -------------------- fio --------------------

def fio_run(cmd_list, dry=False):
    """
    Run fio with JSON output and return parsed json dict.

    Example final command:
      fio --name=seq --filename=/mnt/nvme_test/seq.bin --rw=readwrite --rwmixread=50 \
          --bs=256k --size=8G --ioengine=io_uring --iodepth=32 --numjobs=2 \
          --time_based=1 --runtime=60 --direct=1 --group_reporting --output-format=json
    """
    if "--output-format=json" not in cmd_list:
        cmd_list += ["--output-format=json"]
    info("fio: " + " ".join(cmd_list))
    out = run(cmd_list, dry=dry)
    return json.loads(out) if out else {}

def parse_fio_summary(data):
    """
    Extract BW/IOPS and p99 clat (us) from first job.
    """
    if not data or "jobs" not in data or not data["jobs"]:
        return {"read_bw_kbps":0,"write_bw_kbps":0,"read_iops":0,"write_iops":0,
                "read_p99_us":None,"write_p99_us":None}
    j = data["jobs"][0]
    rd = j.get("read", {})
    wr = j.get("write", {})
    def p99(ns_block):
        try:
            p = ns_block.get("clat_ns",{}).get("percentile",{}).get("99.000000")
            return None if p is None else round(float(p)/1000.0, 1)  # ns -> us
        except Exception:
            return None
    return {
        "read_bw_kbps":  rd.get("bw",0),
        "write_bw_kbps": wr.get("bw",0),
        "read_iops":     rd.get("iops",0),
        "write_iops":    wr.get("iops",0),
        "read_p99_us":   p99(rd),
        "write_p99_us":  p99(wr),
    }

# -------------------- scenarios --------------------

def scenario_seq_throughput(mount_point, runtime=60, dry=False):
    """
    Large sequential read/write throughput.

    Example final command:
      fio --name=seq --filename=/mnt/nvme_test/seq.bin --rw=readwrite --rwmixread=50 \
          --bs=256k --size=8G --ioengine=io_uring --iodepth=32 --numjobs=2 \
          --time_based=1 --runtime=60 --direct=1 --group_reporting --output-format=json
    """
    path = os.path.join(mount_point, "seq.bin")
    cmd = ["fio","--name=seq",f"--filename={path}",
           "--rw=readwrite","--rwmixread=50",
           "--bs=256k","--size=8G",
           "--ioengine=io_uring","--iodepth=32","--numjobs=2",
           "--time_based=1", f"--runtime={runtime}",
           "--direct=1","--group_reporting"]
    return fio_run(cmd, dry=dry)

def scenario_qd_sweep(mount_point, runtime=25, dry=False):
    """
    4k random read IOPS across iodepth sweep (1..64).

    Example final command (one step, qd=32):
      fio --name=qd32 --filename=/mnt/nvme_test/qd32.bin --rw=randread --bs=4k \
          --size=2G --ioengine=io_uring --iodepth=32 --numjobs=1 \
          --time_based=1 --runtime=25 --direct=1 --group_reporting --output-format=json
    """
    results = []
    for qd in [1, 2, 4, 8, 16, 32, 64]:
        path = os.path.join(mount_point, f"qd{qd}.bin")
        cmd = ["fio", f"--name=qd{qd}", f"--filename={path}",
               "--rw=randread","--bs=4k","--size=2G",
               "--ioengine=io_uring", f"--iodepth={qd}", "--numjobs=1",
               "--time_based=1", f"--runtime={runtime}",
               "--direct=1","--group_reporting"]
        data = fio_run(cmd, dry=dry)
        results.append((qd, data))
    return results

def scenario_bs_sweep(mount_point, runtime=30, dry=False):
    """
    Block-size sweep for throughput (readwrite 50/50).

    Example final command (one step, bs=64k):
      fio --name=bs64k --filename=/mnt/nvme_test/bs64k.bin --rw=readwrite --rwmixread=50 \
          --bs=64k --size=4G --ioengine=io_uring --iodepth=32 --numjobs=2 \
          --time_based=1 --runtime=30 --direct=1 --group_reporting --output-format=json
    """
    results = []
    for bs in ["4k","8k","16k","64k","256k"]:
        path = os.path.join(mount_point, f"bs{bs}.bin")
        cmd = ["fio", f"--name=bs{bs}", f"--filename={path}",
               "--rw=readwrite","--rwmixread=50",
               f"--bs={bs}","--size=4G",
               "--ioengine=io_uring","--iodepth=32","--numjobs=2",
               "--time_based=1", f"--runtime={runtime}",
               "--direct=1","--group_reporting"]
        data = fio_run(cmd, dry=dry)
        results.append((bs, data))
    return results

def scenario_longevity(mount_point, runtime=300, dry=False):
    """
    Long-duration mixed I/O (randrw) to surface leaks or instability.

    Example final command:
      fio --name=long --filename=/mnt/nvme_test/long.bin --rw=randrw --rwmixread=70 \
          --bs=16k --size=16G --ioengine=io_uring --iodepth=64 --numjobs=4 \
          --time_based=1 --runtime=300 --direct=1 --group_reporting --output-format=json
    """
    path = os.path.join(mount_point, "long.bin")
    cmd = ["fio","--name=long",f"--filename={path}",
           "--rw=randrw","--rwmixread=70",
           "--bs=16k","--size=16G",
           "--ioengine=io_uring","--iodepth=64","--numjobs=4",
           "--time_based=1", f"--runtime={runtime}",
           "--direct=1","--group_reporting"]
    return fio_run(cmd, dry=dry)

# -------------------- reporting --------------------

def write_csv_header_if_needed():
    new_file = not os.path.exists(CSV_FILE)
    if new_file:
        with open(CSV_FILE, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp","scenario","param","read_MBps","write_MBps",
                "read_IOPS","write_IOPS","read_p99_us","write_p99_us",
                "cpu_util_pct","xfrm_error_sum","notes"
            ])

def kbps_to_MBps(kbps): return round(kbps/1024.0, 1)

def xfrm_error_sum(delta: dict) -> int:
    # Sum all counters typically indicating errors; keep generic
    return sum(v for k,v in delta.items() if v > 0)

def record_result(scenario, param, fio_json, cpu_pct, xfrm_delta, notes=""):
    write_csv_header_if_needed()
    summ = parse_fio_summary(fio_json)
    row = [
        ts(),
        scenario,
        param,
        kbps_to_MBps(summ["read_bw_kbps"]),
        kbps_to_MBps(summ["write_bw_kbps"]),
        int(summ["read_iops"]), int(summ["write_iops"]),
        summ["read_p99_us"] if summ["read_p99_us"] is not None else "",
        summ["write_p99_us"] if summ["write_p99_us"] is not None else "",
        round(cpu_pct,1),
        xfrm_error_sum(xfrm_delta),
        notes
    ]
    with open(CSV_FILE, "a", newline="") as f:
        csv.writer(f).writerow(row)
    print(" | ".join(map(str,row)))

# -------------------- orchestrator --------------------

def run_with_metrics(run_callable, *args, iface=None, label="", dry=False, **kwargs):
    """
    Wrap a scenario to capture CPU and xfrm stats around it.

    Example stats commands:
      ip -s xfrm state show
      ip -s xfrm policy show
      ethtool -S eth0
    """
    # Pre snapshots
    xfrm_before = xfrm_stats_snapshot()
    if iface:
        _ = ethtool_features(iface, dry=dry)
        _ = ethtool_stats(iface, dry=dry)

    # Coarse CPU during run: measure over entire wall time if not dry
    cpu_pct = 0.0
    t0 = time.time()
    if not dry:
        # sample periodically in a background-ish manner (simple)
        cpu_samples = []
        stop_at = t0 + max(5, int(kwargs.get("runtime", 30)))
        while time.time() < stop_at:
            cpu_samples.append(cpu_util_percent_during(0.5))
        cpu_pct = sum(cpu_samples)/len(cpu_samples) if cpu_samples else 0.0

    # Execute scenario
    result = run_callable(*args, dry=dry, **kwargs)

    # Post snapshots
    xfrm_after = xfrm_stats_snapshot()
    xdelta = dict_delta(xfrm_after, xfrm_before)
    if iface:
        _ = ethtool_stats(iface, dry=dry)

    return result, cpu_pct, xdelta

# -------------------- CLI --------------------

def parse_args():
    p = argparse.ArgumentParser(description="Performance & Resource Handling (Linux)")
    p.add_argument("--mount", required=True, help="Mounted path for test files (e.g., /mnt/nvme_test)")
    p.add_argument("--iface", help="NIC interface for optional ethtool stats (e.g., eth0)")
    p.add_argument("--only", choices=["seq_throughput","qd_sweep","bs_sweep","longevity"],
                   help="Run only this scenario")

    p.add_argument("--seq-runtime", type=int, default=60)
    p.add_argument("--qd-runtime", type=int, default=25)
    p.add_argument("--bs-runtime", type=int, default=30)
    p.add_argument("--longevity-runtime", type=int, default=300)

    p.add_argument("--dry-run", action="store_true", help="Print final commands and skip execution")
    return p.parse_args()

def main():
    ensure_root()
    args = parse_args()
    if not os.path.isdir(args.mount):
        sys.exit(f"Mount path not found: {args.mount}")

    print(f"[{ts()}] Performance run start. CSV -> {CSV_FILE}")

    # SEQ
    if args.only in (None, "seq_throughput"):
        data, cpu, xdelta = run_with_metrics(
            scenario_seq_throughput, args.mount,
            iface=args.iface, runtime=args.seq_runtime, label="seq", dry=args.dry_run
        )
        record_result("seq_throughput","bs=256k,qd=32,nj=2", data, cpu, xdelta)

    # QD SWEEP
    if args.only in (None, "qd_sweep"):
        results, cpu, xdelta = run_with_metrics(
            scenario_qd_sweep, args.mount,
            iface=args.iface, runtime=args.qd_runtime, label="qd", dry=args.dry_run
        )
        if isinstance(results, list):
            for qd, data in results:
                record_result("qd_sweep", f"qd={qd},bs=4k", data, cpu, xdelta)

    # BS SWEEP
    if args.only in (None, "bs_sweep"):
        results, cpu, xdelta = run_with_metrics(
            scenario_bs_sweep, args.mount,
            iface=args.iface, runtime=args.bs_runtime, label="bs", dry=args.dry_run
        )
        if isinstance(results, list):
            for bs, data in results:
                record_result("bs_sweep", f"bs={bs},qd=32,nj=2", data, cpu, xdelta)

    # LONGEVITY
    if args.only in (None, "longevity"):
        data, cpu, xdelta = run_with_metrics(
            scenario_longevity, args.mount,
            iface=args.iface, runtime=args.longevity_runtime, label="long", dry=args.dry_run
        )
        record_result("longevity","randrw 70/30, bs=16k, qd=64, nj=4", data, cpu, xdelta)

    print(f"[{ts()}] Done.")

if __name__ == "__main__":
    main()
