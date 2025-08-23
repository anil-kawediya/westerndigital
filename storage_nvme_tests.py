#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
    """
    Execute a shell command.

    Example (final command):
      nvme list
    """
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    res = subprocess.run(cmd, check=check, text=True,
                         capture_output=capture)
    return res.stdout if capture else ""

def ensure_root():
    """Exit if not root (required for nvme/mount/fio direct I/O)."""
    if os.geteuid() != 0:
        sys.exit("This script must be run as root (sudo).")

def info(msg): print(f"[INFO] {msg}")
def warn(msg): print(f"[WARN] {msg}")
def err(msg):  print(f"[ERR ] {msg}")

# ---------- nvme discovery/connect ----------
def nvme_list():
    """
    Return output of 'nvme list'.

    Example (final command):
      nvme list
    """
    out = run(["nvme", "list"])
    return out

def find_namespace_for_nqn(nqn):
    """
    Parse `nvme list` to find /dev/nvmeXnY for a given NQN.

    Example step that precedes this:
      nvme list
    """
    out = nvme_list()
    dev = None
    lines = out.splitlines()
    devs = []
    current = {}
    for ln in lines:
        m = re.match(r"^(/dev/nvme\dn\d)\s+", ln)
        if m:
            dev = m.group(1)
            current = {"dev": dev}
            devs.append(current)
        if "Subsystem NQN" in ln and current:
            current["nqn"] = ln.split(":", 1)[-1].strip()
    for d in devs:
        if d.get("nqn") and nqn in d["nqn"]:
            return d["dev"]
    return None

def nvme_connect_tcp(nqn, traddr, trsvcid="4420", hostnqn=None, retries=10, wait_s=1.0):
    """
    Connect to NVMe/TCP target and wait for a namespace device to appear.

    Example (final command):
      nvme connect -t tcp -a 192.168.1.50 -s 4420 -n nqn.2014-08.org.nvmexpress:uuid:1234
      # (optional)
      nvme connect -t tcp -a 192.168.1.50 -s 4420 -n nqn.2014-08.org.nvmexpress:uuid:1234 -q <hostnqn>
    """
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
    """
    Disconnect by NQN (or controller).

    Example (final command):
      nvme disconnect -n nqn.2014-08.org.nvmexpress:uuid:1234
    """
    try:
        run(["nvme", "disconnect", "-n", dev_or_nqn], capture=False)
    except subprocess.CalledProcessError:
        pass

# ---------- filesystem & mount ----------
def mkfs(device, fstype="ext4", label="nvmetest"):
    """
    Create filesystem (DESTRUCTIVE).

    Examples (final commands):
      mkfs.ext4 -F -L nvmetest /dev/nvme0n1
      mkfs.xfs  -f -L nvmetest /dev/nvme0n1
    """
    warn(f"Making filesystem ({fstype}) on {device} (DESTRUCTIVE).")
    if fstype == "ext4":
        run(["mkfs.ext4", "-F", "-L", label, device], capture=False)
    elif fstype == "xfs":
        run(["mkfs.xfs", "-f", "-L", label, device], capture=False)
    else:
        raise ValueError("Unsupported fstype (use ext4 or xfs)")

def mount_fs(device, mountpoint, fstype=None, opts="noatime,nodiratime"):
    """
    Mount a device to a mountpoint.

    Examples (final commands):
      mount -o noatime,nodiratime /dev/nvme0n1 /mnt/nvme_test
      mount -t ext4 -o noatime,nodiratime /dev/nvme0n1 /mnt/nvme_test
    """
    os.makedirs(mountpoint, exist_ok=True)
    cmd = ["mount", "-o", opts, device, mountpoint] if not fstype else \
          ["mount", "-t", fstype, "-o", opts, device, mountpoint]
    info(f"Mount: {' '.join(cmd)}")
    run(cmd, capture=False)

def umount_fs(mountpoint):
    """
    Unmount a mountpoint.

    Example (final command):
      umount -f /mnt/nvme_test
    """
    try:
        run(["umount", "-f", mountpoint], capture=False)
    except subprocess.CalledProcessError:
        pass

# ---------- fio wrappers ----------
def fio_cmd(base):
    """
    Build a fio command as a list (helper).

    Example usage:
      fio --name=job --filename=/mnt/nvme_test/file.bin --rw=randrw ...
    """
    return shlex.split(base)

def fio_run(cmd):
    """
    Run fio with JSON output and return parsed dict + compact summary.

    Example (final command shape):
      fio --name=basic --filename=/mnt/nvme_test/basic_randrw.bin --rw=randrw --bs=4k \
          --size=4G --ioengine=io_uring --iodepth=32 --numjobs=4 --direct=1 \
          --time_based=1 --runtime=45 --verify=crc32 --verify_fatal=1 \
          --group_reporting --output-format=json
    """
    if "--output-format=json" not in cmd:
        cmd += ["--output-format=json"]
    info("fio: " + " ".join(cmd))
    out = run(cmd)
    data = json.loads(out)
    j = data["jobs"][0]
    rw = j.get("job options", {}).get("rw", "unknown")
    read_bw = j["read"]["bw"] if "read" in j else 0
    write_bw = j["write"]["bw"] if "write" in j else 0
    read_iops = j["read"]["iops"] if "read" in j else 0
    write_iops = j["write"]["iops"] if "write" in j else 0
    return data, (rw, read_bw, write_bw, read_iops, write_iops)

def kbps_to_str(kbps):
    """Convert fio KB/s to human-friendly MB/s string."""
    return f"{kbps/1024:.1f} MB/s"

# ---------- scenarios ----------
def scenario_basic_randrw(mountpoint, size="4G"):
    """
    Basic correctness under storage stack using io_uring:
      - 4k random read/write
      - verification enabled (crc32)

    Example (final command):
      fio --name=basic --filename=/mnt/nvme_test/basic_randrw.bin --rw=randrw --bs=4k \
          --size=4G --ioengine=io_uring --iodepth=32 --numjobs=4 --direct=1 \
          --time_based=1 --runtime=45 --verify=crc32 --verify_fatal=1 \
          --group_reporting --output-format=json
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
    Misaligned buffers & offsets to exercise firmware/driver alignment handling:
      - offset=1 byte (misaligned file offset)
      - buffer_align=3 (odd buffer alignment)
      - 4k randwrite with verification

    Example (final command):
      fio --name=misaligned --filename=/mnt/nvme_test/misaligned.bin --rw=randwrite --bs=4k \
          --size=2G --ioengine=io_uring --iodepth=16 --direct=1 \
          --verify=crc32 --verify_fatal=1 --group_reporting \
          --offset=1 --buffer_align=3 --output-format=json
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
    Exercise scatter/gather and request fragmentation/coalescing:
      - Variable block sizes (4k..256k)
      - Higher iodepth + multiple jobs
      - Time-based mixed randrw

    Example (final command):
      fio --name=sg --filename=/mnt/nvme_test/sg.bin --rw=randrw --bsrange=4k-256k \
          --size=4G --ioengine=io_uring --iodepth=64 --numjobs=4 --direct=1 \
          --time_based=1 --runtime=60 --verify=crc32 --verify_fatal=1 \
          --group_reporting --output-format=json
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
    Sweep queue depth to observe IOPS scaling and latency behavior:
      - 4k random read
      - iodepth: 1,4,8,16,32,64
      - time-based short runs

    Example (final command for one depth, qd=16):
      fio --name=qd16 --filename=/mnt/nvme_test/qd16.bin --rw=randread --bs=4k \
          --size=2G --ioengine=io_uring --iodepth=16 --numjobs=1 --direct=1 \
          --time_based=1 --runtime=20 --group_reporting --output-format=json
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
    Large sequential read/write throughput:
      - 256k block size
      - readwrite (50/50)
      - moderate depth + 2 jobs

    Example (final command):
      fio --name=large_seq --filename=/mnt/nvme_test/large_seq.bin --rw=readwrite --rwmixread=50 \
          --bs=256k --size=8G --ioengine=io_uring --iodepth=32 --numjobs=2 --direct=1 \
          --time_based=1 --runtime=60 --group_reporting --output-format=json
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
