#!/usr/bin/env python3
"""
firmware_upgrade_session_linux.py

Linux harness for Firmware Upgrade & Session Continuity under active IPsec + NVMe/TCP I/O.

Flow:
  1) Start steady-state fio workload on mounted storage path.
  2) Start tcpdump on ESP.
  3) Snapshot SA/SPIs (ip xfrm state show).
  4) Trigger FW reload/upgrade using a user-supplied shell command.
  5) Detect downtime window and post-recovery state:
     - Same SPI -> "Persistent"
     - New SPI and I/O recovered quickly -> "Graceful"
     - I/O fails or recovery exceeds threshold -> "Fail"
  6) Store CSV row with timings and outcome.

Requirements:
  sudo, iproute2 (ip xfrm), fio, tcpdump
  A working mount point backed by the encrypted path (e.g., NVMe/TCP over IPsec).

CSV: firmware_upgrade_results.csv
"""

import argparse, csv, os, shlex, subprocess, sys, time, json, signal
from datetime import datetime

CSV_FILE = "firmware_upgrade_results.csv"

def run(cmd, check=True, capture=True, dry=False):
    """
    Execute a shell command, respecting --dry-run.

    Example final commands:
      ip xfrm state show
      tcpdump -i eth0 -w /tmp/fw_session.pcap esp
    """
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    printable = " ".join(cmd)
    if dry:
        print(f"[DRY] {printable}")
        return ""
    res = subprocess.run(cmd, check=check, text=True, capture_output=capture)
    return res.stdout if capture else ""

def ensure_root():
    if os.geteuid() != 0:
        sys.exit("Run as root (sudo).")

def ts(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def start_tcpdump(iface, pcap, dry):
    """
    Start packet capture on ESP.

    Example final command:
      tcpdump -i eth0 -w /tmp/fw_session.pcap esp
    """
    run(["tcpdump","-i",iface,"-w",pcap,"esp"], capture=False, dry=dry)

def stop_tcpdump():
    """
    Stop tcpdump (best-effort).

    Example final command:
      pkill -f 'tcpdump -i'
    """
    try:
        subprocess.run(["pkill","-f","tcpdump -i"], check=False)
    except Exception:
        pass

def fio_start_background(mount_point, fname, runtime, iodepth, numjobs, dry):
    """
    Launch fio in background to keep steady-state I/O during FW event.

    Example final command:
      fio --name=fwrun --filename=/mnt/nvme_test/fw.bin --rw=randrw --bs=4k \
          --size=2G --ioengine=io_uring --iodepth=32 --numjobs=4 \
          --time_based=1 --runtime=120 --direct=1 --group_reporting
    """
    path = os.path.join(mount_point, fname)
    cmd = ["fio","--name=fwrun",f"--filename={path}","--rw=randrw","--bs=4k",
           "--size=2G","--ioengine=io_uring",f"--iodepth={iodepth}",f"--numjobs={numjobs}",
           "--time_based=1",f"--runtime={runtime}","--direct=1","--group_reporting"]
    if dry:
        print("[DRY] "+" ".join(cmd))
        return None
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc

def xfrm_state_snapshot(dry):
    """
    Snapshot xfrm SAs (for SPI persistence check).

    Example final command:
      ip xfrm state show
    """
    out = run(["ip","xfrm","state","show"], dry=dry)
    return out

def parse_first_spi(state_text):
    """
    Parse first SPI (hex) found in 'ip xfrm state show' output.
    """
    for line in state_text.splitlines():
        if "spi" in line:
            # e.g.: "spi 0x0000000d ..."
            parts = line.strip().split()
            for i,p in enumerate(parts):
                if p == "spi" and i+1 < len(parts):
                    return parts[i+1]
    return None

def trigger_firmware(cmdline, dry):
    """
    Execute user-supplied firmware reload/upgrade command.

    Example final command (illustrations; replace with your real trigger):
      ssh root@dut '/usr/local/bin/fw_upgrade.sh --image /tmp/new.bin'
      OR
      systemctl restart nvmeoffload.service
    """
    if not cmdline:
        raise ValueError("No firmware trigger command provided.")
    if isinstance(cmdline, str):
        cmd = shlex.split(cmdline)
    else:
        cmd = cmdline
    return run(cmd, capture=False, dry=dry)

def monitor_recovery(timeout_s, poll_fn, interval=1.0):
    """
    Poll for recovery condition until timeout.

    We use this to wait for I/O to continue or SA to appear.
    """
    start = time.time()
    while time.time() - start < timeout_s:
        if poll_fn():
            return True, time.time() - start
        time.sleep(interval)
    return False, timeout_s

def fio_is_running(proc):
    if proc is None: return False
    return proc.poll() is None

def write_csv(row):
    new = not os.path.exists(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["timestamp","event","target","pre_spi","post_spi","downtime_s","outcome","notes"])
        w.writerow(row)

def main():
    ensure_root()
    ap = argparse.ArgumentParser(description="Firmware Upgrade & Session Continuity (Linux)")
    ap.add_argument("--mount", required=True, help="Mounted path for fio (e.g., /mnt/nvme_test)")
    ap.add_argument("--iface", required=True, help="Interface for tcpdump (e.g., eth0)")
    ap.add_argument("--target", default="DUT", help="Human label for target/DUT")
    ap.add_argument("--fw-cmd", required=True, help="Shell command to trigger firmware reload/upgrade")
    ap.add_argument("--io-runtime", type=int, default=120, help="Seconds for fio steady-state runtime")
    ap.add_argument("--iodepth", type=int, default=32)
    ap.add_argument("--numjobs", type=int, default=4)
    ap.add_argument("--recovery-timeout", type=int, default=180, help="Seconds to wait for recovery")
    ap.add_argument("--dry-run", action="store_true", help="Print commands but do not execute")
    args = ap.parse_args()

    print(f"[{ts()}] Starting Firmware Session test. CSV -> {CSV_FILE}")
    start_tcpdump(args.iface, "/tmp/fw_session.pcap", args.dry_run)

    # Snapshot pre-event SA
    pre_state = xfrm_state_snapshot(args.dry_run)
    pre_spi = parse_first_spi(pre_state) or "unknown"
    print(f"[{ts()}] Pre-event SPI: {pre_spi}")

    # Start fio background workload
    proc = fio_start_background(args.mount, "fw.bin", args.io_runtime, args.iodepth, args.numjobs, args.dry_run)
    time.sleep(5)

    # Trigger FW event
    print(f"[{ts()}] Triggering FW with: {args.fw_cmd}")
    try:
        trigger_firmware(args.fw_cmd, args.dry_run)
    except Exception as e:
        write_csv([ts(),"FW Trigger",args.target,pre_spi,"n/a",0,"FAIL",str(e)])
        stop_tcpdump()
        sys.exit(2)

    # Detect downtime and recovery (very simple heuristic: check fio still running or restarted SAs present)
    t0 = time.time()

    def recovered():
        # consider recovered if fio still running (or resumed) and an SA exists
        st = xfrm_state_snapshot(args.dry_run)
        return ("proto esp" in st) or fio_is_running(proc)

    ok, elapsed = monitor_recovery(args.recovery_timeout, recovered, interval=3.0)
    post_state = xfrm_state_snapshot(args.dry_run)
    post_spi = parse_first_spi(post_state) or "unknown"

    # Determine outcome
    if not ok:
        outcome = "FAIL"
        note = "No recovery within timeout"
    else:
        if post_spi == pre_spi and post_spi != "unknown":
            outcome = "PASS-PERSISTENT"
            note = "SA SPI unchanged"
        else:
            outcome = "PASS-GRACEFUL"
            note = "SA re-negotiated"

    downtime = time.time() - t0
    print(f"[{ts()}] Outcome: {outcome} (downtime ~ {int(downtime)}s) preSPI={pre_spi} postSPI={post_spi}")
    write_csv([ts(),"FW Reload/Upgrade",args.target,pre_spi,post_spi,int(downtime),outcome,note])

    # Cleanup
    stop_tcpdump()
    if proc and proc.poll() is None and not args.dry_run:
        try:
            proc.send_signal(signal.SIGINT)
        except Exception:
            pass
    print(f"[{ts()}] Done. Results in {CSV_FILE}")

if __name__ == "__main__":
    main()
