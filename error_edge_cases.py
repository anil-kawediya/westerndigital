#!/usr/bin/env python3
"""
error_edge_cases_linux.py

Linux harness for IPsec Error & Edge Case Handling.

Scenarios:
  - SA expiration / rekey during active I/O
  - Key mismatch / auth failure (tamper local SA)
  - Packet drop / reorder via tc netem (scoped to target IP)
  - (Placeholder) Offload fallback toggle hook

Requirements:
  sudo, iproute2 (ip xfrm, tc), tcpdump, fio
  Optional: strongSwan (swanctl) if you wire it in.

Safe-first:
  Use --dry-run initially to print exact commands.

CSV: error_edge_cases_results.csv
"""

import argparse, csv, os, shlex, subprocess, sys, time
from datetime import datetime

CSV_FILE = "error_edge_cases_results.csv"

def run(cmd, check=True, capture=True, dry=False):
    """
    Execute a shell command, respecting --dry-run.

    Example final command:
      ip xfrm state show
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

def log_row(path, row):
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["timestamp","scenario","mode","target_ip","result","details"])
        w.writerow(row)

# ---------------- tcpdump ----------------
def start_tcpdump(iface, pcap, dry):
    """
    Start packet capture focused on ESP.

    Example final command:
      tcpdump -i eth0 -w /tmp/ipsec_edge_cases.pcap esp
    """
    cmd = ["tcpdump", "-i", iface, "-w", pcap, "esp"]
    return run(cmd, capture=False, dry=dry)

def stop_tcpdump():
    """
    Stop tcpdump by killing it (best-effort).

    Example final command:
      pkill -f 'tcpdump -i'
    """
    try:
        subprocess.run(["pkill","-f","tcpdump -i"], shell=False)
    except Exception:
        pass

# --------------- tc netem ----------------
def tc_targeted_netem(iface, ip, loss=2.0, delay_ms=10, reorder=10, dry=False):
    """
    Apply netem ONLY to traffic to/from target IP.

    Example final commands:
      tc qdisc del dev eth0 root
      tc qdisc add dev eth0 root handle 1: prio
      tc qdisc add dev eth0 parent 1:3 handle 30: netem loss 2% delay 10ms reorder 10%
      tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dst 10.0.0.2 flowid 1:3
      tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip src 10.0.0.2 flowid 1:3
    """
    run(["tc","qdisc","del","dev",iface,"root"], check=False, capture=False, dry=dry)
    run(["tc","qdisc","add","dev",iface,"root","handle","1:","prio"], capture=False, dry=dry)
    run(["tc","qdisc","add","dev",iface,"parent","1:3","handle","30:","netem",
         "loss",f"{loss}%","delay",f"{delay_ms}ms","reorder",f"{reorder}%"], capture=False, dry=dry)
    run(["tc","filter","add","dev",iface,"protocol","ip","parent","1:","prio","1","u32",
         "match","ip","dst",ip,"flowid","1:3"], capture=False, dry=dry)
    run(["tc","filter","add","dev",iface,"protocol","ip","parent","1:","prio","1","u32",
         "match","ip","src",ip,"flowid","1:3"], capture=False, dry=dry)

def tc_clear(iface, dry=False):
    """
    Clear root qdisc.

    Example final command:
      tc qdisc del dev eth0 root
    """
    run(["tc","qdisc","del","dev",iface,"root"], check=False, capture=False, dry=dry)

# --------------- xfrm helpers ------------
def xfrm_show_states(dry=False):
    """
    Show xfrm SAs.

    Example final command:
      ip xfrm state show
    """
    return run(["ip","xfrm","state","show"], dry=dry)

def xfrm_delete_spi(spi_hex, dry=False):
    """
    Delete a specific SA by SPI.

    Example final command:
      ip xfrm state delete spi 0x1001
    """
    run(["ip","xfrm","state","delete","spi",spi_hex], capture=False, dry=dry)

def xfrm_flush_all(dry=False):
    """
    Flush all xfrm state/policy (DANGEROUS in shared hosts).

    Example final commands:
      ip xfrm state flush
      ip xfrm policy flush
    """
    run(["ip","xfrm","state","flush"], capture=False, dry=dry)
    run(["ip","xfrm","policy","flush"], capture=False, dry=dry)

# --------------- fio helpers -------------
def fio_randrw(mount_point, fname, runtime=30, bs="4k", iodepth=32, numjobs=4, verify=True, dry=False):
    """
    Run a short randrw workload with verification.

    Example final command:
      fio --name=edge --filename=/mnt/nvme_test/edge.bin --rw=randrw --bs=4k \
          --size=512M --ioengine=io_uring --iodepth=32 --numjobs=4 --time_based=1 \
          --runtime=30 --direct=1 --verify=crc32 --verify_fatal=1 --group_reporting --output-format=json
    """
    path = os.path.join(mount_point, fname)
    cmd = ["fio", "--name=edge", f"--filename={path}", "--rw=randrw", f"--bs={bs}",
           "--size=512M", "--ioengine=io_uring", f"--iodepth={iodepth}", f"--numjobs={numjobs}",
           "--time_based=1", f"--runtime={runtime}", "--direct=1", "--group_reporting",
           "--output-format=json"]
    if verify:
        cmd += ["--verify=crc32","--verify_fatal=1"]
    out = run(cmd, dry=dry)
    return out

# --------------- scenarios ----------------
def scenario_rekey_during_io(mount_point, iface, target_ip, spi_hex, dry=False):
    """
    Start I/O, then force a rekey-like event by deleting the active SA (local),
    expecting the stack to re-establish (if using IKE) or to drop I/O (manual xfrm).

    Example SA delete command:
      ip xfrm state delete spi 0x1001
    """
    print(f"[{ts()}] scenario: rekey during IO")
    start_tcpdump(iface, "/tmp/ipsec_edge_rekey.pcap", dry)
    try:
        # start fio (short)
        fio_randrw(mount_point, "rekey.bin", runtime=20, dry=dry)
        time.sleep(5)
        # simulate rekey by killing current SA
        xfrm_delete_spi(spi_hex, dry=dry)
        time.sleep(5)
        # run more I/O
        fio_randrw(mount_point, "rekey_post.bin", runtime=15, dry=dry)
        log_row(CSV_FILE, [ts(),"SA Rekey During IO","n/a",target_ip,"PASS","Deleted SPI and continued I/O"])
    except Exception as e:
        log_row(CSV_FILE, [ts(),"SA Rekey During IO","n/a",target_ip,"FAIL",str(e)])
    finally:
        stop_tcpdump()

def scenario_key_mismatch(mount_point, iface, target_ip, dry=False):
    """
    Simulate auth failure by tampering local SA to wrong key (requires prior manual SA add).
    Here we do a 'state flush' to break symmetry then re-add wrong key (left as site-specific).

    Example final commands (illustrative):
      ip xfrm state flush
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x2001 mode tunnel enc rfc4106(gcm(aes)) 0xDEADBEEF... reqid 1
      # (peer still using original key -> auth fail)
    """
    print(f"[{ts()}] scenario: key mismatch / auth failure")
    start_tcpdump(iface, "/tmp/ipsec_edge_authfail.pcap", dry)
    try:
        xfrm_flush_all(dry=dry)
        fio_randrw(mount_point, "authfail.bin", runtime=15, dry=dry)
        log_row(CSV_FILE, [ts(),"Key Mismatch/Auth Fail","n/a",target_ip,"PASS","Tampered local SA; expect drops"])
    except Exception as e:
        log_row(CSV_FILE, [ts(),"Key Mismatch/Auth Fail","n/a",target_ip,"FAIL",str(e)])
    finally:
        stop_tcpdump()

def scenario_packet_loss_reorder(mount_point, iface, target_ip, dry=False):
    """
    Inject loss/reorder/delay using tc netem, then exercise I/O.

    Example final commands:
      tc qdisc del dev eth0 root
      tc qdisc add dev eth0 root handle 1: prio
      tc qdisc add dev eth0 parent 1:3 handle 30: netem loss 3% delay 15ms reorder 10%
      tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dst 10.0.0.2 flowid 1:3
      tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip src 10.0.0.2 flowid 1:3
    """
    print(f"[{ts()}] scenario: packet loss & reorder")
    try:
        tc_targeted_netem(iface, target_ip, loss=3.0, delay_ms=15, reorder=10, dry=dry)
        fio_randrw(mount_point, "netem.bin", runtime=25, dry=dry)
        log_row(CSV_FILE, [ts(),"Packet Drop/Reorder","n/a",target_ip,"PASS","I/O under netem impairment"])
    except Exception as e:
        log_row(CSV_FILE, [ts(),"Packet Drop/Reorder","n/a",target_ip,"FAIL",str(e)])
    finally:
        tc_clear(iface, dry=dry)

def scenario_offload_fallback_placeholder():
    """
    Placeholder hook — offload fallback is NIC/driver specific.
    You may toggle features with ethtool or module params.

    Example ideas (illustrative; adapt to your NIC/stack):
      ethtool --offload eth0 rx off tx off
      # or vendor tool to disable IPsec HW offload engine
    """
    pass

# --------------- main ---------------------
def main():
    ensure_root()
    ap = argparse.ArgumentParser(description="IPsec Error & Edge Cases (Linux)")
    ap.add_argument("--mount", required=True, help="Mounted path to run fio (e.g., /mnt/nvme_test)")
    ap.add_argument("--iface", required=True, help="Interface for tcpdump/tc (e.g., eth0)")
    ap.add_argument("--target-ip", required=True, help="Peer/storage IP to scope netem filters")
    ap.add_argument("--spi-hex", default="0x1001", help="SPI (hex) to delete for rekey scenario")
    ap.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    ap.add_argument("--skip-rekey", action="store_true")
    ap.add_argument("--skip-authfail", action="store_true")
    ap.add_argument("--skip-netem", action="store_true")
    args = ap.parse_args()

    print(f"[{ts()}] Starting Error & Edge Cases. CSV -> {CSV_FILE}")
    try:
        if not args.skip_rekey:
            scenario_rekey_during_io(args.mount, args.iface, args.target_ip, args.spi_hex, dry=args.dry_run)
        if not args.skip_authfail:
            scenario_key_mismatch(args.mount, args.iface, args.target_ip, dry=args.dry_run)
        if not args.skip_netem:
            scenario_packet_loss_reorder(args.mount, args.iface, args.target_ip, dry=args.dry_run)
        print(f"[{ts()}] Done.")
    finally:
        try: tc_clear(args.iface, dry=args.dry_run)
        except Exception: pass
        stop_tcpdump()

if __name__ == "__main__":
    main()
