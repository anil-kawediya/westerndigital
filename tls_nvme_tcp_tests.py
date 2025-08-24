#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tls_nvme_tcp_tests.py

TLS 1.3 functionality tests for NVMe/TCP on Linux.

Adds:
  - Bad-certificate negative test (expect failure)
  - Traffic impairments with tc netem (loss/delay/reorder [+optional duplicate/corrupt])

Requirements:
  Linux, root, nvme-cli, fio, tcpdump, openssl, iproute2 (tc)

Examples:
  # Basic connect + I/O + capture
  sudo ./tls_nvme_tcp_tests.py \
    --traddr 192.168.1.10 --trsvcid 4420 \
    --nqn nqn.2014-08.org.nvmexpress:uuid:abcd \
    --hostnqn nqn.2014-08.org.nvmexpress:uuid:host123 \
    --tls-cert /etc/nvme/host.crt --tls-key /etc/nvme/host.key --tls-ca /etc/nvme/ca.crt \
    --iface eth0 --fio --runtime 45 --capture

  # Bad-cert negative test (should fail)
  sudo ./tls_nvme_tcp_tests.py \
    --traddr 192.168.1.10 --trsvcid 4420 \
    --nqn nqn.2014-08.org.nvmexpress:uuid:abcd \
    --hostnqn nqn.2014-08.org.nvmexpress:uuid:host123 \
    --tls-cert /etc/nvme/host.crt --tls-key /etc/nvme/host.key --tls-ca /etc/nvme/ca.crt \
    --bad-cert --bad-tls-ca /etc/nvme/bad_ca.crt

  # Impairment (loss/delay/reorder scoped to port 4420 via root qdisc)
  sudo ./tls_nvme_tcp_tests.py \
    --traddr 192.168.1.10 --trsvcid 4420 \
    --nqn nqn... --hostnqn nqn... \
    --tls-cert /etc/nvme/host.crt --tls-key /etc/nvme/host.key --tls-ca /etc/nvme/ca.crt \
    --iface eth0 --fio --impair --loss 2 --delay 10 --reorder 5
"""

import argparse, os, re, shlex, subprocess, sys, time
from datetime import datetime

# -------------------- helpers --------------------

def run(cmd, check=True, capture=True, dry=False):
    """
    Execute a shell command or print it if dry-run.

    Example final command:
      nvme list
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

def ts(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def info(m): print(f"[INFO] {m}")
def warn(m): print(f"[WARN] {m}")
def err(m):  print(f"[ERR ] {m}")

# -------------------- capture --------------------

def start_tcpdump_tls(iface, pcap_path, trsvcid="4420", dry=False):
    """
    Start packet capture for NVMe/TCP (port 4420) / TLS handshake.

    Example final command:
      tcpdump -i eth0 -w /tmp/nvme_tls.pcap port 4420
    """
    cmd = ["tcpdump","-i",iface,"-w",pcap_path,"port",str(trsvcid)]
    run(cmd, capture=False, dry=dry)

def stop_tcpdump():
    """
    Best-effort stop for tcpdump.

    Example final command:
      pkill -f 'tcpdump -i'
    """
    try:
        subprocess.run(["pkill","-f","tcpdump -i"], check=False)
    except Exception:
        pass

# -------------------- tc netem helpers --------------------

def tc_netem_add_root(iface, loss=0.0, delay_ms=0, reorder=0, duplicate=0, corrupt=0, dry=False):
    """
    Apply netem impairment to all traffic on iface.

    Example final command:
      tc qdisc add dev eth0 root netem loss 2% delay 10ms reorder 5% duplicate 1% corrupt 1%
    """
    cmd = ["tc","qdisc","add","dev",iface,"root","netem"]
    if loss and loss > 0:        cmd += ["loss", f"{loss}%"]
    if delay_ms and delay_ms > 0:cmd += ["delay", f"{delay_ms}ms"]
    if reorder and reorder > 0:  cmd += ["reorder", f"{reorder}%"]
    if duplicate and duplicate>0:cmd += ["duplicate", f"{duplicate}%"]
    if corrupt and corrupt>0:    cmd += ["corrupt", f"{corrupt}%"]
    run(cmd, capture=False, dry=dry)

def tc_netem_clear(iface, dry=False):
    """
    Clear root qdisc.

    Example final command:
      tc qdisc del dev eth0 root
    """
    run(["tc","qdisc","del","dev",iface,"root"], check=False, capture=False, dry=dry)

# -------------------- nvme/tls helpers --------------------

def nvme_connect_tls(traddr, trsvcid, nqn, hostnqn, tls_cert, tls_key, tls_ca, ctrl_loss_tmo=None, dry=False):
    """
    Connect NVMe/TCP with TLS 1.3 enabled.

    Example final command:
      nvme connect -t tcp --traddr 192.168.1.10 --trsvcid 4420 \
        --nqn nqn.2014-08.org.nvmexpress:uuid:abcd \
        --hostnqn nqn.2014-08.org.nvmexpress:uuid:host123 \
        --tls --tls_cert /etc/nvme/host.crt --tls_key /etc/nvme/host.key --tls_ca /etc/nvme/ca.crt
    """
    cmd = ["nvme","connect","-t","tcp","--traddr",traddr,"--trsvcid",str(trsvcid),
           "--nqn",nqn,"--hostnqn",hostnqn,"--tls",
           "--tls_cert",tls_cert,"--tls_key",tls_key,"--tls_ca",tls_ca]
    if ctrl_loss_tmo is not None:
        cmd += ["--ctrl-loss-tmo", str(ctrl_loss_tmo)]
    run(cmd, capture=False, dry=dry)

def nvme_disconnect(nqn, dry=False):
    """
    Disconnect by subsystem NQN.

    Example final command:
      nvme disconnect -n nqn.2014-08.org.nvmexpress:uuid:abcd
    """
    run(["nvme","disconnect","-n",nqn], capture=False, dry=dry)

def nvme_list():
    """
    List NVMe devices/subsystems.

    Example final command:
      nvme list
    """
    return run(["nvme","list"])

def find_namespace_device_for_nqn(nqn):
    """
    Parse `nvme list` to find a /dev/nvmeXnY that belongs to the given NQN.

    Example prior command:
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
            current = {"dev":dev}
            devs.append(current)
        if "Subsystem NQN" in ln and current:
            current["nqn"] = ln.split(":", 1)[-1].strip()
    for d in devs:
        if d.get("nqn") and nqn in d["nqn"]:
            return d["dev"]
    return None

def openssl_client_hello(traddr, trsvcid, tls_cert, tls_key, tls_ca, dry=False):
    """
    Optional: sanity-check TLS 1.3 handshake path with OpenSSL.

    Example final command:
      openssl s_client -connect 192.168.1.10:4420 -tls1_3 \
        -cert /etc/nvme/host.crt -key /etc/nvme/host.key -CAfile /etc/nvme/ca.crt -brief
    """
    cmd = ["openssl","s_client","-connect",f"{traddr}:{trsvcid}","-tls1_3",
           "-cert",tls_cert,"-key",tls_key,"-CAfile",tls_ca,"-brief"]
    return run(cmd, dry=dry)

# -------------------- fio --------------------

def fio_basic_rw(devnode, runtime=30, bs="4k", iodepth=32, numjobs=4, verify=True, dry=False):
    """
    Run a basic mixed I/O workload on the RAW namespace device.

    Example final command:
      fio --name=nvmectl --filename=/dev/nvme0n1 --rw=randrw --bs=4k \
          --size=2G --ioengine=io_uring --iodepth=32 --numjobs=4 \
          --time_based=1 --runtime=30 --direct=1 --group_reporting \
          --verify=crc32 --verify_fatal=1 --output-format=json
    """
    cmd = ["fio","--name=nvmectl",f"--filename={devnode}","--rw=randrw",f"--bs={bs}",
           "--size=2G","--ioengine=io_uring",f"--iodepth={iodepth}",f"--numjobs={numjobs}",
           "--time_based=1",f"--runtime={runtime}","--direct=1","--group_reporting","--output-format=json"]
    if verify:
        cmd += ["--verify=crc32","--verify_fatal=1"]
    return run(cmd, dry=dry)

# -------------------- scenarios --------------------

def scenario_tls_connect_and_io(args):
    """
    Functional smoke:
      1) (optional) tcpdump capture on port 4420
      2) nvme connect with TLS 1.3
      3) (optional) openssl s_client sanity
      4) discover namespace device
      5) fio mixed I/O against raw device
      6) disconnect

    Example sequence:
      tcpdump -i eth0 -w /tmp/nvme_tls.pcap port 4420
      nvme connect -t tcp --traddr 192.168.1.10 --trsvcid 4420 --nqn <NQN> --hostnqn <HOSTNQN> --tls \
        --tls_cert /etc/nvme/host.crt --tls_key /etc/nvme/host.key --tls_ca /etc/nvme/ca.crt
      openssl s_client -connect 192.168.1.10:4420 -tls1_3 -cert /etc/nvme/host.crt -key /etc/nvme/host.key -CAfile /etc/nvme/ca.crt -brief
      nvme list
      fio --name=nvmectl --filename=/dev/nvme0n1 --rw=randrw --bs=4k --size=2G \
          --ioengine=io_uring --iodepth=32 --numjobs=4 --time_based=1 --runtime=30 \
          --direct=1 --group_reporting --verify=crc32 --verify_fatal=1 --output-format=json
      nvme disconnect -n <NQN>
    """
    try:
        if args.capture:
            start_tcpdump_tls(args.iface, "/tmp/nvme_tls.pcap", args.trsvcid, args.dry_run)

        nvme_connect_tls(args.traddr, args.trsvcid, args.nqn, args.hostnqn,
                         args.tls_cert, args.tls_key, args.tls_ca,
                         ctrl_loss_tmo=args.ctrl_loss_tmo, dry=args.dry_run)

        if args.openssl_check:
            out = openssl_client_hello(args.traddr, args.trsvcid, args.tls_cert, args.tls_key, args.tls_ca, dry=args.dry_run)
            if not args.dry_run:
                print(out)

        dev = find_namespace_device_for_nqn(args.nqn)
        if dev is None:
            raise RuntimeError("Could not find namespace device for NQN (check nvme list output).")

        info(f"Using namespace: {dev}")
        if args.fio:
            print(fio_basic_rw(dev, runtime=args.runtime, bs=args.bs, iodepth=args.iodepth,
                               numjobs=args.numjobs, verify=True, dry=args.dry_run))
    finally:
        try:
            nvme_disconnect(args.nqn, dry=args.dry_run)
        except Exception:
            pass
        if args.capture:
            stop_tcpdump()

def scenario_bad_cert(args):
    """
    Negative test: use a wrong/invalid CA (or mismatched cert) and expect connect to fail.

    Example final command:
      nvme connect -t tcp --traddr 192.168.1.10 --trsvcid 4420 --nqn <NQN> --hostnqn <HOSTNQN> --tls \
        --tls_cert /etc/nvme/host.crt --tls_key /etc/nvme/host.key --tls_ca /etc/nvme/bad_ca.crt
    """
    info("Running bad-certificate negative test (expect failure)")
    try:
        nvme_connect_tls(args.traddr, args.trsvcid, args.nqn, args.hostnqn,
                         args.tls_cert, args.tls_key, args.bad_tls_ca,
                         ctrl_loss_tmo=args.ctrl_loss_tmo, dry=args.dry_run)
        # If we get here without exception, it (unexpectedly) succeeded
        warn("BAD-CERT TEST: connect unexpectedly succeeded (should fail)")
    except subprocess.CalledProcessError as e:
        info("BAD-CERT TEST: connect failed as expected")
        if not args.dry_run:
            print(e.stderr or str(e))
    finally:
        try:
            nvme_disconnect(args.nqn, dry=args.dry_run)
        except Exception:
            pass

def scenario_impairment(args):
    """
    Run connect + I/O under tc netem impairment (loss/delay/reorder [+dup/corrupt]).

    Example sequence:
      tc qdisc add dev eth0 root netem loss 2% delay 10ms reorder 5%
      nvme connect -t tcp --traddr 192.168.1.10 --trsvcid 4420 --nqn <NQN> --hostnqn <HOSTNQN> --tls \
        --tls_cert /etc/nvme/host.crt --tls_key /etc/nvme/host.key --tls_ca /etc/nvme/ca.crt
      fio --name=nvmectl --filename=/dev/nvme0n1 --rw=randrw --bs=4k --size=2G \
          --ioengine=io_uring --iodepth=32 --numjobs=4 --time_based=1 --runtime=30 \
          --direct=1 --group_reporting --verify=crc32 --verify_fatal=1 --output-format=json
      nvme disconnect -n <NQN>
      tc qdisc del dev eth0 root
    """
    if not args.impair:
        info("Impairment flag not set; skipping scenario_impairment.")
        return

    tc_netem_add_root(args.iface, loss=args.loss, delay_ms=args.delay, reorder=args.reorder,
                      duplicate=args.duplicate, corrupt=args.corrupt, dry=args.dry_run)
    try:
        nvme_connect_tls(args.traddr, args.trsvcid, args.nqn, args.hostnqn,
                         args.tls_cert, args.tls_key, args.tls_ca,
                         ctrl_loss_tmo=args.ctrl_loss_tmo, dry=args.dry_run)

        dev = find_namespace_device_for_nqn(args.nqn)
        if dev is None:
            raise RuntimeError("Could not find namespace device for NQN under impairment.")

        info(f"[impair] Using namespace: {dev}")
        if args.fio:
            print(fio_basic_rw(dev, runtime=args.runtime, bs=args.bs, iodepth=args.iodepth,
                               numjobs=args.numjobs, verify=True, dry=args.dry_run))
    finally:
        try:
            nvme_disconnect(args.nqn, dry=args.dry_run)
        except Exception:
            pass
        tc_netem_clear(args.iface, dry=args.dry_run)

def scenario_session_resumption(args):
    """
    Basic session resumption check:
      - Connect with TLS, run short I/O
      - Disconnect
      - Reconnect immediately (expect resumption if server enabled)
      - Run short I/O again

    Example sequence:
      nvme connect ... --tls ...
      nvme list
      fio --name=nvmectl --filename=/dev/nvme0n1 --rw=randrw --bs=4k --size=1G --ioengine=io_uring ...
      nvme disconnect -n <NQN>
      nvme connect ... --tls ...
      fio --name=nvmectl --filename=/dev/nvme0n1 --rw=randrw --bs=4k --size=1G --ioengine=io_uring ...
      nvme disconnect -n <NQN>
    """
    nvme_connect_tls(args.traddr, args.trsvcid, args.nqn, args.hostnqn,
                     args.tls_cert, args.tls_key, args.tls_ca,
                     ctrl_loss_tmo=args.ctrl_loss_tmo, dry=args.dry_run)
    try:
        dev = find_namespace_device_for_nqn(args.nqn)
        if dev is None:
            raise RuntimeError("Could not find namespace device for NQN after first connect.")
        fio_basic_rw(dev, runtime=max(10, args.runtime//2), iodepth=max(16, args.iodepth//2),
                     numjobs=max(2, args.numjobs//2), verify=False, dry=args.dry_run)
    finally:
        nvme_disconnect(args.nqn, dry=args.dry_run)

    time.sleep(2)

    nvme_connect_tls(args.traddr, args.trsvcid, args.nqn, args.hostnqn,
                     args.tls_cert, args.tls_key, args.tls_ca,
                     ctrl_loss_tmo=args.ctrl_loss_tmo, dry=args.dry_run)
    try:
        dev = find_namespace_device_for_nqn(args.nqn)
        if dev is None:
            raise RuntimeError("Could not find namespace device for NQN after reconnect.")
        fio_basic_rw(dev, runtime=max(10, args.runtime//2), iodepth=max(16, args.iodepth//2),
                     numjobs=max(2, args.numjobs//2), verify=False, dry=args.dry_run)
    finally:
        nvme_disconnect(args.nqn, dry=args.dry_run)

# -------------------- CLI --------------------

def parse_args():
    p = argparse.ArgumentParser(description="TLS 1.3 functionality test for NVMe/TCP (Linux)")
    # Target
    p.add_argument("--traddr", required=True, help="NVMe/TCP target IP/host")
    p.add_argument("--trsvcid", default="4420", help="NVMe/TCP service/port (default 4420)")
    p.add_argument("--nqn", required=True, help="Subsystem NQN")
    p.add_argument("--hostnqn", required=True, help="Host NQN string")
    p.add_argument("--ctrl-loss-tmo", type=int, help="Optional controller loss timeout (seconds)")

    # TLS material
    p.add_argument("--tls-cert", required=True, help="Path to host certificate (PEM)")
    p.add_argument("--tls-key",  required=True, help="Path to host private key (PEM)")
    p.add_argument("--tls-ca",   required=True, help="Path to CA bundle (PEM)")

    # Options
    p.add_argument("--openssl-check", action="store_true", help="Run openssl s_client sanity check")
    p.add_argument("--capture", action="store_true", help="Capture tcpdump on port 4420")
    p.add_argument("--iface", default="eth0", help="Interface for tcpdump and tc (default eth0)")

    # fio knobs
    p.add_argument("--fio", action="store_true", help="Run fio mixed I/O against the namespace device")
    p.add_argument("--runtime", type=int, default=30, help="fio runtime (seconds)")
    p.add_argument("--bs", default="4k", help="fio block size")
    p.add_argument("--iodepth", type=int, default=32, help="fio iodepth")
    p.add_argument("--numjobs", type=int, default=4, help="fio numjobs")

    # Scenarios
    p.add_argument("--resumption", action="store_true", help="Also test disconnect/reconnect (session resumption)")
    p.add_argument("--bad-cert", action="store_true", help="Run bad-certificate negative test")
    p.add_argument("--bad-tls-ca", help="Path to WRONG CA bundle to force cert validation failure")

    # Impairments
    p.add_argument("--impair", action="store_true", help="Enable tc netem impairment during test")
    p.add_argument("--loss", type=float, default=0.0, help="Packet loss percent (e.g., 2.0)")
    p.add_argument("--delay", type=int, default=0, help="One-way delay in ms (e.g., 10)")
    p.add_argument("--reorder", type=int, default=0, help="Reorder percent (e.g., 5)")
    p.add_argument("--duplicate", type=int, default=0, help="Duplicate percent (e.g., 1)")
    p.add_argument("--corrupt", type=int, default=0, help="Bit-corrupt percent (e.g., 1)")

    # Safety
    p.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    return p.parse_args()

def main():
    ensure_root()
    args = parse_args()

    info("Starting TLS 1.3 NVMe/TCP functionality test")
    scenario_tls_connect_and_io(args)

    if args.resumption:
        info("Running session resumption check")
        scenario_session_resumption(args)

    if args.bad_cert:
        if not args.bad_tls_ca:
            sys.exit("--bad-cert requires --bad-tls-ca <path>")
        scenario_bad_cert(args)

    if args.impair:
        info("Running impairment scenario with tc netem")
        scenario_impairment(args)

    info("Done.")

if __name__ == "__main__":
    main()
