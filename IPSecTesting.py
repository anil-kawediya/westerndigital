#!/usr/bin/env python3
"""
IPSecTesting.py (Linux, unified)

Features:
 - Manual IPsec bring-up (transport/tunnel) with `ip xfrm`
 - Optional live traffic: ping & fio
 - Packet capture with tcpdump (ESP filter)
 - NEW: Traffic impairments with tc netem (loss/delay/reorder), with helpers
 - Dry-run support to preview all shell commands

Examples:
  # Transport with ping+fio, capture, and netem impairment preview
  sudo ./IPSecTesting.py --mode transport --local 10.0.0.1 --remote 10.0.0.2 \
       --iface eth0 --cipher gcm --spi-in 0x1001 --spi-out 0x1002 \
       --key-in 0x<gcm_key_salt_in> --key-out 0x<gcm_key_salt_out> \
       --ping --fio --mount /mnt/nvme_test --capture \
       --impair --loss 2 --delay 10 --reorder 5 --dry-run

  # Tunnel with subnets, real run (no dry-run)
  sudo ./IPSecTesting.py --mode tunnel --local 10.0.0.1 --remote 10.0.0.2 \
       --local-subnet 10.1.0.0/16 --remote-subnet 10.2.0.0/16 \
       --iface eth0 --cipher gcm --spi-in 0x1101 --spi-out 0x1102 \
       --key-in 0x<gcm_key_salt_in> --key-out 0x<gcm_key_salt_out> \
       --ping --fio --mount /mnt/nvme_test --capture
"""

import argparse, os, shlex, subprocess, sys, time
from datetime import datetime

# -------------------- Helpers --------------------

def run(cmd, check=True, capture=True, dry=False):
    """
    Execute a shell command with optional dry-run.

    Example final command:
      ip xfrm state show
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
    """Abort if not root (ip xfrm/tcpdump/fio/tc need sudo)."""
    if os.geteuid() != 0:
        sys.exit("Run as root (sudo).")

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# -------------------- Capture --------------------

def start_tcpdump(iface, pcap_path, dry=False):
    """
    Start packet capture for ESP on an interface.

    Example final command:
      tcpdump -i eth0 -w /tmp/ipsec_basic.pcap esp
    """
    cmd = ["tcpdump", "-i", iface, "-w", pcap_path, "esp"]
    return run(cmd, capture=False, dry=dry)

def stop_tcpdump():
    """
    Best-effort stop for tcpdump.

    Example final command:
      pkill -f 'tcpdump -i'
    """
    try:
        subprocess.run(["pkill", "-f", "tcpdump -i"], check=False)
    except Exception:
        pass

# -------------------- tc netem helpers --------------------

def tc_netem_add_root(iface, loss=0.0, delay_ms=0, reorder=0, dry=False):
    """
    Apply simple root-level netem impairment to all traffic on iface.

    Example final command:
      tc qdisc add dev eth0 root netem loss 2% delay 10ms reorder 5%
    """
    cmd = ["tc","qdisc","add","dev",iface,"root","netem"]
    if loss and loss > 0:
        cmd += ["loss", f"{loss}%"]
    if delay_ms and delay_ms > 0:
        cmd += ["delay", f"{delay_ms}ms"]
    if reorder and reorder > 0:
        cmd += ["reorder", f"{reorder}%"]
    run(cmd, capture=False, dry=dry)

def tc_netem_add_scoped(iface, peer_ip, loss=0.0, delay_ms=0, reorder=0, dry=False):
    """
    Apply netem to traffic specifically to/from peer_ip using prio qdisc and u32 filters.

    Example final commands:
      tc qdisc del dev eth0 root
      tc qdisc add dev eth0 root handle 1: prio
      tc qdisc add dev eth0 parent 1:3 handle 30: netem loss 2% delay 10ms reorder 5%
      tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dst 10.0.0.2 flowid 1:3
      tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip src 10.0.0.2 flowid 1:3
    """
    # Clear any existing qdisc
    run(["tc","qdisc","del","dev",iface,"root"], check=False, capture=False, dry=dry)
    # Create prio root
    run(["tc","qdisc","add","dev",iface,"root","handle","1:","prio"], capture=False, dry=dry)
    # Add scoped netem on band 3
    base = ["tc","qdisc","add","dev",iface,"parent","1:3","handle","30:","netem"]
    if loss and loss > 0:
        base += ["loss", f"{loss}%"]
    if delay_ms and delay_ms > 0:
        base += ["delay", f"{delay_ms}ms"]
    if reorder and reorder > 0:
        base += ["reorder", f"{reorder}%"]
    run(base, capture=False, dry=dry)
    # Filters for dst/src peer_ip
    run(["tc","filter","add","dev",iface,"protocol","ip","parent","1:","prio","1","u32",
         "match","ip","dst",peer_ip,"flowid","1:3"], capture=False, dry=dry)
    run(["tc","filter","add","dev",iface,"protocol","ip","parent","1:","prio","1","u32",
         "match","ip","src",peer_ip,"flowid","1:3"], capture=False, dry=dry)

def tc_netem_clear(iface, dry=False):
    """
    Clear root qdisc.

    Example final command:
      tc qdisc del dev eth0 root
    """
    run(["tc","qdisc","del","dev",iface,"root"], check=False, capture=False, dry=dry)

# -------------------- xfrm Builders --------------------

def xfrm_state_add_transport(src, dst, spi_hex, cipher, key_hex, auth=None, dry=False):
    """
    Add a transport-mode ESP state from src -> dst.

    For AES-GCM (AEAD in Linux: rfc4106(gcm(aes))):
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x2001 mode transport \
        enc rfc4106(gcm(aes)) 0x<gcm_key_and_salt>

    For AES-CBC + HMAC-SHA256:
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x2001 mode transport \
        auth hmac(sha256) 0x<auth_key> enc cbc(aes) 0x<enc_key>
    """
    if cipher == "gcm":
        cmd = ["ip","xfrm","state","add","src",src,"dst",dst,"proto","esp",
               "spi",spi_hex,"mode","transport",
               "enc","rfc4106(gcm(aes))", key_hex]
    elif cipher == "cbc":
        if not auth:
            raise ValueError("auth must be provided for CBC+HMAC")
        auth_key, enc_key = key_hex.split(",", 1)
        cmd = ["ip","xfrm","state","add","src",src,"dst",dst,"proto","esp",
               "spi",spi_hex,"mode","transport",
               "auth",f"hmac({auth})", auth_key,
               "enc","cbc(aes)", enc_key]
    else:
        raise ValueError("cipher must be 'gcm' or 'cbc'")
    run(cmd, capture=False, dry=dry)

def xfrm_state_add_tunnel(src, dst, spi_hex, cipher, key_hex, auth=None, dry=False):
    """
    Add a tunnel-mode ESP state from src -> dst.

    For AES-GCM:
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x1101 mode tunnel \
        enc rfc4106(gcm(aes)) 0x<gcm_key_and_salt>

    For AES-CBC + HMAC:
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x1101 mode tunnel \
        auth hmac(sha256) 0x<auth_key> enc cbc(aes) 0x<enc_key>
    """
    if cipher == "gcm":
        cmd = ["ip","xfrm","state","add","src",src,"dst",dst,"proto","esp",
               "spi",spi_hex,"mode","tunnel",
               "enc","rfc4106(gcm(aes))", key_hex]
    elif cipher == "cbc":
        if not auth:
            raise ValueError("auth must be provided for CBC+HMAC")
        auth_key, enc_key = key_hex.split(",", 1)
        cmd = ["ip","xfrm","state","add","src",src,"dst",dst,"proto","esp",
               "spi",spi_hex,"mode","tunnel",
               "auth",f"hmac({auth})", auth_key,
               "enc","cbc(aes)", enc_key]
    else:
        raise ValueError("cipher must be 'gcm' or 'cbc'")
    run(cmd, capture=False, dry=dry)

def xfrm_policy_add_transport(direction, src_sel, dst_sel, dry=False):
    """
    Add a transport-mode policy (in/out).

    Example final commands:
      ip xfrm policy add dir out src 10.0.0.1/32 dst 10.0.0.2/32 tmpl proto esp mode transport
      ip xfrm policy add dir in  src 10.0.0.2/32 dst 10.0.0.1/32 tmpl proto esp mode transport
    """
    cmd = ["ip","xfrm","policy","add","dir",direction,
           "src",src_sel,"dst",dst_sel,"tmpl","proto","esp","mode","transport"]
    run(cmd, capture=False, dry=dry)

def xfrm_policy_add_tunnel(direction, src_sel, dst_sel, dry=False):
    """
    Add a tunnel-mode policy (in/out), using subnets as selectors.

    Example final commands:
      ip xfrm policy add dir out src 10.1.0.0/16 dst 10.2.0.0/16 tmpl proto esp mode tunnel
      ip xfrm policy add dir in  src 10.2.0.0/16 dst 10.1.0.0/16 tmpl proto esp mode tunnel
    """
    cmd = ["ip","xfrm","policy","add","dir",direction,
           "src",src_sel,"dst",dst_sel,"tmpl","proto","esp","mode","tunnel"]
    run(cmd, capture=False, dry=dry)

def xfrm_state_policy_flush(dry=False):
    """
    Flush all xfrm state and policy (DANGEROUS on shared hosts).

    Example final commands:
      ip xfrm state flush
      ip xfrm policy flush
    """
    run(["ip","xfrm","state","flush"], capture=False, dry=dry)
    run(["ip","xfrm","policy","flush"], capture=False, dry=dry)

def xfrm_state_show(dry=False):
    """
    Show xfrm SAs.

    Example final command:
      ip xfrm state show
    """
    return run(["ip","xfrm","state","show"], dry=dry)

def xfrm_policy_show(dry=False):
    """
    Show xfrm policies.

    Example final command:
      ip xfrm policy show
    """
    return run(["ip","xfrm","policy","show"], dry=dry)

# -------------------- Sanity/Traffic --------------------

def do_ping(target_ip, count=3, dry=False):
    """
    Sanity ping (outside/inside depends on routing/policy).

    Example final command:
      ping -c 3 10.0.0.2
    """
    cmd = ["ping","-c",str(count), target_ip]
    return run(cmd, dry=dry)

def fio_randrw(mount_path, filename="ipsec_test.bin", runtime=20, bs="4k", iodepth=16, numjobs=1, verify=True, dry=False):
    """
    Run a short fio randrw for live I/O verification.

    Example final command:
      fio --name=ipsec --filename=/mnt/storage_test/ipsec_test.bin --rw=randrw --bs=4k \
          --size=1G --ioengine=io_uring --iodepth=16 --numjobs=1 \
          --time_based=1 --runtime=20 --direct=1 --group_reporting \
          --verify=crc32 --verify_fatal=1 --output-format=json
    """
    if not mount_path:
        raise ValueError("mount_path required for fio")
    path = os.path.join(mount_path, filename)
    cmd = ["fio","--name=ipsec",f"--filename={path}","--rw=randrw","--bs",bs,
           "--size=1G","--ioengine=io_uring","--iodepth",str(iodepth),
           "--numjobs",str(numjobs),"--time_based=1","--runtime",str(runtime),
           "--direct=1","--group_reporting","--output-format=json"]
    if verify:
        cmd += ["--verify=crc32","--verify_fatal=1"]
    return run(cmd, dry=dry)

# -------------------- Scenarios --------------------

def bring_up_transport(local_ip, remote_ip, spi_out, spi_in, cipher, key_out, key_in, auth=None, dry=False):
    """
    Transport-mode end-to-end bring-up (states + policies for both directions).

    Example final commands:
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x2001 mode transport \
        enc rfc4106(gcm(aes)) 0x<GCMKEY_OUT>
      ip xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi 0x2002 mode transport \
        enc rfc4106(gcm(aes)) 0x<GCMKEY_IN>
      ip xfrm policy add dir out src 10.0.0.1/32 dst 10.0.0.2/32 tmpl proto esp mode transport
      ip xfrm policy add dir in  src 10.0.0.2/32 dst 10.0.0.1/32 tmpl proto esp mode transport
    """
    xfrm_state_add_transport(local_ip, remote_ip, spi_out, cipher, key_out, auth, dry=dry)
    xfrm_state_add_transport(remote_ip, local_ip, spi_in,  cipher, key_in,  auth, dry=dry)
    xfrm_policy_add_transport("out", f"{local_ip}/32", f"{remote_ip}/32", dry=dry)
    xfrm_policy_add_transport("in",  f"{remote_ip}/32", f"{local_ip}/32", dry=dry)

def bring_up_tunnel(local_ip, remote_ip, spi_out, spi_in, cipher, key_out, key_in,
                    local_subnet, remote_subnet, auth=None, dry=False):
    """
    Tunnel-mode end-to-end bring-up (states + policies for both directions).

    Example final commands:
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x1101 mode tunnel \
        enc rfc4106(gcm(aes)) 0x<GCMKEY_OUT>
      ip xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi 0x1102 mode tunnel \
        enc rfc4106(gcm(aes)) 0x<GCMKEY_IN>
      ip xfrm policy add dir out src 10.1.0.0/16 dst 10.2.0.0/16 tmpl proto esp mode tunnel
      ip xfrm policy add dir in  src 10.2.0.0/16 dst 10.1.0.0/16 tmpl proto esp mode tunnel
    """
    xfrm_state_add_tunnel(local_ip, remote_ip, spi_out, cipher, key_out, auth, dry=dry)
    xfrm_state_add_tunnel(remote_ip, local_ip, spi_in,  cipher, key_in,  auth, dry=dry)
    xfrm_policy_add_tunnel("out", local_subnet, remote_subnet, dry=dry)
    xfrm_policy_add_tunnel("in",  remote_subnet, local_subnet, dry=dry)

def teardown_all(dry=False):
    """
    Flush all xfrm states and policies.

    Example final commands:
      ip xfrm state flush
      ip xfrm policy flush
    """
    xfrm_state_policy_flush(dry=dry)

def scenario_transport_flow(args):
    """
    Full transport-mode scenario:
      1) Bring up transport states/policies
      2) Optional tcpdump capture
      3) Optional netem impairment
      4) Optional ping
      5) Optional fio on mounted path
      6) Teardown

    Example final commands (subset):
      ip xfrm state add ... mode transport ...
      ip xfrm policy add ... mode transport
      tcpdump -i eth0 -w /tmp/ipsec_basic.pcap esp
      tc qdisc add dev eth0 root netem loss 2% delay 10ms reorder 5%
      ping -c 3 10.0.0.2
      fio --name=ipsec --filename=/mnt/storage_test/ipsec_test.bin --rw=randrw --bs=4k ...
      tc qdisc del dev eth0 root
      ip xfrm state flush ; ip xfrm policy flush
    """
    bring_up_transport(args.local, args.remote, args.spi_out, args.spi_in,
                       args.cipher, args.key_out, args.key_in, args.auth, dry=args.dry_run)
    if args.capture:
        start_tcpdump(args.iface, "/tmp/ipsec_basic.pcap", args.dry_run)
    try:
        if args.impair:
            if args.scope_peer:
                tc_netem_add_scoped(args.iface, args.remote, args.loss, args.delay, args.reorder, dry=args.dry_run)
            else:
                tc_netem_add_root(args.iface, args.loss, args.delay, args.reorder, dry=args.dry_run)
        if args.ping:
            print(do_ping(args.remote, count=3, dry=args.dry_run))
        if args.fio and args.mount:
            print(fio_randrw(args.mount, runtime=20, dry=args.dry_run))
    finally:
        if args.impair:
            tc_netem_clear(args.iface, dry=args.dry_run)
        if args.capture:
            stop_tcpdump()
        teardown_all(dry=args.dry_run)

def scenario_tunnel_flow(args):
    """
    Full tunnel-mode scenario:
      1) Bring up tunnel states/policies (with subnets)
      2) Optional tcpdump capture
      3) Optional netem impairment
      4) Optional ping (to endpoint/inner host)
      5) Optional fio on mounted path
      6) Teardown

    Example final commands (subset):
      ip xfrm state add ... mode tunnel ...
      ip xfrm policy add ... mode tunnel
      tcpdump -i eth0 -w /tmp/ipsec_basic.pcap esp
      tc qdisc add dev eth0 root netem loss 2% delay 10ms reorder 5%
      ping -c 3 10.0.0.2
      fio --name=ipsec --filename=/mnt/storage_test/ipsec_test.bin --rw=randrw --bs=4k ...
      tc qdisc del dev eth0 root
      ip xfrm state flush ; ip xfrm policy flush
    """
    if not (args.local_subnet and args.remote_subnet):
        raise ValueError("--local-subnet and --remote-subnet required for tunnel")
    bring_up_tunnel(args.local, args.remote, args.spi_out, args.spi_in,
                    args.cipher, args.key_out, args.key_in,
                    args.local_subnet, args.remote_subnet,
                    args.auth, dry=args.dry_run)
    if args.capture:
        start_tcpdump(args.iface, "/tmp/ipsec_basic.pcap", args.dry_run)
    try:
        if args.impair:
            if args.scope_peer:
                tc_netem_add_scoped(args.iface, args.remote, args.loss, args.delay, args.reorder, dry=args.dry_run)
            else:
                tc_netem_add_root(args.iface, args.loss, args.delay, args.reorder, dry=args.dry_run)
        if args.ping:
            print(do_ping(args.remote, count=3, dry=args.dry_run))
        if args.fio and args.mount:
            print(fio_randrw(args.mount, runtime=20, dry=args.dry_run))
    finally:
        if args.impair:
            tc_netem_clear(args.iface, dry=args.dry_run)
        if args.capture:
            stop_tcpdump()
        teardown_all(dry=args.dry_run)

# -------------------- CLI --------------------

def parse_args():
    p = argparse.ArgumentParser(description="IPsec Basic + Impairment Testing (Linux, ip xfrm + tc)")
    p.add_argument("--mode", choices=["transport","tunnel","both"], required=True, help="IPsec mode")
    p.add_argument("--local", required=True, help="Local endpoint IP (outer IP)")
    p.add_argument("--remote", required=True, help="Remote endpoint IP (outer IP)")
    p.add_argument("--local-subnet", help="Inner subnet CIDR for tunnel mode (e.g., 10.1.0.0/16)")
    p.add_argument("--remote-subnet", help="Inner subnet CIDR for tunnel mode (e.g., 10.2.0.0/16)")
    p.add_argument("--iface", required=True, help="Interface for tcpdump/tc (e.g., eth0)")

    # Crypto/SPI
    p.add_argument("--cipher", choices=["gcm","cbc"], default="gcm",
                   help="ESP cipher: 'gcm' (rfc4106(gcm(aes))) or 'cbc' (cbc(aes)+HMAC)")
    p.add_argument("--auth", default="sha256", help="Auth hash for CBC (e.g., sha256). Ignored for GCM.")
    p.add_argument("--spi-in",  required=True, help="Inbound SPI (peer->local), hex like 0x1001")
    p.add_argument("--spi-out", required=True, help="Outbound SPI (local->peer), hex like 0x1002")
    p.add_argument("--key-in",  required=True,
                   help="Inbound key material. For GCM: 0x<gcm_key_and_salt>. For CBC+HMAC: '0x<authkey>,0x<enckey>'")
    p.add_argument("--key-out", required=True,
                   help="Outbound key material. For GCM: 0x<gcm_key_and_salt>. For CBC+HMAC: '0x<authkey>,0x<enckey>'")

    # Traffic
    p.add_argument("--ping", action="store_true", help="Run a short ping check")
    p.add_argument("--fio",  action="store_true", help="Run a short fio randrw against --mount")
    p.add_argument("--mount", help="Mount path for fio (e.g., /mnt/nvme_test)")
    p.add_argument("--capture", action="store_true", help="Capture ESP with tcpdump")

    # Impairments
    p.add_argument("--impair", action="store_true", help="Enable tc netem impairment during test")
    p.add_argument("--loss", type=float, default=0.0, help="Packet loss percent (e.g., 2.0)")
    p.add_argument("--delay", type=int, default=0, help="One-way delay in ms (e.g., 10)")
    p.add_argument("--reorder", type=int, default=0, help="Reorder percent (e.g., 5)")
    p.add_argument("--scope-peer", action="store_true", help="Scope impairment to peer IP using prio+u32 filters")

    # Misc
    p.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    return p.parse_args()

def main():
    ensure_root()
    args = parse_args()

    print(f"[{ts()}] Starting IPsec test (mode={args.mode})")
    if args.mode in ("transport","both"):
        scenario_transport_flow(args)
    if args.mode in ("tunnel","both"):
        scenario_tunnel_flow(args)
    print(f"[{ts()}] Done.")

if __name__ == "__main__":
    main()
