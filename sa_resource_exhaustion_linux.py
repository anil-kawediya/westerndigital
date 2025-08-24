#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sa_resource_exhaustion_linux.py

Purpose:
  Probe firmware/kernel/driver IPsec resource limits by creating many ESP SAs
  (and matching policies) until the system refuses new entries, then report the
  maximum count reached. Supports transport or tunnel mode.

Scenarios:
  - state_only: create states only (no policies) to find raw SA capacity.
  - state_policy: create states + policies (default), closer to real use.

Safety:
  - Use --dry-run to preview commands first.
  - Use --cleanup to flush SAs/policies at the end.
  - Prefer a lab box; mass xfrm entries can impact live traffic.

Examples:
  # Transport, create states+policies until failure starting SPI 0x4000
  sudo ./sa_resource_exhaustion_linux.py --mode transport \
       --local 10.0.0.1 --remote 10.0.0.2 \
       --cipher gcm --key-template 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEF00000000 \
       --spi-base 0x4000 --until-fail --cleanup

  # Tunnel with subnets, cap to 200 pairs, dry-run
  sudo ./sa_resource_exhaustion_linux.py --mode tunnel \
       --local 10.0.0.1 --remote 10.0.0.2 \
       --local-subnet 10.1.0.0/16 --remote-subnet 10.2.0.0/16 \
       --cipher gcm --key-template 0xFEEDFACEFEEDFACEFEEDFACEFEEDFACE11111111 \
       --max-pairs 200 --dry-run
"""

import argparse, os, shlex, subprocess, sys, time
from datetime import datetime

def run(cmd, check=True, capture=True, dry=False):
    """
    Execute a shell command (supports dry-run).

    Example final command:
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x4001 mode transport \
        enc rfc4106(gcm(aes)) 0xDEADBEEF...00000000
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

# ---------------- xfrm helpers ----------------

def add_state(src, dst, spi_hex, mode, cipher, key_hex, auth=None, reqid=None, dry=False):
    """
    Add ESP xfrm state with chosen mode and cipher.

    AES-GCM example (transport):
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x4001 mode transport \
        enc rfc4106(gcm(aes)) 0x<gcm_key_and_salt> reqid 4001

    AES-CBC+HMAC example (tunnel):
      ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi 0x5001 mode tunnel \
        auth hmac(sha256) 0x<authkey> enc cbc(aes) 0x<enckey> reqid 5001
    """
    if cipher == "gcm":
        cmd = ["ip","xfrm","state","add","src",src,"dst",dst,"proto","esp",
               "spi",spi_hex,"mode",mode,
               "enc","rfc4106(gcm(aes))", key_hex]
    elif cipher == "cbc":
        if not auth:
            raise ValueError("auth required for CBC+HMAC")
        # Expect key_hex format: "0xAUTHKEY,0xENCKEY"
        auth_key, enc_key = key_hex.split(",", 1)
        cmd = ["ip","xfrm","state","add","src",src,"dst",dst,"proto","esp",
               "spi",spi_hex,"mode",mode,
               "auth",f"hmac({auth})", auth_key,
               "enc","cbc(aes)", enc_key]
    else:
        raise ValueError("cipher must be gcm or cbc")
    if reqid is not None:
        cmd += ["reqid", str(reqid)]
    run(cmd, capture=False, dry=dry)

def add_policy(direction, mode, src_sel, dst_sel, reqid=None, dry=False):
    """
    Add xfrm policy for a direction with a template.

    Transport example:
      ip xfrm policy add dir out src 10.0.0.1/32 dst 10.0.0.2/32 \
        tmpl proto esp mode transport reqid 4001

    Tunnel example:
      ip xfrm policy add dir in  src 10.2.0.0/16 dst 10.1.0.0/16 \
        tmpl proto esp mode tunnel reqid 5001
    """
    cmd = ["ip","xfrm","policy","add","dir",direction,"src",src_sel,"dst",dst_sel,
           "tmpl","proto","esp","mode",mode]
    if reqid is not None:
        cmd += ["reqid", str(reqid)]
    run(cmd, capture=False, dry=dry)

def flush_all(dry=False):
    """
    Flush all states and policies.

    Example final commands:
      ip xfrm state flush
      ip xfrm policy flush
    """
    run(["ip","xfrm","state","flush"], capture=False, dry=dry)
    run(["ip","xfrm","policy","flush"], capture=False, dry=dry)

def show_counts():
    """
    Return (state_count, policy_count) via `ip xfrm ... | wc -l`.

    Example final commands:
      ip xfrm state show
      ip xfrm policy show
    """
    try:
        s = run(["bash","-lc","ip xfrm state show | wc -l"])
        p = run(["bash","-lc","ip xfrm policy show | wc -l"])
        return int(s.strip()), int(p.strip())
    except Exception:
        return -1, -1

# ------------- exhaustion loop -------------

def try_add_pair(idx, args, dry=False):
    """
    Add one *pair* of SAs (outbound + inbound) and (optionally) two policies.

    TRANSPORT (selectors are /32 host IPs):
      ip xfrm state add src <local> dst <remote> proto esp spi <spi_out> mode transport ... reqid <reqid>
      ip xfrm state add src <remote> dst <local> proto esp spi <spi_in>  mode transport ... reqid <reqid>
      ip xfrm policy add dir out src <local>/32  dst <remote>/32 tmpl proto esp mode transport reqid <reqid>
      ip xfrm policy add dir in  src <remote>/32 dst <local>/32  tmpl proto esp mode transport reqid <reqid>

    TUNNEL (selectors are subnets):
      ip xfrm state add src <local> dst <remote> proto esp spi <spi_out> mode tunnel ... reqid <reqid>
      ip xfrm state add src <remote> dst <local> proto esp spi <spi_in>  mode tunnel ... reqid <reqid>
      ip xfrm policy add dir out src <local_subnet>  dst <remote_subnet> tmpl proto esp mode tunnel reqid <reqid>
      ip xfrm policy add dir in  src <remote_subnet> dst <local_subnet>  tmpl proto esp mode tunnel reqid <reqid>
    """
    spi_out = f"0x{args.spi_base + (2*idx):x}"
    spi_in  = f"0x{args.spi_base + (2*idx) + 1:x}"
    reqid   = args.reqid_base + idx if args.use_reqid else None
    mode = args.mode

    # Build key material per-index if requested (e.g., salt last bytes vary)
    key_out = args.key_template
    key_in  = args.key_template
    if args.vary_key:
        # crude suffix change: replace last 4 hex chars with idx
        def vary(hexkey, bump):
            s = hexkey[2:] if hexkey.startswith("0x") else hexkey
            s = s[:-4] + f"{(bump & 0xffff):04x}"
            return "0x"+s
        if args.cipher == "gcm":
            key_out = vary(args.key_template, 2*idx)
            key_in  = vary(args.key_template, 2*idx+1)
        elif args.cipher == "cbc":
            ak, ek = args.key_template.split(",",1)
            ak = vary(ak, 2*idx)
            ek = vary(ek, 2*idx+1)
            key_out = ",".join([ak, ek])
            key_in  = ",".join([ak, ek])

    # Add states
    add_state(args.local, args.remote, spi_out, mode, args.cipher, key_out, auth=args.auth, reqid=reqid, dry=dry)
    add_state(args.remote, args.local, spi_in,  mode, args.cipher, key_in,  auth=args.auth, reqid=reqid, dry=dry)

    # Add policies if enabled
    if args.with_policy:
        if mode == "transport":
            add_policy("out", mode, f"{args.local}/32",  f"{args.remote}/32", reqid=reqid, dry=dry)
            add_policy("in",  mode, f"{args.remote}/32", f"{args.local}/32",  reqid=reqid, dry=dry)
        else:  # tunnel
            if not (args.local_subnet and args.remote_subnet):
                raise ValueError("--local-subnet and --remote-subnet required for tunnel mode when policies are enabled.")
            add_policy("out", mode, args.local_subnet,  args.remote_subnet, reqid=reqid, dry=dry)
            add_policy("in",  mode, args.remote_subnet, args.local_subnet,  reqid=reqid, dry=dry)

def exhaust(args):
    """
    Loop creating SA pairs until failure (or until --max-pairs reached).
    Returns (pairs_created, last_error).
    """
    created = 0
    err_msg = ""
    for i in range(args.max_pairs if not args.until_fail else (args.max_pairs or 1_000_000_000)):
        try:
            try_add_pair(i, args, dry=args.dry_run)
            created += 1
            if args.progress and not args.dry_run:
                if created % args.progress == 0:
                    sct, pct = show_counts()
                    print(f"[{ts()}] Created pairs={created}  (states={sct}, policies={pct})")
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() if e.stderr else str(e)
            print(f"[{ts()}] Creation failed at pair {i} -> {err_msg}")
            break
        except Exception as e:
            err_msg = str(e)
            print(f"[{ts()}] Creation failed at pair {i} -> {err_msg}")
            break
        if not args.until_fail and created >= args.max_pairs:
            break
    return created, err_msg

def main():
    ensure_root()
    ap = argparse.ArgumentParser(description="IPsec SA Resource Exhaustion (Linux, ip xfrm)")
    ap.add_argument("--mode", choices=["transport","tunnel"], required=True, help="IPsec mode for SAs/policies")
    ap.add_argument("--local", required=True, help="Local outer IP")
    ap.add_argument("--remote", required=True, help="Remote outer IP")
    ap.add_argument("--local-subnet", help="Tunnel inner src CIDR (e.g., 10.1.0.0/16)")
    ap.add_argument("--remote-subnet", help="Tunnel inner dst CIDR (e.g., 10.2.0.0/16)")

    ap.add_argument("--cipher", choices=["gcm","cbc"], default="gcm")
    ap.add_argument("--auth", default="sha256", help="Auth hash for CBC+HMAC (ignored for GCM)")
    ap.add_argument("--key-template", required=True,
                    help="For GCM: 0x<gcm_key_and_salt>. For CBC+HMAC: '0x<authkey>,0x<enckey>'")
    ap.add_argument("--vary-key", action="store_true",
                    help="Vary last 2 bytes of key per pair (simple salt/key change)")

    ap.add_argument("--spi-base", type=lambda x:int(x,0), default=0x4000,
                    help="Base SPI (hex allowed). Outbound uses base+2*i; inbound base+2*i+1")
    ap.add_argument("--reqid-base", type=int, default=4000, help="Base reqid (increment per pair)")
    ap.add_argument("--use-reqid", action="store_true", help="Attach reqid to states/policies")

    ap.add_argument("--with-policy", action="store_true", help="Create policies for each state pair (recommended)")
    ap.add_argument("--max-pairs", type=int, default=0, help="Upper cap on pairs (0=unbounded)")
    ap.add_argument("--until-fail", action="store_true", help="Keep adding until a failure occurs")
    ap.add_argument("--progress", type=int, default=100, help="Print counts every N pairs (0=disable)")

    ap.add_argument("--dry-run", action="store_true", help="Print final commands but do not execute")
    ap.add_argument("--cleanup", action="store_true", help="Flush all xfrm states/policies at end")
    args = ap.parse_args()

    print(f"[{ts()}] Starting SA exhaustion test: mode={args.mode} policies={args.with_policy} vary_key={args.vary_key}")
    if args.mode == "tunnel" and args.with_policy:
        if not (args.local_subnet and args.remote_subnet):
            sys.exit("--local-subnet and --remote-subnet required for tunnel mode with policies.")

    pre_states, pre_policies = show_counts()
    print(f"[{ts()}] Pre: states={pre_states} policies={pre_policies}")

    created, err = exhaust(args)

    post_states, post_policies = show_counts()
    print(f"[{ts()}] Post: states={post_states} policies={post_policies}")
    print(f"[{ts()}] Result: created_pairs={created}  last_error='{err}'")

    if args.cleanup:
        print(f"[{ts()}] Cleanup: flushing all xfrm states/policies")
        flush_all(dry=args.dry_run)
        sct, pct = show_counts()
        print(f"[{ts()}] After cleanup: states={sct} policies={pct}")

if __name__ == "__main__":
    main()
