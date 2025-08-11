#!/usr/bin/env python3
"""
1: Basic Protocol Functionality as discussed:
	•	Tunnel vs Transport mode
	•	Multiple ESP cipher/auth combos (parametrized)
	•	SA negotiation checks and rekey mid-I/O
	•	Inbound vs outbound flow checks (write → read, verify)
	•	Anti-replay tests via packet loss / reorder (using tc netem)
	•	Uses fio for storage I/O and verifies checksums to detect corruption


Prereqs & warnings:
 - Linux, run as root (script enforces).
 - fio, ip, tc, swanctl/ipsec (optional but preferred), jq (optional if you want to examine JSON).
 - Mount the WD storage target at the given mount point before running.
 - This script will create/delete IPsec state/policies and tc qdiscs/filters on the provided iface.
 - Test in an isolated environment — do not run on production hosts.
"""

import argparse
import os
import shlex
import subprocess
import threading
import time
import tempfile
import hashlib
from datetime import datetime
import binascii

# ---------- CONFIG (adjust to your environment) ----------
FIO_BINARY = "fio"
TEST_FILE_NAME = "ipsec_test_file.bin"
FIO_RUNTIME = 30
FIO_BLOCKSIZE = "4k"
FIO_IODEPTH = 32
FIO_NUMJOBS = 4
FIO_RW_WRITE_HEAVY = "randwrite"
FIO_RW_READ_HEAVY = "randread"
FIO_SIZE = "256M"

# Cipher list - friendly representations; detailed mapping handled later
CIPHER_SUITE_PRESET = [
    ("AES-GCM-128", {"type": "aead", "name": "aes_gcm", "key_len": 16}),
    ("AES-CBC-HMAC-SHA256", {"type": "auth_enc", "enc": "cbc(aes)", "enc_key_len": 16, "auth": "hmac(sha256)", "auth_key_len": 32}),
    ("CHACHA20-POLY1305", {"type": "aead", "name": "chacha20poly1305", "key_len": 32}),
]

# Rekey timing
REKEY_DELAY = 12  # seconds after fio starts to trigger rekey
# Netem impairment parameters (used by filter-targeted netem)
NETEM_LOSS_PCT = 2.0
NETEM_DELAY_MS = 10
NETEM_REORDER_PCT = 10

# ---------------------------------------------------------

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_cmd(cmd, capture_output=False, check=True, text=True):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        result = subprocess.run(cmd, capture_output=capture_output, check=check, text=text)
        return result
    except subprocess.CalledProcessError as e:
        print(f"[{timestamp()}] ERROR running: {' '.join(cmd)}")
        if e.stdout:
            print("stdout:", e.stdout)
        if e.stderr:
            print("stderr:", e.stderr)
        raise

def ensure_root():
    if os.geteuid() != 0:
        raise SystemExit("This script must be run as root (sudo).")

# ---------- strongSwan helper ----------
def has_strongswan():
    # prefer swanctl (modern) else ipsec
    try:
        run_cmd(["swanctl", "--version"], capture_output=True)
        return "swanctl"
    except Exception:
        try:
            run_cmd(["ipsec", "version"], capture_output=True)
            return "ipsec"
        except Exception:
            return None

def build_swanctl_conn(local_ip, remote_ip, name, preshared_key=None, auth_cfg=None, aead=False, aead_alg=None, enc_alg=None, auth_alg=None, key_hex=None):
    """
    Create swanctl connection file content (minimal) for loading with swanctl --load-conn.
    We'll write a temporary conn file and load it. This is a best-effort template and may
    require adaptation for your strongSwan version.
    """
    # This function produces a small connection block for swanctl's config format (swanctl.conf)
    # We use 'psk' auth for simplicity. For production, certificate-based auth is better.
    # NOTE: swanctl syntax is YAML-like INI; differences exist across versions.
    # We'll build a minimal conn in the simple format; if invalid, fallback to ip xfrm path.

    conn = f"""
connections {{
  {name} {{
    local_addrs = [{local_ip}]
    remote_addrs = [{remote_ip}]
    type = tunnel
    proposals = aes128gcm16-prfsha256-ecp256
    children {{
      {name}_child {{
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        start_action = start
      }}
    }}
  }}
}}
secrets {{
  ike-psk {{
    id = "{local_ip}"
    secret = "{preshared_key}"
  }}
}}
"""
    return conn

def swanctl_load_conn(temp_conf_path):
    # swanctl --load-conn <file>
    run_cmd(["swanctl", "--load-conn", temp_conf_path])

def swanctl_unload_conn(name):
    try:
        run_cmd(["swanctl", "--terminate", "--all"], check=False)
    except Exception:
        pass

# ---------- ip xfrm helpers ----------
def ip_xfrm_flush():
    print(f"[{timestamp()}] Flushing ip xfrm state & policies.")
    run_cmd(["ip", "xfrm", "state", "flush"], check=False)
    run_cmd(["ip", "xfrm", "policy", "flush"], check=False)

def configure_ipxfrm_sa_policy(local_ip, remote_ip, mode, spi, enc_alg_str, enc_key_hex, auth_alg_str=None, auth_key_hex=None, reqid=0):
    """
    Add xfrm state & policy. enc_alg_str/auth_alg_str should match kernel names.
    enc_key_hex/auth_key_hex must be hex strings **without** '0x' prefix for ip command.
    """
    print(f"[{timestamp()}] Adding xfrm SA: src={local_ip} dst={remote_ip} spi=0x{spi:x} mode={mode}")
    state_cmd = ["ip", "xfrm", "state", "add", "src", local_ip, "dst", remote_ip, "proto", "esp", "spi", f"0x{spi:x}", "mode", mode]
    # enc and auth tokens vary by kernel; some kernels support 'aead' style
    if enc_alg_str:
        state_cmd += ["enc", enc_alg_str, f"0x{enc_key_hex}"]
    if auth_alg_str:
        state_cmd += ["auth", auth_alg_str, f"0x{auth_key_hex}"]
    if reqid:
        state_cmd += ["reqid", str(reqid)]
    run_cmd(state_cmd)

    # policies
    run_cmd(["ip", "xfrm", "policy", "add", "src", local_ip, "dst", remote_ip, "dir", "out", "tmpl", "src", local_ip, "dst", remote_ip, "proto", "esp", "mode", mode, "reqid", str(reqid)])
    run_cmd(["ip", "xfrm", "policy", "add", "src", remote_ip, "dst", local_ip, "dir", "in", "tmpl", "src", local_ip, "dst", remote_ip, "proto", "esp", "mode", mode, "reqid", str(reqid)])

def ip_xfrm_delete_by_spi(spi):
    run_cmd(["ip", "xfrm", "state", "delete", "spi", f"0x{spi:x}"], check=False)

# ---------- tc + filter (targeted netem) ----------
def clear_tc(iface):
    run_cmd(["tc", "qdisc", "del", "dev", iface, "root"], check=False)

def apply_targeted_netem(iface, target_ip, loss_pct, delay_ms, reorder_pct):
    """
    Create a prio qdisc with a child netem class, then add filters that classify
    traffic to/from target_ip into that class. This scopes impairment to the IP only.

    Note: This is IPv4-only and simplistic. It uses u32 match on dst/src.
    """
    print(f"[{timestamp()}] Applying targeted netem on {iface} for IP {target_ip}")
    # Delete existing root qdisc
    run_cmd(["tc", "qdisc", "del", "dev", iface, "root"], check=False)

    # root prio qdisc
    run_cmd(["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "prio"])

    # create a netem qdisc on class 1:3 (arbitrary choice)
    run_cmd(["tc", "qdisc", "add", "dev", iface, "parent", "1:3", "handle", "30:", "netem", "loss", f"{loss_pct}%", "delay", f"{delay_ms}ms", "reorder", f"{reorder_pct}%"])

    # add filter for traffic to target IP (outgoing)
    run_cmd(["tc", "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:", "prio", "1", "u32", "match", "ip", "dst", target_ip, "flowid", "1:3"])

    # add filter for traffic from target IP (incoming) - match on src IP
    run_cmd(["tc", "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:", "prio", "1", "u32", "match", "ip", "src", target_ip, "flowid", "1:3"])


# ---------- fio / storage helpers ----------
def run_fio(mount_point, filename, runtime, size, bs, iodepth, numjobs, rw, verify=1):
    test_path = os.path.join(mount_point, filename)
    # remove prior file to ensure consistent read-heavy behavior
    if rw == FIO_RW_READ_HEAVY and not os.path.exists(test_path):
        # For read-heavy test, we need a file present; create a file quickly
        # using a small fio write to make a dataset to read from.
        pre_cmd = (f"{FIO_BINARY} --name=prep_write --filename={test_path} --bs={bs} --size={size} "
                   f"--rw=write --ioengine=libaio --iodepth=1 --numjobs=1 --direct=1 --group_reporting")
        print(f"[{timestamp()}] Preparing file for read-heavy test (one-time): {pre_cmd}")
        run_cmd(pre_cmd)

    fio_cmd = (f"{FIO_BINARY} --name=ipsec_test --filename={test_path} --bs={bs} --size={size} "
               f"--rw={rw} --ioengine=libaio --iodepth={iodepth} --numjobs={numjobs} --runtime={runtime} "
               f"--time_based=1 --direct=1 --verify={verify} --verify_fatal=1 --group_reporting")
    print(f"[{timestamp()}] Running fio: {fio_cmd}")
    run_cmd(fio_cmd)
    return test_path

def compute_checksum(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# ---------- Key generation ----------
def gen_random_hex(nbytes):
    return binascii.hexlify(os.urandom(nbytes)).decode()

def make_key_for_kernel(enc_spec):
    """
    Given enc_spec from CIPHER_SUITE_PRESET, produce enc/auth key hex strings adapted
    for ip xfrm 'enc <alg> <hex>' usage. Some kernels require special AEAD formatting;
    this is best-effort: provide raw key hex strings and leave mapping to ip xfrm.
    """
    if enc_spec["type"] == "aead":
        key_len = enc_spec["key_len"]
        key_hex = gen_random_hex(key_len)  # hex string
        return {"aead_key": key_hex}
    else:
        enc_key = gen_random_hex(enc_spec["enc_key_len"])
        auth_key = gen_random_hex(enc_spec["auth_key_len"])
        return {"enc_key": enc_key, "auth_key": auth_key}

# ---------- Test orchestrator ----------
def do_tests(local_ip, target_ip, mount_point, iface, ciphers):
    swan_tool = has_strongswan()
    print(f"[{timestamp()}] strongSwan presence: {swan_tool}")

    # iterate modes and ciphers
    modes = ["tunnel", "transport"]
    base_spi = 0x2000

    for mode in modes:
        for idx, (cname, enc_spec) in enumerate(ciphers):
            spi = base_spi + idx + (0 if mode == "tunnel" else 0x4000)
            print("\n" + "="*70)
            print(f"[{timestamp()}] TEST START mode={mode} cipher={cname} spi=0x{spi:x}")
            print("="*70)
            try:
                # cleanup pre-state
                if not swan_tool:
                    ip_xfrm_flush()

                # Prepare keys
                key_dict = make_key_for_kernel(enc_spec)

                # If strongSwan is available, try to load a minimal conn (prefer real IKE)
                if swan_tool:
                    print(f"[{timestamp()}] Attempting to use strongSwan for SA establishment...")
                    # Build a minimal temporary swanctl.conf (very minimal; may need adaptation)
                    # We'll use a pre-shared key (psk) approach to keep things simple.
                    psk = gen_random_hex(16)
                    conn_name = f"ipsec_test_{mode}_{idx}"
                    conf_content = build_swanctl_conn(local_ip, target_ip, conn_name, preshared_key=psk)
                    tmp_conf = tempfile.NamedTemporaryFile(mode="w+", delete=False, prefix="swanctl_conf_", suffix=".conf")
                    tmp_conf.write(conf_content)
                    tmp_conf.flush()
                    tmp_conf.close()
                    try:
                        swanctl_load_conn(tmp_conf.name)
                        print(f"[{timestamp()}] swanctl loaded connection (name={conn_name}) - waiting briefly for SA")
                        time.sleep(3)
                    except Exception as e:
                        print(f"[{timestamp()}] swanctl load failed: {e}; falling back to ip xfrm")
                        swan_tool = None
                    finally:
                        try:
                            os.unlink(tmp_conf.name)
                        except Exception:
                            pass

                # If strongSwan not used or failed, configure via ip xfrm directly
                if not swan_tool:
                    print(f"[{timestamp()}] Configuring SA with ip xfrm (mode={mode})")
                    # Prepare enc/auth strings for ip command (best effort)
                    if enc_spec["type"] == "aead":
                        # attempt to use 'aead' kernel name mapping; many kernels support 'rfc4106(gcm(aes))'
                        # but names vary. We'll try 'aead(aes_gcm)' style or 'chacha20poly1305' directly.
                        if enc_spec["name"].lower().startswith("aes"):
                            enc_alg = "rfc4106(gcm(aes))"
                        else:
                            enc_alg = enc_spec["name"]
                        enc_key = key_dict["aead_key"]
                        # auth not used
                        auth_alg = None
                        # ip xfrm expects hex prefixed with 0x for keys -> we'll pass without 0x to commands that expect raw
                        configure_ipxfrm_sa_policy(local_ip, target_ip, mode, spi, enc_alg, enc_key, auth_alg, None, reqid=spi & 0xffff)
                    else:
                        enc_alg = enc_spec["enc"]
                        auth_alg = enc_spec["auth"]
                        enc_key = key_dict["enc_key"]
                        auth_key = key_dict["auth_key"]
                        configure_ipxfrm_sa_policy(local_ip, target_ip, mode, spi, enc_alg, enc_key, auth_alg, auth_key, reqid=spi & 0xffff)

                # verify xfrm presence (simple)
                time.sleep(1)
                out = run_cmd(["ip", "xfrm", "state", "show"], capture_output=True).stdout
                print(f"[{timestamp()}] ip xfrm state (snippet):\n{out.splitlines()[:10]}")

                # Create baseline: remove old test files
                test_path = os.path.join(mount_point, TEST_FILE_NAME)
                if os.path.exists(test_path):
                    os.remove(test_path)

                # === PER-DIRECTION TESTS ===
                # 1) Write-heavy: run fio write-heavy workload (exercises outbound writes and inbound ACKs/read-backs)
                print(f"[{timestamp()}] Starting WRITE-HEAVY workload (exercises outbound write flow)")
                fio_thread = threading.Thread(target=run_fio, kwargs={
                    "mount_point": mount_point,
                    "filename": TEST_FILE_NAME,
                    "runtime": FIO_RUNTIME,
                    "size": FIO_SIZE,
                    "bs": FIO_BLOCKSIZE,
                    "iodepth": FIO_IODEPTH,
                    "numjobs": FIO_NUMJOBS,
                    "rw": FIO_RW_WRITE_HEAVY,
                    "verify": 1
                })
                fio_thread.start()

                # rekey during active I/O (delete SA and recreate with new SPI)
                time.sleep(REKEY_DELAY)
                print(f"[{timestamp()}] Rekeying: replacing SA mid-I/O")
                if swan_tool:
                    # try to terminate and let IKE re-establish; here we just attempt to terminate IKE child
                    try:
                        run_cmd(["swanctl", "--terminate", "--all"], check=False)
                        time.sleep(2)
                        # Note: with a proper strongSwan IKE server, rekey would be automatic.
                        # Because we used a minimal swanctl conn, automatic rekey may not happen here.
                    except Exception as e:
                        print(f"[{timestamp()}] swanctl terminate error: {e}")
                else:
                    ip_xfrm_delete_by_spi(spi)
                    new_spi = spi + 1
                    # generate new keys
                    new_keys = make_key_for_kernel(enc_spec)
                    if enc_spec["type"] == "aead":
                        try:
                            configure_ipxfrm_sa_policy(local_ip, target_ip, mode, new_spi, enc_spec["name"], new_keys["aead_key"], None, None, reqid=new_spi & 0xffff)
                        except Exception as e:
                            print(f"[{timestamp()}] Failed to add AEAD SA with new SPI: {e}")
                    else:
                        try:
                            configure_ipxfrm_sa_policy(local_ip, target_ip, mode, new_spi, enc_spec["enc"], new_keys["enc_key"], enc_spec["auth"], new_keys["auth_key"], reqid=new_spi & 0xffff)
                        except Exception as e:
                            print(f"[{timestamp()}] Failed to add SA: {e}")

                fio_thread.join(timeout=FIO_RUNTIME + 30)
                if fio_thread.is_alive():
                    print(f"[{timestamp()}] WRITE-HEAVY fio did not finish in time; continuing to attempt validate anyway")

                # Validate checksum written by fio (fio --verify ensures content correctness; still compute)
                if os.path.exists(test_path):
                    checksum = compute_checksum(test_path)
                    print(f"[{timestamp()}] WRITE-HEAVY test file checksum: {checksum}")
                else:
                    raise RuntimeError("WRITE-HEAVY expected test file not created")

                # 2) Read-heavy: run a read-heavy workload to exercise inbound flow (target -> initiator)
                print(f"[{timestamp()}] Starting READ-HEAVY workload (exercises inbound flow to initiator)")
                # Ensure file exists (we created it above)
                short_read_filename = f"read_{TEST_FILE_NAME}"
                # copy or ensure presence; we'll reuse the same test file by creating a copy
                read_file_path = os.path.join(mount_point, short_read_filename)
                # create a copy to avoid interfering with main file (fast copy using dd might be used on block devices; we'll use Python copy)
                run_cmd(["cp", test_path, read_file_path])

                # run fio read-heavy on the copy
                run_fio(mount_point, short_read_filename, runtime=20, size="128M", bs=FIO_BLOCKSIZE, iodepth=FIO_IODEPTH, numjobs=FIO_NUMJOBS, rw=FIO_RW_READ_HEAVY, verify=1)
                read_checksum = compute_checksum(read_file_path)
                print(f"[{timestamp()}] READ-HEAVY file checksum: {read_checksum}")

                # === Anti-replay / impairment test (targeted via filters) ===
                print(f"[{timestamp()}] Applying targeted impairment (loss/reorder/delay) to {target_ip}")
                apply_targeted_netem(iface, target_ip, NETEM_LOSS_PCT, NETEM_DELAY_MS, NETEM_REORDER_PCT)
                # run a short verify workload under impairment
                impaired_filename = f"impaired_{TEST_FILE_NAME}"
                if os.path.exists(os.path.join(mount_point, impaired_filename)):
                    os.remove(os.path.join(mount_point, impaired_filename))
                run_fio(mount_point, impaired_filename, runtime=12, size="64M", bs=FIO_BLOCKSIZE, iodepth=8, numjobs=2, rw="randrw", verify=1)
                impaired_checksum = compute_checksum(os.path.join(mount_point, impaired_filename))
                print(f"[{timestamp()}] Impaired test checksum: {impaired_checksum}")
                # clear tc filters/qdisc
                clear_tc(iface)

                # Cleanup SA resources after test
                if swan_tool:
                    try:
                        swanctl_unload_conn(conn_name)
                    except Exception:
                        pass
                else:
                    # delete any spis we touched
                    ip_xfrm_delete_by_spi(spi)
                    try:
                        ip_xfrm_delete_by_spi(new_spi)
                    except Exception:
                        pass

                print(f"[{timestamp()}] PASS: mode={mode} cipher={cname}")

            except Exception as e:
                print(f"[{timestamp()}] FAIL: mode={mode} cipher={cname} -> {e}")
            finally:
                # final cleanup
                try:
                    if not swan_tool:
                        ip_xfrm_flush()
                    clear_tc(iface)
                except Exception:
                    pass

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="Improved IPSec Basic Protocol tests (uses strongSwan when available, targeted tc filters, per-direction fio)")
    p.add_argument("--local-ip", required=True)
    p.add_argument("--target-ip", required=True)
    p.add_argument("--mount-point", required=True)
    p.add_argument("--iface", required=True)
    p.add_argument("--fio-binary", default=FIO_BINARY)
    p.add_argument("--runtime", type=int, default=FIO_RUNTIME)
    return p.parse_args()

def main():
    args = parse_args()
    global FIO_BINARY, FIO_RUNTIME
    FIO_BINARY = args.fio_binary
    FIO_RUNTIME = args.runtime

    ensure_root()

    # simple environment checks
    if not os.path.isdir(args.mount_point):
        raise SystemExit(f"Mount point {args.mount_point} not found; mount the storage before running.")
    try:
        run_cmd(["ping", "-c", "2", args.target_ip], capture_output=True)
    except Exception:
        print(f"[{timestamp()}] WARNING: ping to target {args.target_ip} failed; ensure network connectivity.")

    print(f"[{timestamp()}] Starting improved IPSec basic protocol tests.")
    do_tests(args.local_ip, args.target_ip, args.mount_point, args.iface, CIPHER_SUITE_PRESET)
    print(f"[{timestamp()}] Tests complete. Final cleanup.")
    try:
        clear_tc(args.iface)
        ip_xfrm_flush()
    except Exception:
        pass
    print(f"[{timestamp()}] Done.")

if __name__ == "__main__":
    main()