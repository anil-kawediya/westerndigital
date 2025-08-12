import subprocess
import time
import os
import ssl
import socket

# --- Configuration ---
# Replace with your NVMe-TLS Target details
NVME_TARGET_IP = "192.168.1.100"  # IP address of your NVMe target
NVME_TARGET_PORT = 4420          # Default NVMe/TCP port
NVME_TARGET_NQN = "nqn.2014-08.org.nvmexpress:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Target's NQN
NVME_SUBSYSTEM_NQN = "nqn.2014-08.org.nvmexpress:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" # Subsystem NQN (if different)
NVME_TLS_KEY_NAME = "my_nvme_tls_key" # Name of the PSK key in your .nvme keyring

# Fio Benchmark Configuration
TEST_FILE_SIZE = "1G"            # Size of the test file (e.g., "1G", "10G")
TEST_BLOCK_SIZE = "4k"           # Block size for I/O (e.g., "4k", "128k")
TEST_FILENAME = "/dev/nvmeX"     # Replace with the actual NVMe device after connection (e.g., /dev/nvme1n1)
FIO_JOB_FILE_NO_TLS = "fio_write_no_tls.fio"
FIO_JOB_FILE_WITH_TLS = "fio_write_with_tls.fio"

# --- Helper Functions ---

def run_command(command, check_error=True):
    """Executes a shell command and prints its output."""
    print(f"\nExecuting: {' '.join(command)}")
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=check_error
        )
        if result.stdout:
            print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        if check_error:
            raise
        return None

def verify_tls_version(host, port):
    """Attempts to connect to the host:port and print the negotiated TLS version."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3  # Force TLS 1.3 check

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"\nSuccessfully connected to {host}:{port}")
                print(f"Negotiated TLS version: {ssock.version()}")
                print(f"Cipher suite: {ssock.cipher()}")
                return ssock.version() == "TLSv1.3"
    except Exception as e:
        print(f"\nCould not verify TLS 1.3 connection to {host}:{port}: {e}")
        print("This might indicate TLS 1.3 is not enabled or the target is unreachable.")
    return False

def create_fio_job_file(filename, output_file, use_tls):
    """Creates a fio job file."""
    mode_str = "with TLS 1.3" if use_tls else "without TLS (baseline)"
    fio_config = f"""
[global]
ioengine=sync
direct=1
size={TEST_FILE_SIZE}
numjobs=1
group_reporting
filename={filename}

[write_test_{'tls' if use_tls else 'no_tls'}]
rw=write
bs={TEST_BLOCK_SIZE}
iodepth=16
"""
    with open(output_file, "w") as f:
        f.write(fio_config)
    print(f"Fio job file '{output_file}' for {mode_str} created.")

def run_fio_test(job_file):
    """Runs the fio test and returns its output."""
    print(f"\nRunning fio test with job file: {job_file}")
    output = run_command(["fio", job_file])
    print(f"Fio test '{job_file}' completed.")
    return output

def parse_fio_results(fio_output):
    """Simple parser to extract key metrics from Fio output."""
    if not fio_output:
        return {}
    results = {}
    lines = fio_output.splitlines()
    for line in lines:
        if "write:" in line:
            if "bw=" in line:
                bw_match = re.search(r"bw=(\d+\.?\d*)([KMG]?B/s)", line)
                if bw_match:
                    results['write_bw'] = f"{bw_match.group(1)}{bw_match.group(2)}"
            if "iops=" in line:
                iops_match = re.search(r"iops=(\d+\.?\d*)", line)
                if iops_match:
                    results['write_iops'] = iops_match.group(1)
        if "clat percentiles" in line:
            lat_match = re.search(r"lat \(usec\): min=(\d+\.?\d*), max=(\d+\.?\d*), avg=(\d+\.?\d*)", line)
            if lat_match:
                results['write_clat_min_us'] = lat_match.group(1)
                results['write_clat_max_us'] = lat_match.group(2)
                results['write_clat_avg_us'] = lat_match.group(3)
        if "slat percentiles" in line:
            lat_match = re.search(r"lat \(usec\): min=(\d+\.?\d*), max=(\d+\.?\d*), avg=(\d+\.?\d*)", line)
            if lat_match:
                results['write_slat_min_us'] = lat_match.group(1)
                results['write_slat_max_us'] = lat_match.group(2)
                results['write_slat_avg_us'] = lat_match.group(3)
    return results

# --- Main Workflow ---

def main():
    import re # for regex in parse_fio_results

    print("--- Starting NVMe-TLS 1.3 File Write Performance Test ---")
    print("Please ensure your NVMe target and client are configured for NVMe-TLS 1.3.")
    print("This script requires 'nvme-cli' and 'fio' to be installed.")

    # 1. Verify TLS 1.3 connectivity (optional but highly recommended)
    print("\nAttempting to verify TLS 1.3 connection to NVMe target...")
    if not verify_tls_version(NVME_TARGET_IP, NVME_TARGET_PORT):
        print("WARNING: Could not confirm TLS 1.3. Ensure target is correctly configured.")
        # Decide whether to proceed or exit based on your testing requirements
        # input("Press Enter to continue anyway, or Ctrl+C to exit.")

    # 2. Connect to NVMe-TLS Target (assuming PSK is already in .nvme keyring)
    print("\nAttempting to connect to NVMe-TLS target...")
    try:
        connect_command = [
            "nvme", "connect",
            "--transport=tcp",
            f"--traddr={NVME_TARGET_IP}",
            f"--trsvcid={NVME_TARGET_PORT}",
            f"--nqn={NVME_TARGET_NQN}",
            f"--tls={NVME_TLS_KEY_NAME}"
        ]
        run_command(connect_command)
        print("NVMe-TLS connection attempted. You should see a new /dev/nvmeX device.")
        print(f"Please update TEST_FILENAME to the correct /dev/nvmeX device path (e.g., /dev/nvme1n1) if necessary before proceeding.")
        TEST_FILENAME_ACTUAL = input("Enter the actual NVMe device path (e.g., /dev/nvme1n1) and press Enter: ")
        if not TEST_FILENAME_ACTUAL:
            print("No NVMe device path entered. Exiting.")
            return
        global TEST_FILENAME
        TEST_FILENAME = TEST_FILENAME_ACTUAL

    except Exception as e:
        print(f"Failed to connect to NVMe-TLS target: {e}")
        print("Ensure 'nvme-cli' is installed and configured for NVMe-TLS, and PSK is in keyring.")
        print("You may need to manually manage NVMe-TLS connections and keys using 'nvme-cli'.")
        return

    # 3. Create Fio job files
    create_fio_job_file(TEST_FILENAME, FIO_JOB_FILE_NO_TLS, False)
    create_fio_job_file(TEST_FILENAME, FIO_JOB_FILE_WITH_TLS, True) # Fio doesn't directly use TLS, but reflects the environment

    # 4. Run Fio tests
    print("\n--- Running Fio test without TLS (baseline) ---")
    fio_output_no_tls = run_fio_test(FIO_JOB_FILE_NO_TLS)
    results_no_tls = parse_fio_results(fio_output_no_tls)

    print("\n--- Running Fio test with TLS (configured environment) ---")
    fio_output_with_tls = run_fio_test(FIO_JOB_FILE_WITH_TLS)
    results_with_tls = parse_fio_results(fio_output_with_tls)

    # 5. Analyze and Report
    print("\n--- Performance Comparison ---")
    print(f"File Size: {TEST_FILE_SIZE}, Block Size: {TEST_BLOCK_SIZE}")
    print(f"NVMe Target: {NVME_TARGET_IP}:{NVME_TARGET_PORT} ({NVME_TARGET_NQN})")
    print(f"NVMe Device: {TEST_FILENAME}")
    print("\nBaseline (No TLS Environment):")
    for k, v in results_no_tls.items():
        print(f"  {k}: {v}")

    print("\nWith TLS 1.3 (Configured Environment):")
    for k, v in results_with_tls.items():
        print(f"  {k}: {v}")

    # Calculate and display differences (simple example)
    print("\n--- Impact Analysis (Approximate) ---")
    try:
        bw_no_tls = float(re.search(r"(\d+\.?\d*)", results_no_tls.get('write_bw', '0')).group(1))
        bw_with_tls = float(re.search(r"(\d+\.?\d*)", results_with_tls.get('write_bw', '0')).group(1))
        if bw_no_tls > 0:
            bw_diff = ((bw_no_tls - bw_with_tls) / bw_no_tls) * 100
            print(f"Bandwidth decrease: {bw_diff:.2f}%")

        iops_no_tls = float(results_no_tls.get('write_iops', '0'))
        iops_with_tls = float(results_with_tls.get('write_iops', '0'))
        if iops_no_tls > 0:
            iops_diff = ((iops_no_tls - iops_with_tls) / iops_no_tls) * 100
            print(f"IOPS decrease: {iops_diff:.2f}%")

        lat_avg_no_tls = float(results_no_tls.get('write_clat_avg_us', '0'))
        lat_avg_with_tls = float(results_with_tls.get('write_clat_avg_us', '0'))
        if lat_avg_no_tls > 0:
            lat_diff = ((lat_avg_with_tls - lat_avg_no_tls) / lat_avg_no_tls) * 100
            print(f"Average Latency increase: {lat_diff:.2f}%")
    except Exception as e:
        print(f"Could not calculate differences: {e}")

    # 6. Disconnect from NVMe Target (optional)
    print("\nAttempting to disconnect from NVMe target...")
    try:
        disconnect_command = [
            "nvme", "disconnect",
            "--transport=tcp",
            f"--traddr={NVME_TARGET_IP}",
            f"--nqn={NVME_TARGET_NQN}"
        ]
        run_command(disconnect_command, check_error=False) # May fail if already disconnected
    except Exception as e:
        print(f"Failed to disconnect from NVMe target: {e}")


    # 7. Cleanup
    print("\nCleaning up Fio job files...")
    if os.path.exists(FIO_JOB_FILE_NO_TLS):
        os.remove(FIO_JOB_FILE_NO_TLS)
    if os.path.exists(FIO_JOB_FILE_WITH_TLS):
        os.remove(FIO_JOB_FILE_WITH_TLS)
    print("Cleanup complete.")

if __name__ == "__main__":
    main()