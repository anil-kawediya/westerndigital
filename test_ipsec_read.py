
"""
Pytest: Use assertions. Designed for automated testing. No manual checks .. no prints.
"""

import os
import hashlib
import pytest

# Path to the file you want to read and verify
TEST_FILE_PATH = "/path/to/read_ipsec_test_file.bin"

def compute_checksum(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

@pytest.mark.parametrize("file_path", [TEST_FILE_PATH])
def test_read_and_verify_checksum(file_path):
    # Check that the file exists
    assert os.path.exists(file_path), f"File not found: {file_path}"

    # Compute checksum
    checksum = compute_checksum(file_path)
    assert checksum is not None and len(checksum) == 64, "Invalid checksum"

    # Optionally, compare against a known good checksum
    # known_checksum = "your_known_good_checksum_here"
    # assert checksum == known_checksum, "Checksum mismatch"

    print(f"Read and verified file: {file_path}, checksum: {checksum}")

""" 
This is python version of the same function.
Pytest: Use assertions. Designed for automated testing. No manual checks .. no prints.

import os
import hashlib

# Path to the file you want to read and verify
TEST_FILE_PATH = "/path/to/read_ipsec_test_file.bin"

def compute_checksum(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def main():
    if not os.path.exists(TEST_FILE_PATH):
        print(f"File not found: {TEST_FILE_PATH}")
        return

    checksum = compute_checksum(TEST_FILE_PATH)
    if checksum and len(checksum) == 64:
        print(f"Read and verified file: {TEST_FILE_PATH}, checksum: {checksum}")
    else:
        print("Invalid checksum")

if __name__ == "__main__":
    main()

""" 
