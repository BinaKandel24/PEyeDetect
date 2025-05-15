import os
import pefile
import hashlib
from datetime import datetime

def get_file_details(file_path):
    details = {}

    # Basic file info
    details['file_name'] = os.path.basename(file_path)
    details['file_extension'] = os.path.splitext(file_path)[1]
    details['file_size_bytes'] = os.path.getsize(file_path)

    # Compute SHA256 hash
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    details['sha256'] = sha256_hash

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        details['error'] = "Not a valid PE file."
        return details
    finally:
        if 'pe' in locals():
            pe.close()

    # Timestamp (compile time)
    timestamp = pe.FILE_HEADER.TimeDateStamp
    local_time = datetime.fromtimestamp(timestamp)
    details['compile_time'] = local_time.strftime('%Y-%m-%d %H:%M:%S %Z')

    # Machine architecture
    machine = pe.FILE_HEADER.Machine
    machine_types = {
        0x014c: "Intel 386",
        0x8664: "x64",
        0x01c0: "ARM",
        0x01c4: "ARMv7",
        0xAA64: "ARM64",
    }
    details['machine'] = machine_types.get(machine, hex(machine))
    return details