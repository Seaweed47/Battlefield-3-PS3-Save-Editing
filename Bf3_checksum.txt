#!/usr/bin/env python3
"""
BF3 PS3 Save — In-Place Checksum Patcher
- Computes CRC32 over bytes[4:]
- First 4 bytes store checksum (big-endian)
- Polynomial: 0xEDB88320
- Initial seed: 0xEDCBA987
- Final output: bitwise-NOT (~crc & 0xFFFFFFFF)

Usage:
    python Bf3_checksum.py USR-DATA
"""

import sys
import struct
from pathlib import Path

POLY = 0xEDB88320
INITIAL = 0xEDCBA987


def make_crc32_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ POLY
            else:
                crc >>= 1
        table.append(crc & 0xFFFFFFFF)
    return table


CRC_TABLE = make_crc32_table()


def bf3_crc32(buf: bytes) -> int:
    """Battlefield 3 PS3 CRC algorithm."""
    crc = INITIAL
    table = CRC_TABLE
    for b in buf:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFFFFFF  # final bitwise-NOT


def read_stored_checksum(buf: bytes) -> int:
    """Checksum is stored big-endian in first 4 bytes."""
    return struct.unpack(">I", buf[:4])[0]


def write_checksum_be(crc: int) -> bytes:
    """Return 4-byte big-endian checksum field."""
    return struct.pack(">I", crc)


def Bf3_checksum(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    data = path.read_bytes()

    stored = read_stored_checksum(data)
    computed = bf3_crc32(data[4:])

    print(f"File: {path}")
    print(f"Stored   = 0x{stored:08X}")
    print(f"Computed = 0x{computed:08X}")

    if stored == computed:
            print("Status   = OK — checksum already valid")
            return

    print("Status   = FIXING — writing new checksum…")

    patched = write_checksum_be(computed) + data[4:]
    path.write_bytes(patched)

    print("Done — checksum patched in place.")
    print(f"New checksum = 0x{computed:08X}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python Bf3_checksum.py USR-DATA")
        sys.exit(1)

    path = Path(sys.argv[1])
    Bf3_checksum(path)


if __name__ == "__main__":
    main()
