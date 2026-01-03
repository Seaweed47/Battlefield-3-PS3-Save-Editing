#!/usr/bin/env python3
import sys
from pathlib import Path

# CRC-32 (IEEE, reflected) polynomial
POLY = 0xEDB88320

def make_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ POLY
            else:
                crc >>= 1
        table.append(crc)
    return table


TABLE = make_table()


def bf3_custom_crc(data: bytes, skip=4):
    """Reproduces the routine from sub_4012c0."""
    crc = 0xEDCBA987  # custom initial seed

    # skip leading bytes (default: first 4)
    data = data[skip:]

    for b in data:
        crc = (crc >> 8) ^ TABLE[(crc ^ b) & 0xFF]

    # final inversion (bitwise NOT)
    return (~crc) & 0xFFFFFFFF


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {Path(sys.argv[0]).name} <file> [skip_bytes]")
        sys.exit(1)

    path = Path(sys.argv[1])
    skip = int(sys.argv[2], 0) if len(sys.argv) > 2 else 4

    data = path.read_bytes()
    crc = bf3_custom_crc(data, skip)

    print(f"File: {path}")
    print(f"Skip bytes: {skip}")
    print(f"CRC = 0x{crc:08X}")
    print(f"Bytes = {crc:02X} {crc>>16 & 0xFF:02X} ???")  # little-endian depends on format
    print(f"(decimal: {crc})")


if __name__ == "__main__":
    main()
