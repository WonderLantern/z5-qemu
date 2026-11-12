# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the explicitly synthetic C1.50 region 0x4a experiment input."""
import argparse
import hashlib
from pathlib import Path
from publication_paths import output_root

ROOT = Path(__file__).resolve().parents[2]
SIZE = 0x180000
VERSION_OFFSET = 0xB8012


def make_input():
    # Zeroes are functional assumptions, not known neutral factory data.
    data = bytearray(SIZE)
    data[VERSION_OFFSET] = 0x19
    data[-4:] = b'ENDM'
    return bytes(data)


def validate_input(data):
    if len(data) != SIZE:
        raise ValueError('synthetic input size mismatch')
    if data != make_input():
        raise ValueError('not the declared synthetic profile')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(output_root()):
        parser.error('output file must be below output/')
    data = make_input()
    with out.open('xb') as stream:
        stream.write(data)
    print(f'synthetic assumption-only profile sha256={hashlib.sha256(data).hexdigest()} camera_verified=false')


if __name__ == '__main__':
    main()
