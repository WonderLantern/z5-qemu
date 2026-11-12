# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace whether an injected native input record was consumed, using RAM dumps only.

    input_taint.py <run-directory> [--submit ADDRESS] [--stride 0x34]

`boot_probe --dump-ram ADDR:SIZE` writes `ram-<addr>-<size>.bin` when a run ends. This
tool extracts the record the probe submitted (the encoder block at +0x20 and the whole
0x34-byte record) and reports every place either pattern appears in the dump.

Interpretation: the submit call itself writes only the first record, so an extra copy
elsewhere was made by firmware code. That proves the record was read and republished; it
does not by itself prove that any individual field, such as one encoder count, is diffed.

Standard library only, so it runs under the WSL python3 as well as the reverse venv.
"""
import argparse
import struct
import sys
from pathlib import Path

SUBMIT_STRUCT = 0xC1F995C4
ENCODERS_AT = 0x20
RECORD = 0x34


def regions(directory):
    """Load `ram-<addr>-<size>.bin` dumps as (base, size, bytes)."""
    loaded = []
    for path in sorted(Path(directory).glob('ram-*.bin')):
        parts = path.stem.split('-')
        if len(parts) != 3 or parts[0] != 'ram':
            raise ValueError(f'unexpected dump name {path.name}')
        loaded.append((int(parts[1], 16), int(parts[2], 16), path.read_bytes()))
    if not loaded:
        raise ValueError(f'no ram-*.bin dumps in {directory}')
    return loaded


def read(loaded, address, length):
    for base, size, data in loaded:
        if base <= address and address + length <= base + size:
            return data[address - base:address - base + length]
    raise ValueError(f'{address:#x}+{length:#x} is not covered by any dump')


def occurrences(loaded, needle):
    """Every absolute address where `needle` appears."""
    found = []
    for base, _size, data in loaded:
        start = 0
        while True:
            index = data.find(needle, start)
            if index < 0:
                break
            found.append(base + index)
            start = index + 1
    return found


# Fill patterns whose bytes contain common sentinels as a substring. 0xdeadbeef ends in
# the halfword 0xbeef, so a bare 16-bit search reports uninitialised memory as taint.
FILLERS = (0xDEADBEEF,)


def filler_words(loaded):
    """How many filler words the dumps contain, i.e. the contamination risk."""
    total = 0
    for pattern in FILLERS:
        needle = struct.pack('<I', pattern)
        for _base, _size, data in loaded:
            start = 0
            while True:
                index = data.find(needle, start)
                if index < 0:
                    break
                total += 1
                start = index + 1
    return total


def sentinel_hits(loaded, value, width=4):
    """Addresses where `value` appears as a `width`-byte word."""
    needle = value.to_bytes(width, 'little')
    return occurrences(loaded, needle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--submit', default=hex(SUBMIT_STRUCT))
    parser.add_argument('--stride', default=hex(RECORD))
    parser.add_argument('--sentinel', default='',
                        help='also search this value as a 32-bit word, e.g. 0xbeefbeef')
    args = parser.parse_args()
    submit, stride = int(args.submit, 16), int(args.stride, 16)
    loaded = regions(args.directory)

    if args.sentinel:
        value = int(args.sentinel, 16)
        hits = sentinel_hits(loaded, value, 4)
        print(f'sentinel {value:#010x}: {len(hits)} occurrence(s) at '
              f'{", ".join(hex(hit) for hit in hits[:20])}')
        fillers = filler_words(loaded)
        if fillers:
            print(f'note: the dumps hold {fillers} filler word(s) of '
                  f'{", ".join(hex(f) for f in FILLERS)}; a 16-bit search for a value '
                  f'that appears inside them will over-report. Prefer the 32-bit form.')

    record = read(loaded, submit, stride)
    encoders = record[ENCODERS_AT:ENCODERS_AT + 12]
    print(f'submit record at {submit:#x}: {record.hex()}')
    print(f'encoder block      : {encoders.hex()}')

    for label, needle in (('encoder12', encoders), ('record52', record)):
        hits = occurrences(loaded, needle)
        offsets = [address - submit for address in hits]
        print(f'{label}: {len(hits)} occurrence(s) at '
              f'{", ".join(f"{address:#x} ({offset:+d})" for address, offset in zip(hits, offsets))}')
        if label == 'record52' and len(hits) > 1:
            first = read(loaded, hits[0], stride)
            for address in hits[1:]:
                if read(loaded, address, stride) == first:
                    print(f'  {address:#x} is a byte-identical firmware copy of the submitted record')
    return 0


if __name__ == '__main__':
    sys.exit(main())
