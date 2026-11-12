"""只读核对 Z5 主模块和 Z6 QEMU 源码配置，输出 Q0 差异证据。

不执行固件，不启动 QEMU，不修改参考仓库；只向新的 output/ 路径写 JSON。
字面量出现次数不等于指令引用数，更不证明外设行为兼容。
"""
import argparse
import binascii
import hashlib
import json
from pathlib import Path
from publication_paths import output_root
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
MAIN_SIZE = 34603578
MAIN_SHA256 = '1d9742a951ea8a8ebe695fa9bb1f29a3be73e16dfe4a8372d997e903bbc58e98'
SCATTER_START, SCATTER_END = 0x10034000, 0x10034120
COPY, ZERO = 0x1002006C, 0x10020088
LITERALS = (
    0x04008000, 0x04008F00, 0x04008FFC, 0x04280000, 0x0428002C,
    0x20010000, 0x20100000, 0x20200000, 0x20380000, 0x203C0000,
    0x24010000, 0x28000000, 0x2B000000, 0x2C000000,
    0x2C010000, 0x2C020000, 0x2C090000, 0x2C0A0000,
)


def hx(value):
    return f'0x{value:08X}'


def check_identity(data, expected_size, expected_sha256):
    if len(data) != expected_size:
        raise ValueError(f'input length {len(data)} != {expected_size}')
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('input SHA-256 mismatch; abort')


def read_scatter(data, base, start, end, copy_handler, zero_handler):
    if not (base <= start < end <= base + len(data)) or (end - start) % 16:
        raise ValueError('scatter table is truncated or misaligned')
    rows = []
    for address in range(start, end, 16):
        src, dst, size, handler = struct.unpack_from('<4I', data, address - base)
        if handler not in (copy_handler, zero_handler):
            raise ValueError(f'unknown scatter handler {hx(handler)}')
        if not size or dst + size > 0x100000000:
            raise ValueError('invalid scatter destination range')
        if handler == copy_handler and not (base <= src < src + size <= base + len(data)):
            raise ValueError('scatter copy source lies outside input')
        rows.append(dict(record=hx(address), source=hx(src), destination=hx(dst),
                         size=size, destination_end=hx(dst + size), handler=hx(handler),
                         operation='copy' if handler == copy_handler else 'zero'))
    return rows


def uncovered(start, end, windows):
    """返回未被窗口并集覆盖的半开区间。"""
    result, cursor = [], start
    for low, size in sorted(windows):
        high = low + size
        if high <= cursor or low >= end:
            continue
        if low > cursor:
            result.append((cursor, low))
        cursor = max(cursor, min(high, end))
    if cursor < end:
        result.append((cursor, end))
    return result


def literal_occurrences(data, base, targets):
    result = {}
    for target in targets:
        needle, offset, count, locations = struct.pack('<I', target), 0, 0, []
        while (found := data.find(needle, offset)) >= 0:
            if found % 4 == 0:
                count += 1
                if len(locations) < 8:
                    locations.append(hx(base + found))
            offset = found + 1
        result[hx(target)] = dict(aligned_word_count=count, sample_rom_locations=locations)
    return result


def parse_reference(profile, board):
    profile = re.sub(r'/\*.*?\*/', '', profile, flags=re.S)
    board = re.sub(r'/\*.*?\*/', '', board, flags=re.S)
    fields = {}
    for key in ('main_base', 'main_bytes'):
        match = re.search(r'\.' + key + r'\s*=\s*(0x[\da-fA-F]+|\d+)', profile)
        if not match:
            raise ValueError(f'reference profile missing {key}')
        fields[key] = int(match[1], 0)
    windows = re.search(r'nikon_z6_ram_windows\[\]\s*=\s*\{(.*?)\};', profile, re.S)
    rom = re.search(r'memory_region_init_rom\(&s->main_rom,\s*NULL,\s*"[^"]+",\s*'
                    r'(0x[\da-fA-F]+|\d+)\s*,', board)
    if not windows or not rom:
        raise ValueError('reference RAM windows or ROM capacity missing')
    fields['ram_windows'] = [(int(a, 0), int(b, 0)) for a, b in
                             re.findall(r'\{\s*(0x[\da-fA-F]+),\s*(0x[\da-fA-F]+)\s*\}', windows[1])]
    if not fields['ram_windows']:
        raise ValueError('reference RAM windows are empty')
    fields['rom_capacity'] = int(rom[1], 0)
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--main', required=True, type=Path)
    parser.add_argument('--reference', type=Path, default=ROOT / 'reference/z6-qemu')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    output = args.out.resolve()
    if not output.is_relative_to(output_root()):
        parser.error('--out must be inside the shared workspace output/')
    if output.exists():
        parser.error('refusing to overwrite existing output')
    data = args.main.read_bytes()
    check_identity(data, MAIN_SIZE, MAIN_SHA256)
    profile_path = args.reference / 'qemu/nikon-z6-profile.h'
    board_path = args.reference / 'qemu/nikon-z6.c'
    ref = parse_reference(profile_path.read_text(encoding='utf-8'),
                          board_path.read_text(encoding='utf-8'))
    scatter = read_scatter(data, BASE, SCATTER_START, SCATTER_END, COPY, ZERO)
    for row in scatter:
        gaps = uncovered(int(row['destination'], 16), int(row['destination_end'], 16), ref['ram_windows'])
        # Z6 separately maps the boot SRAM; it is not in the profile's pool array.
        gaps = [part for a, b in gaps for part in uncovered(a, b, [(0x04008000, 0x1000)])]
        row['unmapped_in_z6_model'] = [[hx(a), hx(b)] for a, b in gaps]
    first = struct.unpack_from('<I', data)[0]
    if first & 0xFF000000 != 0xEA000000:
        raise ValueError('unexpected initial ARM branch')
    displacement = first & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    revision = subprocess.check_output(['git', '-C', str(args.reference), 'rev-parse', 'HEAD'], text=True).strip()
    report = dict(
        milestone='Q0', verification='static_only', emulator_verified=False, camera_verified=False,
        firmware_file_modified=False, qemu_started=False,
        z5=dict(size=len(data), sha256=MAIN_SHA256, base=hx(BASE), end_exclusive=hx(BASE + len(data)),
                module_crc_residue=binascii.crc_hqx(data, 0), initial_arm_branch=hx(BASE + 8 + displacement * 4),
                scatter_start=hx(SCATTER_START), scatter_end_exclusive=hx(SCATTER_END), scatter=scatter),
        z6_reference=dict(revision=revision, evidence='source profile, not independently supplied Z6 firmware',
                          main_base=hx(ref['main_base']), main_bytes=ref['main_bytes'], rom_capacity=ref['rom_capacity'],
                          profile_sha256=hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                          board_sha256=hashlib.sha256(board_path.read_bytes()).hexdigest()),
        differences=dict(payload_size_delta=len(data) - ref['main_bytes'],
                         bytes_beyond_z6_rom=max(0, len(data) - ref['rom_capacity']),
                         required_rom_page_aligned=(len(data) + 0xFFF) & ~0xFFF,
                         scatter_records_with_mapping_gaps=sum(bool(r['unmapped_in_z6_model']) for r in scatter)),
        literal_scan=dict(scope='aligned little-endian words; not instruction xrefs or device compatibility',
                          candidates=literal_occurrences(data, BASE, LITERALS)))
    if report['z5']['module_crc_residue'] != 0:
        raise ValueError('unexpected main-module CRC residue')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(f'Q0 report: {output}')
    print(json.dumps(report['differences'], indent=2))


if __name__ == '__main__':
    main()
