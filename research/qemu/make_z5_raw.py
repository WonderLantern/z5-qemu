# SPDX-License-Identifier: GPL-2.0-or-later
"""生成 Z5 模拟器取景用的合成 RAW 输入（只写新的 output/ 目录，无第三方依赖）。

- ingress：引擎 0x200，1508x1006、行跨 2272、packed12（两样本三字节，小端）。几何来自客体寄存器写入
  （output/qemu-sensor-cal-20261107-codex-02），打包格式沿用 Z6 供体假设。
- native0：引擎 0x400，暂用模型 profile 的供体几何 2034x1434、行跨 4080、LE u16。
  Z5 的 native0 几何尚未从客体观察到，仅用于让 TG 持续和走模型流程。

画面与 Z6 `tools/cmos_source.py` 的 scene(frame=0) 相同：上半 8 色条，中间亮度斜坡，底部 1/4
暗底加亮条；RGGB、黑电平 64、白电平 4095。不是传感器线协议，`camera_verified: false`。
"""
import argparse
from publication_paths import output_root
import hashlib
import json
import struct
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BLACK, WHITE = 64, 4095
BARS = ((1, 1, 1), (1, 1, 0), (0, 1, 1), (0, 1, 0), (1, 0, 1), (1, 0, 0), (0, 0, 1), (0, 0, 0))
LAYOUTS = (
    # kind, width, height, stride, packed12
    ('ingress', 1508, 1006, 2272, True),
    ('native0', 2034, 1434, 4080, False),
)


def scene_row(width, height, y):
    """Linear RGB triples for row y, matching Z6 scene(width, height, 0)."""
    if y < height // 2:
        return [BARS[min(x * 8 // width, 7)] for x in range(width)]
    if y < height * 3 // 4:
        return [(x / (width - 1),) * 3 for x in range(width)]
    stripe = max(2, width // 32)
    return [(1.0,) * 3 if x % width < stripe else (.125,) * 3 for x in range(width)]


def mosaic_row(rgb, y):
    """RGGB sample values; Python round() is round-half-even like numpy rint."""
    channels = (0, 1) if y % 2 == 0 else (1, 2)
    return [round(BLACK + rgb[x][channels[x & 1]] * (WHITE - BLACK)) for x in range(len(rgb))]


def pack12_row(samples, stride):
    out = bytearray(stride)
    for i in range(0, len(samples), 2):
        a, b = samples[i], samples[i + 1]
        o = i * 3 // 2
        out[o], out[o + 1], out[o + 2] = a & 255, (a >> 8) | ((b & 15) << 4), b >> 4
    return out


def unpack12_row(row, width):
    values = []
    for o in range(0, width * 3 // 2, 3):
        values += [row[o] | ((row[o + 1] & 15) << 8), (row[o + 1] >> 4) | (row[o + 2] << 4)]
    return values


def u16_row(samples, stride):
    out = bytearray(stride)
    struct.pack_into(f'<{len(samples)}H', out, 0, *samples)
    return out


def build(kind, width, height, stride, packed):
    if width % 2 or height % 2 or stride < (width * 3 // 2 if packed else width * 2):
        raise ValueError(kind + ': invalid geometry')
    raw, preview = bytearray(), bytearray()
    for y in range(height):
        rgb = scene_row(width, height, y)
        samples = mosaic_row(rgb, y)
        row = pack12_row(samples, stride) if packed else u16_row(samples, stride)
        back = unpack12_row(row, width) if packed else list(struct.unpack_from(f'<{width}H', row))
        if back != samples:
            raise ValueError(kind + ': RAW packing failed round trip')
        raw += row
        if y % 2 == 0:  # half-size sRGB preview, one pixel per 2x2 cell
            preview.append(0)
            for x in range(0, width, 2):
                preview += bytes(srgb8(c) for c in rgb[x])
    return bytes(raw), bytes(preview)


def srgb8(v):
    s = 12.92 * v if v <= .0031308 else 1.055 * v ** (1 / 2.4) - .055
    return max(0, min(255, round(s * 255)))


def png(width, height, rows):
    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(rows, 6)) + chunk(b'IEND', b''))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, help='new directory below output/ (default: timestamped)')
    a = p.parse_args()
    out = (a.out or output_root() / f'qemu-raw-{time.strftime("%Y%m%d-%H%M%S")}').resolve()
    if not out.is_relative_to(output_root()):
        p.error('output must be below output/')
    out.mkdir(parents=True, exist_ok=False)
    manifest = {}
    for kind, w, h, stride, packed in LAYOUTS:
        raw, preview = build(kind, w, h, stride, packed)
        (out / f'{kind}.raw').write_bytes(raw)
        (out / f'{kind}-reference.png').write_bytes(png(w // 2, h // 2, preview))
        manifest[kind] = dict(file=f'{kind}.raw', width=w, height=h, stride_bytes=stride, sample_bits=12,
            cfa='RGGB', black_level=BLACK, white_level=WHITE,
            storage='packed12: two samples in three little-endian bytes' if packed else 'little-endian uint16',
            bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
            geometry_source='guest register writes' if kind == 'ingress' else 'donor profile, unverified for Z5',
            scene='Z6 cmos_source.scene frame 0', firmware_layout_verified=False, camera_verified=False)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(out)


if __name__ == '__main__':
    main()
