# SPDX-License-Identifier: GPL-2.0-or-later
"""生成模拟器取景参考背景：720x480 RGB24（`--lv-background` 使用），只写新的 output/ 目录。

这是主机合成的界面参考底图，不经过固件 RAW/ISP 管线。默认画面为色条与亮度斜坡；
`--rgb` 可改用已转换好的 720x480 RGB24 文件（例如用 convert_lv_background.ps1 从照片转换）。
"""
import argparse
from publication_paths import output_root
import hashlib
import json
import time
from pathlib import Path

from make_z5_raw import png, scene_row, srgb8

ROOT = Path(__file__).resolve().parents[2]
WIDTH, HEIGHT = 720, 480
SIZE = WIDTH * HEIGHT * 3


def color_bars():
    out = bytearray()
    for y in range(HEIGHT):
        for rgb in scene_row(WIDTH, HEIGHT, y):
            out += bytes(srgb8(c) for c in rgb)
    return bytes(out)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rgb', type=Path, help='existing 720x480 RGB24 file to package')
    p.add_argument('--out', type=Path, help='new directory below output/ (default: timestamped)')
    a = p.parse_args()
    data = a.rgb.read_bytes() if a.rgb else color_bars()
    if len(data) != SIZE:
        p.error(f'background must be {SIZE} bytes (720x480 RGB24)')
    out = (a.out or output_root() / f'qemu-lvbg-{time.strftime("%Y%m%d-%H%M%S")}').resolve()
    if not out.is_relative_to(output_root()):
        p.error('output must be below output/')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'background.rgb').write_bytes(data)
    rows = b''.join(b'\0' + data[y * WIDTH * 3:(y + 1) * WIDTH * 3] for y in range(HEIGHT))
    (out / 'background.png').write_bytes(png(WIDTH, HEIGHT, rows))
    (out / 'manifest.json').write_text(json.dumps(dict(
        file='background.rgb', width=WIDTH, height=HEIGHT, format='RGB24', bytes=SIZE,
        sha256=hashlib.sha256(data).hexdigest(), source=str(a.rgb) if a.rgb else 'colour bars',
        firmware_pipeline=False, purpose='UI reference background composited by the emulator host',
        camera_verified=False), indent=2), encoding='utf-8')
    print(out / 'background.rgb')


if __name__ == '__main__':
    main()
