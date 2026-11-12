# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare two aligned Z5 i-panel QMP captures; never ship camera image data."""
import argparse
import json
from pathlib import Path

WIDTH, HEIGHT = 720, 480
SLOT_CELL = (1, 3)  # The [1][2] markers already exist without the stand-in.


def compare_panel(baseline, candidate):
    if len(baseline) != WIDTH * HEIGHT * 3 or len(candidate) != len(baseline):
        raise ValueError('expected two 720x480 RGB frames')
    cells = []
    for row in range(2):
        for col in range(6):
            x0, y0 = col * 120, 282 + row * 72
            changed = 0
            for y in range(y0 + 8, y0 + 62):
                for x in range(x0 + 8, x0 + 112):
                    i = (y * WIDTH + x) * 3
                    changed += baseline[i:i+3] != candidate[i:i+3]
            cells.append(dict(row=row, column=col, changed_pixels=changed))
    x0, y0 = SLOT_CELL[1] * 120, 282 + SLOT_CELL[0] * 72
    marker_pixels = sum(min(baseline[(y*WIDTH+x)*3:(y*WIDTH+x)*3+3]) >= 120
                        for y in range(y0+8, y0+62) for x in range(x0+8, x0+112))
    outside = sum(baseline[i:i+3] != candidate[i:i+3]
                  for y in list(range(282)) + list(range(426, HEIGHT))
                  for i in range(y * WIDTH * 3, (y+1) * WIDTH * 3, 3))
    passed = (outside == 0 and marker_pixels >= 20 and
              all(cell['changed_pixels'] >= 40 for cell in cells
                  if (cell['row'], cell['column']) != SLOT_CELL))
    return dict(passed=passed, changed_pixels=cells, existing_slot_marker_pixels=marker_pixels,
                pixels_changed_outside_grid=outside, camera_verified=False,
                scope='aligned baseline and synthetic-setting i-panel captures')


def read_ppm(path):
    data = Path(path).read_bytes()
    try:
        magic, size, maximum, pixels = data.split(b'\n', 3)
    except ValueError as exc:
        raise ValueError('invalid P6 screenshot') from exc
    if (magic, size, maximum) != (b'P6', b'720 480', b'255'):
        raise ValueError('expected 720x480 P6 screenshot')
    return pixels


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--candidate', required=True, type=Path)
    args = parser.parse_args()
    result = compare_panel(read_ppm(args.baseline), read_ppm(args.candidate))
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
