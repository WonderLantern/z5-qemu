# SPDX-License-Identifier: GPL-2.0-or-later
"""Launch the local interactive Z5 UI with explicitly synthetic stand-ins."""
import argparse
from pathlib import Path
import subprocess
import sys
import time

from publication_paths import output_root

HERE = Path(__file__).resolve().parent


def build_command(main, out, background, port):
    return [sys.executable, '-B', str(HERE / 'boot_probe.py'), '--main', str(main),
            '--out', str(out), '--seconds', '120', '--trace-tasks', '--display',
            '--processing-init-standin', '--startup-environment-standin',
            '--application-ready-standin', '--sensor-standin', '--card-standin',
            '--keep-awake', '--lv-background', str(background), '--interactive-port', str(port)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--main', required=True, type=Path, help='user-supplied Z5 C 1.50 extracted MAIN')
    parser.add_argument('--out', required=True, type=Path, help='new result directory within Z5_QEMU_OUTPUT')
    parser.add_argument('--background', type=Path, help='optional existing RGB24 background in Z5_QEMU_OUTPUT')
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    background = args.background
    if background is None:
        background_dir = output_root() / f'background-{time.time_ns()}'
        subprocess.run([sys.executable, '-B', str(HERE / 'make_lv_background.py'),
                        '--out', str(background_dir)], check=True)
        background = background_dir / 'background.rgb'
    return subprocess.call(build_command(args.main, args.out, background, args.port))


if __name__ == '__main__':
    raise SystemExit(main())
