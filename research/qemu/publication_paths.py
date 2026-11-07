# SPDX-License-Identifier: GPL-2.0-or-later
"""Paths for local experiment results; no firmware or results belong in Git."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def output_root():
    return Path(os.environ.get('Z5_QEMU_OUTPUT', ROOT / 'output')).expanduser().resolve()


def within_output(path):
    return Path(path).resolve().is_relative_to(output_root())
