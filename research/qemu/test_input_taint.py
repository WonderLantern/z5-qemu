# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for input_taint using synthetic RAM dumps only."""
import struct
import tempfile
import unittest
from pathlib import Path

import input_taint

BASE = 0xC1F00000
SUBMIT = 0xC1F995C4


def record(encoder_slot=1, count=0xBEEF, groups=(0x200, 0, 0, 0)):
    body = struct.pack('<4I', *groups) + bytes(0x10)
    encoders = [0] * 6
    encoders[encoder_slot] = count
    return body + struct.pack('<6H', *encoders) + bytes(8)


def dump_with(records):
    """records: mapping absolute address -> 52-byte record."""
    data = bytearray(0xA0000)   # BASE..0xC1FA0000 must cover the submit record
    for address, body in records.items():
        data[address - BASE:address - BASE + len(body)] = body
    return bytes(data)


class TaintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write_dump(self, data):
        name = f'ram-{BASE:08x}-{len(data):x}.bin'
        (self.directory / name).write_bytes(data)

    def test_reports_the_submit_slot_and_a_firmware_copy(self):
        body = record()
        self.write_dump(dump_with({SUBMIT: body, SUBMIT + 0x34: body}))
        loaded = input_taint.regions(self.directory)
        self.assertEqual(input_taint.occurrences(loaded, body), [SUBMIT, SUBMIT + 0x34])
        self.assertEqual(input_taint.read(loaded, SUBMIT + 0x20, 12), body[0x20:0x2C])

    def test_distinguishes_records_that_differ(self):
        mine = record()
        other = record(groups=(0x8002, 0, 0, 0))   # Fn2 still held
        self.write_dump(dump_with({SUBMIT: mine, SUBMIT + 0x34: other}))
        loaded = input_taint.regions(self.directory)
        self.assertEqual(input_taint.occurrences(loaded, mine), [SUBMIT])

    def test_rejects_a_directory_without_dumps(self):
        with self.assertRaises(ValueError):
            input_taint.regions(self.directory)

    def test_rejects_a_read_outside_every_dump(self):
        self.write_dump(dump_with({SUBMIT: record()}))
        loaded = input_taint.regions(self.directory)
        with self.assertRaises(ValueError):
            input_taint.read(loaded, 0xC3000000, 4)

    def test_filler_words_are_counted_so_halfword_hits_can_be_doubted(self):
        # 0xdeadbeef ends in the halfword 0xbeef; a 16-bit search would call it taint.
        data = bytearray(0xA0000)
        struct.pack_into('<4I', data, 0x4000, *([0xDEADBEEF] * 4))
        self.write_dump(bytes(data))
        loaded = input_taint.regions(self.directory)
        self.assertEqual(input_taint.filler_words(loaded), 4)
        self.assertEqual(len(input_taint.sentinel_hits(loaded, 0xBEEF, 2)), 4)
        # The 32-bit form of a real injected pair is unaffected by the filler.
        self.assertEqual(input_taint.sentinel_hits(loaded, 0xBEEFBEEF, 4), [])

    def test_sentinel_hits_finds_the_full_word_copy(self):
        data = bytearray(0xA0000)
        struct.pack_into('<I', data, 0x8000, 0xBEEFBEEF)
        self.write_dump(bytes(data))
        loaded = input_taint.regions(self.directory)
        self.assertEqual(input_taint.sentinel_hits(loaded, 0xBEEFBEEF, 4), [BASE + 0x8000])


if __name__ == '__main__':
    unittest.main()
