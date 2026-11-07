"""Q0 检查工具的无固件测试，只使用自建数据。"""
import hashlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inspect_inputs as probe


class InspectInputsTests(unittest.TestCase):
    def test_identity_rejects_changed_bytes_and_wrong_length(self):
        data = b'owned fixture'
        digest = hashlib.sha256(data).hexdigest()
        probe.check_identity(data, len(data), digest)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            probe.check_identity(b'Owned fixture', len(data), digest)
        with self.assertRaisesRegex(ValueError, 'length'):
            probe.check_identity(data[:-1], len(data), digest)

    def test_scatter_keeps_copy_and_zero_as_distinct_operations(self):
        data = bytearray(128)
        struct.pack_into('<4I', data, 0, 0x1040, 0x8000, 16, 0x1006)
        struct.pack_into('<4I', data, 16, 0xDEADBEEF, 0x9000, 32, 0x1008)
        rows = probe.read_scatter(bytes(data), 0x1000, 0x1000, 0x1020,
                                  0x1006, 0x1008)
        self.assertEqual([r['operation'] for r in rows], ['copy', 'zero'])
        self.assertEqual(rows[1]['destination_end'], '0x00009020')

    def test_scatter_rejects_unknown_handler_and_bad_copy_source(self):
        data = bytearray(64)
        struct.pack_into('<4I', data, 0, 0x1030, 0x8000, 16, 0x1234)
        with self.assertRaisesRegex(ValueError, 'handler'):
            probe.read_scatter(data, 0x1000, 0x1000, 0x1010, 0x1006, 0x1008)
        struct.pack_into('<4I', data, 0, 0x1030, 0x8000, 17, 0x1006)
        with self.assertRaisesRegex(ValueError, 'copy source'):
            probe.read_scatter(data, 0x1000, 0x1000, 0x1010, 0x1006, 0x1008)

    def test_scatter_rejects_truncated_table_and_wrapping_destination(self):
        with self.assertRaisesRegex(ValueError, 'table'):
            probe.read_scatter(bytes(31), 0x1000, 0x1000, 0x1020, 6, 8)
        data = struct.pack('<4I', 0, 0xFFFFFFF0, 32, 8)
        with self.assertRaisesRegex(ValueError, 'destination'):
            probe.read_scatter(data, 0x1000, 0x1000, 0x1010, 6, 8)

    def test_mapping_gaps_use_union_and_exclusive_ends(self):
        windows = [(0x1000, 0x100), (0x1180, 0x80), (0x1080, 0x20)]
        self.assertEqual(probe.uncovered(0x1080, 0x1300, windows),
                         [(0x1100, 0x1180), (0x1200, 0x1300)])
        self.assertEqual(probe.uncovered(0x1000, 0x1100, windows), [])

    def test_literals_are_aligned_words_and_not_instruction_references(self):
        value = 0x04280000
        data = struct.pack('<I', value) + b'x' + struct.pack('<I', value)
        refs = probe.literal_occurrences(data, 0x1000, [value])
        self.assertEqual(refs['0x04280000']['aligned_word_count'], 1)
        self.assertEqual(refs['0x04280000']['sample_rom_locations'], ['0x00001000'])

    def test_profile_parser_keeps_rom_capacity_separate_from_payload_size(self):
        profile = '''.main_base = 0x10020000, .main_bytes = 33502842,
        static const NikonRAMWindow nikon_z6_ram_windows[] = {
          {0xc1800000, 0x7a00000}, /* ignore 0x123 */
          {0x80000000, 0x10000},
        };'''
        board = '''memory_region_init_rom(&s->main_rom, NULL, "z6-main-rom",
                            0x02000000, &error_fatal);'''
        result = probe.parse_reference(profile, board)
        self.assertEqual(result['main_bytes'], 33502842)
        self.assertEqual(result['rom_capacity'], 33554432)
        self.assertEqual(result['ram_windows'][0], (0xc1800000, 0x7a00000))

    def test_reference_parser_refuses_changed_source_shape(self):
        with self.assertRaisesRegex(ValueError, 'reference'):
            probe.parse_reference('.main_base = 0x10020000', '')


if __name__ == '__main__':
    unittest.main()
