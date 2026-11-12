# SPDX-License-Identifier: GPL-2.0-or-later
"""Behavioural tests for addr_flow, using hand-assembled Thumb bytes only."""
import struct
import unittest

try:  # capstone is only installed in the reverse-engineering venv, not WSL python3
    import capstone  # noqa: F401
except ImportError:  # pragma: no cover - environment guard
    raise unittest.SkipTest('addr_flow requires capstone (use the reverse-engineering venv)')

from addr_flow import BASE, scan

# Hand-assembled, little-endian halfwords (no assembler dependency):
#   ldr r0, [pc, #4]   ; loads the literal at 0x10020008
#   subs r0, #0xd0     ; the firmware's "literal then adjust" idiom
#   ldr r1, [r0, #4]
LDR_PC4 = 0x4801
SUBS_R0_0XD0 = 0x38D0
LDR_R1_R0_4 = 0x6841      # 01101 imm5=1 Rn=0 Rt=1
STR_R1_R0_4 = 0x6041      # 01100 imm5=1 Rn=0 Rt=1


def image(literal, aligned=True):
    """64-byte image: three instructions, padding, then one literal."""
    body = struct.pack('<3H', LDR_PC4, SUBS_R0_0XD0, LDR_R1_R0_4)
    body += struct.pack('<H', 0xBF00)          # nop padding up to the literal slot
    body += struct.pack('<I', literal)
    return body + bytes(64 - len(body))


class AddrFlowTests(unittest.TestCase):
    def test_resolves_literal_then_subtract(self):
        hits = scan(image(0xC1F994EC), 0xC1F9941C, 0xC1F99424)
        self.assertEqual(len(hits), 1)
        address, site, mnemonic, effect, target, _function, _text = hits[0]
        self.assertEqual(address, BASE + 4)     # the ldr r1, [r0, #4]
        self.assertEqual(site, BASE)            # reached through the ldr pc site
        self.assertEqual(effect, 'load')
        self.assertEqual(target, 0xC1F99420)    # 0xc1f994ec - 0xd0 + 4
        self.assertEqual(mnemonic, 'ldr')

    def test_ignores_accesses_outside_the_requested_range(self):
        self.assertEqual(scan(image(0xC1F994EC), 0xC3000000, 0xC3001000), [])

    def test_ignores_literals_outside_the_ram_window(self):
        # A literal in flash is not a RAM struct pointer, so it is never followed.
        self.assertEqual(scan(image(0x10200000), 0xC1F9941C, 0xC1F99424), [])

    def test_reports_store_and_load_separately(self):
        # str r1, [r0, #4]  -> the same access as a store instead of a load
        body = struct.pack('<3H', LDR_PC4, SUBS_R0_0XD0, STR_R1_R0_4)
        body += struct.pack('<H', 0xBF00) + struct.pack('<I', 0xC1F994EC)
        hits = scan(body + bytes(64 - len(body)), 0xC1F99420, 0xC1F99424)
        self.assertEqual([hit[3] for hit in hits], ['store'])


if __name__ == '__main__':
    unittest.main()
