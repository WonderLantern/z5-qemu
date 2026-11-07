import binascii
import hashlib
import unittest

import patched_main as pm


def with_crc(body):
    """Append the 2 bytes that make crc_hqx(module) == 0 (CRC-16/XMODEM, big-endian)."""
    return body + binascii.crc_hqx(body, 0).to_bytes(2, 'big')


def sha(b):
    return hashlib.sha256(b).hexdigest()


class PatchedMainTest(unittest.TestCase):
    def setUp(self):
        self.stock = with_crc(bytes(range(64)) * 4)
        body = bytearray(self.stock[:-2])
        body[8:12] = b'\xaa\xbb\xcc\xdd'
        loader = b'LOADER!!'
        self.patched = with_crc(bytes(body) + b'\0\0' + loader)
        self.report = dict(
            input=dict(size=len(self.stock), sha256=sha(self.stock)),
            output=dict(size=len(self.patched), sha256=sha(self.patched)),
            edits=[dict(name='lit', offset='0x8', address='0x10020008', expected=self.stock[8:12].hex(),
                        replacement='aabbccdd')],
            appends=[dict(name='loader', offset=hex(len(self.stock)), address='0', size=len(loader),
                          sha256=sha(loader))])

    def test_accepts_declared_patch(self):
        self.assertEqual(pm.verify(self.stock, self.patched, self.report, sha(self.stock))['size'],
                         len(self.patched))

    def test_rejects_undeclared_change_even_with_valid_crc(self):
        body = bytearray(self.patched[:-2])
        body[40] ^= 1
        bad = with_crc(bytes(body))
        report = dict(self.report, output=dict(size=len(bad), sha256=sha(bad)))
        with self.assertRaisesRegex(ValueError, 'undeclared'):
            pm.verify(self.stock, bad, report, sha(self.stock))

    def test_rejects_wrong_original_bytes(self):
        report = dict(self.report, edits=[dict(self.report['edits'][0], expected='00000000')])
        with self.assertRaisesRegex(ValueError, 'original bytes'):
            pm.verify(self.stock, self.patched, report, sha(self.stock))

    def test_rejects_other_stock(self):
        with self.assertRaisesRegex(ValueError, 'stock'):
            pm.verify(self.stock, self.patched, self.report, '0' * 64)


if __name__ == '__main__':
    unittest.main()
