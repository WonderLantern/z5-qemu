"""Compare the fixture mapping against the actual C1.50 Thumb functions."""
import hashlib
from pathlib import Path
import unittest

from shooting_ui import quality_mirror_values

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP
except ImportError:
    Uc = None

IMAGE = Path(__file__).resolve().parents[2] / 'output/stage3-c4-20261106-185724/eg1650_015001.bi'
SHA256 = '1d9742a951ea8a8ebe695fa9bb1f29a3be73e16dfe4a8372d997e903bbc58e98'


@unittest.skipUnless(Uc and IMAGE.exists(), 'requires local C1.50 image and Unicorn')
class NativeQualityMappingTest(unittest.TestCase):
    def test_all_supported_quality_combinations_match_native_functions(self):
        image = IMAGE.read_bytes()
        self.assertEqual(hashlib.sha256(image).hexdigest(), SHA256)
        cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        cpu.mem_map(0x10400000, 0x60000)
        cpu.mem_write(0x10400000, image[0x10400000-0x10020000:0x10460000-0x10020000])
        cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_map(0x30000000, 0x1000)
        settings = {}

        def intercept(uc, address, size, data):
            if address == 0x10456098:
                uc.reg_write(UC_ARM_REG_R0, settings[uc.reg_read(UC_ARM_REG_R0)])
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        cpu.hook_add(UC_HOOK_CODE, intercept)

        def run(address, args):
            cpu.reg_write(UC_ARM_REG_SP, 0x2000fff0)
            cpu.reg_write(UC_ARM_REG_LR, 0x30000001)
            for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), args):
                cpu.reg_write(reg, value)
            cpu.emu_start(address | 1, 0x30000000, count=1000)
            return cpu.reg_read(UC_ARM_REG_R0)

        for kind in (0, 1, 3):
            for compression in (0, 1, 2):
                for star in (0, 1):
                    with self.subTest(kind=kind, compression=compression, star=star):
                        mirror = quality_mirror_values(kind, compression, star)
                        settings.update({0x1803: mirror[0], 0x1804: mirror[1]})
                        self.assertEqual(run(0x104131bc, ()),
                                         run(0x10411712, (compression, kind, star)))


if __name__ == '__main__':
    unittest.main()
