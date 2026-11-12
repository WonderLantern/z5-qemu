"""Read-only Z5 C1.50 region 0x4a loader trace; no guest writes."""
import struct

POINTS = {0x101DFBE6, 0x101DFB7A, 0x1008E4C2, 0x1008E4F2, 0x1008E500, 0x1008E788}
DESCRIPTOR = 0xC1881EB4
DESTINATION = 0xC8500000


def observe(remote, regs, thread, phase):
    pc = int(regs['r15'], 16)
    r0 = int(regs['r0'], 16)
    if pc == 0x101DFBE6:
        if r0 != 0x4A:
            return None
    elif pc == 0x101DFB7A:
        if r0 != DESCRIPTOR:
            return None
    elif pc == 0x1008E788:
        if int(regs['r1'], 16) != 0x13FFFFFC or int(regs['r2'], 16) != 4:
            return None
    elif pc in (0x1008E4C2, 0x1008E4F2, 0x1008E500):
        ptr = r0 if pc == 0x1008E4C2 else int(regs['r4'], 16)
        if not 0xC0000000 <= ptr <= 0xCD800000 - 0x34:
            return None
        if struct.unpack('<I', remote.memory(ptr + 0x2C, 4))[0] != DESTINATION:
            return None
    else:
        return None
    row = dict(pc=hex(pc), thread=thread, phase=phase, r0=hex(r0),
               lr=regs['r14'], guest_ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0])
    if pc in (0x1008E4C2, 0x1008E4F2, 0x1008E500):
        row['loader_arguments'] = remote.memory(ptr, 0x34).hex()
    if pc == 0x1008E788:
        row['expected_marker'] = remote.memory(r0, 4).hex()
        row['observed_marker'] = remote.memory(0x13FFFFFC, 4).hex()
    return row
