# SPDX-License-Identifier: GPL-2.0-or-later
"""C1.50 native input: AO keys plus the DISP switch absent from its AO table."""
import struct

AO_KEYS = {'right': 34, 'left': 35, 'up': 36, 'down': 37,
           'menu': 67, 'play': 68, 'delete': 69, 'i': 72, 'ok': 74,
           'help': 70, 'zoom_in': 75, 'zoom_out': 76}
KEYS = dict(AO_KEYS, disp=None, half_press=None)
# ID_SW2_DISP at 10737C70; ID_SW1_INFO/AO71 is a different physical input.
RAW_KEYS = {'disp': (2, 0x100000), 'half_press': (0, 0x80000000)}
SWITCH_SNAPSHOT, SWITCH_SUBMIT, AO_PRESS = 0x101ED79E, 0x101ED678, 0x1059AE16


def key_metadata(name):
    if name in RAW_KEYS:
        group, mask = RAW_KEYS[name]
        return dict(ao_index=None, switch_group=group, switch_mask=hex(mask))
    return dict(ao_index=AO_KEYS[name])


def switch_payloads(data, group, mask):
    """Mirror 1059AE16's 52-byte snapshot packing without losing other inputs."""
    if len(data) < 0x9c or group not in range(4) or not 0 < mask <= 0xffffffff:
        raise ValueError('invalid native switch snapshot or mask')
    values = [struct.unpack_from('<I', data, offset)[0] for offset in (4, 0x18, 0x2c, 0x40)]
    if values[group] & mask:
        raise ValueError('requested switch is already pressed')
    encoders = [struct.unpack_from('<H', data, offset)[0] for offset in (0x64, 0x6c, 0x74, 0x7c, 0x84, 0x8c)]
    tail = [struct.unpack_from('<I', data, offset)[0] for offset in (0x94, 0x98)]
    released = struct.pack('<8I6H2I', *values, 0, 0, 0, 0, *encoders, *tail)
    values[group] |= mask
    pressed = struct.pack('<8I6H2I', *values, 0, 0, 0, 0, *encoders, *tail)
    return pressed, released


def press_key(name, call, memory, settle, prefix='native_key'):
    """Call only firmware input APIs. settle runs and returns to a safe rendezvous."""
    if name not in RAW_KEYS:
        words = [0] * 8
        index = AO_KEYS[name]
        words[index // 32] = 1 << (index % 32)
        words[4] = 10
        call(f'{prefix}_{name}', AO_PRESS, struct.pack('<8I', *words),
             [('scratch', 0), 5, ('scratch', 20)])
        return
    result = call(f'{prefix}_snapshot', SWITCH_SNAPSHOT, bytes(4), [])
    pointer = int(result['return_r0'], 16)
    if not 0xc1800000 <= pointer <= 0xcd800000 - 0x9c:
        raise ValueError('native switch snapshot pointer outside RAM')
    pressed, released = switch_payloads(memory(pointer, 0x9c), *RAW_KEYS[name])
    # A failed fixture may retain guest/scratch state for diagnosis. Do not
    # overwrite it with another fixture; boot_probe aborts and stops QEMU.
    call(f'{prefix}_{name}_press', SWITCH_SUBMIT, pressed, [('scratch', 0)])
    try:
        settle()
    finally:
        call(f'{prefix}_{name}_release', SWITCH_SUBMIT, released, [('scratch', 0)])
