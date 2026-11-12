# SPDX-License-Identifier: GPL-2.0-or-later
"""Read-only: resolve which code touches a RAM range, including `ldr =const; add/sub` idioms.

    addr_flow.py <MAIN image> <lo-hex> <hi-hex> [--end-mb N] [--steps N]

Z5 C1.50 code rarely stores a target struct address directly in a literal pool; it loads a
nearby literal and then adjusts it (`ldr r0,=0xc1f994ec; subs r0,#0xd0`). A plain literal
search therefore misses every real consumer. This tool starts from literal-pool loading
instructions (exact instruction boundaries, so data is never decoded as code), follows the
loaded register through a few straight-line instructions and reports memory accesses whose
base resolves into the range. The constant tracking is deliberately shallow: it is a
candidate finder, not a decompiler, and every hit still needs confirmation by disassembly.
"""
import argparse
import re
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, Cs

BASE = 0x10020000
DEFAULT_END = 0x1D00000
RAM_LOW, RAM_HIGH = 0xC0000000, 0xD0000000
MEMORY = re.compile(r'\[(?P<base>\w+)')
STOP = {'b', 'bl', 'blx', 'bx', 'cbz', 'cbnz', 'pop', 'tbb', 'tbh', 'push'}


def enclosing_function(halfwords, address):
    """Nearest preceding `push {..,lr}`-style prologue, or 0."""
    index = (address - BASE) // 2
    for back in range(index, max(index - 6000, 0), -1):
        value = halfwords[back]
        if (value & 0xFF00) == 0xB500 or (value == 0xE92D and (halfwords[back + 1] & 0x4000)):
            return BASE + back * 2
    return 0


def pool_loaders(image, end):
    """All `ldr rX,=lit` / `adr rX,lit` sites whose literal lies in the RAM window."""
    halfwords = struct.unpack('<%dH' % (end // 2), image[:end - end % 2])
    sites = []
    for index, halfword in enumerate(halfwords):
        if (halfword & 0xF800) == 0x4800:      # ldr rX, [pc, #imm]
            target = ((BASE + index * 2 + 4) & ~3) + (halfword & 0xFF) * 4
        elif (halfword & 0xF800) == 0xA000:    # adr rX, #imm
            target = ((BASE + index * 2 + 4) & ~3) + (halfword & 0xFF) * 4
        else:
            continue
        offset = target - BASE
        if not 0 <= offset <= len(image) - 4:
            continue
        literal = struct.unpack_from('<I', image, offset)[0]
        if RAM_LOW <= literal < RAM_HIGH:
            sites.append((BASE + index * 2, literal))
    return sites, halfwords


def written_registers(insn):
    try:
        return {insn.reg_name(register) for register in insn.regs_access()[1]}
    except (AttributeError, IndexError):
        return set()


def follow(decoder, image, site, literal, low, high, steps):
    """Track the loaded register forward and report accesses into [low, high)."""
    constants, hits = {}, []
    register = None
    for insn in decoder.disasm(image[site - BASE:site - BASE + steps * 4], site):
        if insn.id == 0 or insn.mnemonic in STOP:
            break
        if register is None:
            operands = insn.operands
            if operands and operands[0].type == CS_OP_REG:
                register = insn.reg_name(operands[0].reg)
                constants[register] = literal
        match = MEMORY.search(insn.op_str)
        if match:
            base = match.group('base')
            displacement = insn.operands[-1].mem.disp if insn.operands[-1].type == CS_OP_MEM else 0
            target = constants[base] + displacement if base in constants else None
            if target is not None and low <= target < high:
                effect = 'store' if insn.mnemonic.startswith('str') else 'load'
                hits.append((site, insn.address, insn.mnemonic, effect, target, insn.op_str))
        if len(insn.operands) >= 2 and insn.mnemonic in ('add', 'adds', 'addw', 'sub', 'subs', 'subw'):
            destination = insn.operands[0]
            source = insn.operands[1] if len(insn.operands) == 3 else insn.operands[0]
            immediate = insn.operands[-1]
            if (destination.type == CS_OP_REG and source.type == CS_OP_REG
                    and immediate.type == CS_OP_IMM):
                name = insn.reg_name(destination.reg)
                if insn.reg_name(source.reg) in constants:
                    delta = -immediate.imm if insn.mnemonic.startswith('sub') else immediate.imm
                    constants[name] = constants[insn.reg_name(source.reg)] + delta
                    register = name
        for written in written_registers(insn):
            if written != register:
                constants.pop(written, None)
    return hits


def scan(image, low, high, steps=6, end=DEFAULT_END):
    """Return `(hits, examined)` for resolved accesses into `[low, high)`."""
    sites, halfwords = pool_loaders(image, min(end, len(image)))
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    results = []
    for site, literal in sites:
        results.extend(follow(decoder, image, site, literal, low, high, steps))
    return [(address, site, mnemonic, effect, target,
             enclosing_function(halfwords, site), text)
            for site, address, mnemonic, effect, target, text in results]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('low')
    parser.add_argument('high')
    parser.add_argument('--end-mb', type=float, default=DEFAULT_END / 0x100000)
    parser.add_argument('--steps', type=int, default=6)
    args = parser.parse_args()
    image = args.image.read_bytes()
    results = scan(image, int(args.low, 16), int(args.high, 16), args.steps,
                   int(args.end_mb * 0x100000))
    if not results:
        print('no resolved memory access in range')
        return 0
    for address, site, mnemonic, effect, target, function, text in sorted(results):
        print(f'{address:#010x} via {site:#010x} fn {function:#010x} {effect:5s} '
              f'-> {target:#x}  {mnemonic} {text}')
    print(f'{len(results)} sites')
    return 0


if __name__ == '__main__':
    sys.exit(main())
