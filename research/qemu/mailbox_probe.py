# SPDX-License-Identifier: GPL-2.0-or-later
"""Interpret an experimental T-Kernel 1.00 mailbox status response."""
import struct


def decode_flag_poll(return_r0, output):
    raw = bytes.fromhex(output)
    if len(raw) != 4:
        raise ValueError('flag result must be exactly four bytes')
    result = int(return_r0, 16)
    if result not in (0, 1):
        raise ValueError('unexpected flag wrapper result')
    return dict(status='matched' if result else 'not_matched_or_error',
                return_r0=return_r0, flags=hex(struct.unpack('<I', raw)[0]))


def decode_kernel_flag_poll(return_r0, output):
    raw = bytes.fromhex(output)
    if len(raw) != 8:
        raise ValueError('kernel flag fixture output must be eight bytes')
    result = int(return_r0, 16)
    status = 'matched' if result == 0 else 'timeout' if result == 0xffce0000 else 'error'
    return dict(status=status, return_r0=return_r0, flags=hex(struct.unpack_from('<I', raw, 4)[0]))


def decode_mailbox_result(return_r0, output):
    raw = bytes.fromhex(output)
    if len(raw) != 12:
        raise ValueError('mailbox status must be exactly 12 bytes')
    status = int(return_r0, 16)
    exinf, waiting, message = struct.unpack('<III', raw)
    return dict(status=('error' if status else 'pending' if message else 'empty'),
                return_r0=return_r0, extended_info=hex(exinf), waiting_task=waiting,
                next_message=hex(message))


def run_isolated_flag_test(call):
    """Check zero-timeout flag polling against an isolated synthetic flag."""
    created = call('flagtest_create', 0x10035f04, struct.pack('<III', 0, 8, 0) + bytes(16),
                   [('scratch', 0)], thumb=False)
    flag_id = int(created['return_r0'], 16)
    if not 0 < flag_id < 0x80000000:
        raise ValueError('isolated flag creation failed')
    def kernel_poll(ident):
        return call('flagtest_kernel_poll', 0x10036504, bytes(8),
                    [ident, 1, 1, ('scratch', 4)], thumb=False)
    unset = kernel_poll(flag_id)
    invalid = kernel_poll(0)
    if int(unset['return_r0'], 16) != 0xffce0000 or unset['return_r0'] == invalid['return_r0']:
        raise ValueError('kernel flag timeout and invalid ID not distinguished')
    payload = struct.pack('<II', flag_id, 0)
    def poll():
        result = call('flagtest_poll', 0x1019a1e2, payload,
                      [('scratch', 0), 1, ('scratch', 4), 0])
        return decode_flag_poll(result['return_r0'], result['output'][8:16])
    states = [poll()]
    if states[-1]['status'] != 'not_matched_or_error':
        raise ValueError('new isolated flag unexpectedly matched')
    result = call('flagtest_set', 0x1019a198, payload, [('scratch', 0), 1])
    if int(result['return_r0'], 16) != 0:
        raise ValueError('isolated flag set failed')
    matching = kernel_poll(flag_id)
    if int(matching['return_r0'], 16) != 0 or not (struct.unpack('<II', bytes.fromhex(matching['output']))[1] & 1):
        raise ValueError('kernel flag poll did not match')
    states.extend([poll(), poll()])
    if any(r['status'] != 'matched' or int(r['flags'], 16) & 1 != 1 for r in states[1:]):
        raise ValueError('flag poll failed or cleared the flag')
    result = call('flagtest_clear', 0x1019a19e, payload, [('scratch', 0), 1])
    if int(result['return_r0'], 16) != 0:
        raise ValueError('isolated flag clear failed')
    states.append(poll())
    if states[-1]['status'] != 'not_matched_or_error':
        raise ValueError('isolated flag remained matched after clear')
    return dict(verified=True, flag_id=flag_id, states=states,
                kernel_unset_return=unset['return_r0'], kernel_invalid_return=invalid['return_r0'],
                kernel_matched_return=matching['return_r0'],
                scope='isolated synthetic flag; no global idle claim')


def run_isolated_mailbox_test(call, read, write):
    """Exercise an isolated guest mailbox; it is destroyed with the QEMU process."""
    created = call('selftest_create', 0x10035f28, struct.pack('<II', 0, 2) + bytes(12),
                   [('scratch', 0)], thumb=False)
    mailbox = int(created['return_r0'], 16)
    if not 0 < mailbox < 0x80000000:
        raise ValueError('isolated mailbox creation failed')
    allocated = call('selftest_alloc', 0x1021c9e0, bytes(4), [32, 0])
    node = int(allocated['return_r0'], 16)
    if not 0xc0000000 <= node <= 0xcd800000 - 32 or node % 4:
        raise ValueError('invalid isolated mailbox node allocation')
    before = read(node, 32)
    if len(before) != 32:
        raise ValueError('short isolated mailbox node')
    write(node, struct.pack('<III', 0, 2, 0) + bytes(20))

    def query():
        result = call('selftest_query', 0x10036230, bytes(12), [mailbox, ('scratch', 0)], thumb=False)
        return decode_mailbox_result(result['return_r0'], result['output'])

    states = [query()]
    if states[-1]['status'] != 'empty':
        raise ValueError('new isolated mailbox was not empty')
    sent = call('selftest_send', 0x100363d0, bytes(4), [mailbox, node], thumb=False)
    if int(sent['return_r0'], 16) != 0:
        raise ValueError('isolated mailbox send failed')
    states.append(query())
    if states[-1]['status'] != 'pending' or int(states[-1]['next_message'], 16) != node:
        raise ValueError('isolated mailbox did not contain sent node')
    received = call('selftest_receive', 0x1003620c, bytes(4), [mailbox, ('scratch', 0), 0], thumb=False)
    if int(received['return_r0'], 16) != 0 or struct.unpack('<I', bytes.fromhex(received['output']))[0] != node:
        raise ValueError('isolated mailbox receive failed')
    states.append(query())
    if states[-1]['status'] != 'empty':
        raise ValueError('isolated mailbox not empty after receive')
    return dict(verified=True, mailbox_id=mailbox, node=hex(node), node_before=before.hex(),
                states=states, scope='isolated synthetic mailbox only; no global idle claim')
