import struct
import unittest

from mailbox_probe import decode_mailbox_result, decode_flag_poll, decode_kernel_flag_poll, run_isolated_mailbox_test, run_isolated_flag_test


class MailboxProbeTest(unittest.TestCase):
    def test_success_distinguishes_empty_from_pending(self):
        empty = decode_mailbox_result('0x0', struct.pack('<III', 1, 2, 0).hex())
        self.assertEqual(empty['status'], 'empty')
        self.assertEqual(empty['waiting_task'], 2)
        pending = decode_mailbox_result('0x0', struct.pack('<III', 1, 0, 0xc1234560).hex())
        self.assertEqual(pending['status'], 'pending')
        self.assertEqual(pending['next_message'], '0xc1234560')

    def test_failure_and_short_output_are_not_empty(self):
        result = decode_mailbox_result('0xfffffff0', bytes(12).hex())
        self.assertEqual(result['status'], 'error')
        with self.assertRaises(ValueError):
            decode_mailbox_result('0x0', bytes(8).hex())

    def test_flag_poll_does_not_infer_idle_from_no_match(self):
        self.assertEqual(decode_flag_poll('0x1', struct.pack('<I', 2).hex())['status'], 'matched')
        self.assertEqual(decode_flag_poll('0x0', bytes(4).hex())['status'], 'not_matched_or_error')
        with self.assertRaises(ValueError):
            decode_flag_poll('0x0', bytes(2).hex())

    def test_kernel_flag_timeout_is_distinct_from_other_errors(self):
        self.assertEqual(decode_kernel_flag_poll('0x0', struct.pack('<II', 0, 2).hex())['status'], 'matched')
        self.assertEqual(decode_kernel_flag_poll('0xffce0000', bytes(8).hex())['status'], 'timeout')
        self.assertEqual(decode_kernel_flag_poll('0xffee0000', bytes(8).hex())['status'], 'error')
        with self.assertRaises(ValueError):
            decode_kernel_flag_poll('0x0', bytes(4).hex())

    def test_isolated_self_test_checks_actual_empty_pending_and_received(self):
        results = iter([
            {'return_r0': '0x01000031'}, {'return_r0': '0xc2001000'},
            {'return_r0': '0x0', 'output': bytes(12).hex()}, {'return_r0': '0x0'},
            {'return_r0': '0x0', 'output': struct.pack('<III', 0, 0, 0xc2001000).hex()},
            {'return_r0': '0x0', 'output': struct.pack('<I', 0xc2001000).hex()},
            {'return_r0': '0x0', 'output': bytes(12).hex()}])
        writes = []
        def call(*args, **kwargs): return next(results)
        result = run_isolated_mailbox_test(call, lambda a, n: bytes(n), lambda a, b: writes.append((a, b)))
        self.assertTrue(result['verified'])
        self.assertEqual([x['status'] for x in result['states']], ['empty', 'pending', 'empty'])
        self.assertEqual(writes[0][0], 0xc2001000)

    def test_isolated_self_test_rejects_missing_message(self):
        results = iter([{'return_r0': '0x01000031'}, {'return_r0': '0xc2001000'},
                        {'return_r0': '0x0', 'output': bytes(12).hex()}, {'return_r0': '0x0'},
                        {'return_r0': '0x0', 'output': bytes(12).hex()}])
        with self.assertRaises(ValueError):
            run_isolated_mailbox_test(lambda *a, **k: next(results), lambda a, n: bytes(n), lambda a, b: None)

    def test_isolated_flag_test_confirms_poll_does_not_clear(self):
        def poll(value, bits):
            return {'return_r0': hex(value), 'output': (struct.pack('<II', 0, bits)).hex()}
        results = iter([{'return_r0': '0x01000044'}, poll(0xffce0000, 0), poll(0xffee0000, 0),
                        poll(0, 0), {'return_r0': '0x0'}, poll(0, 1),
                        poll(1, 1), poll(1, 1), {'return_r0': '0x0'}, poll(0, 0)])
        result = run_isolated_flag_test(lambda *a, **k: next(results))
        self.assertTrue(result['verified'])
        self.assertEqual([r['status'] for r in result['states']],
                         ['not_matched_or_error', 'matched', 'matched', 'not_matched_or_error'])
        self.assertNotEqual(result['kernel_unset_return'], result['kernel_invalid_return'])
