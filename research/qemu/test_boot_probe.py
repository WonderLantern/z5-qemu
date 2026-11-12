"""启动证据的解析和完成条件测试，不含尼康固件。"""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import boot_probe


class BootProbeTests(unittest.TestCase):
    def test_exception_entry_is_watched_from_start_when_requested(self):
        self.assertEqual(boot_probe.exception_trace_points(True), {0x10054680: 'cpu_exception_entry'})
        self.assertEqual(boot_probe.exception_trace_points(False), {})

    def test_native_initialization_uses_loaded_verified_image(self):
        data = bytearray(0x10000)
        offset = 0x1002C010 - boot_probe.BASE
        struct.pack_into('<2I', data, offset, 0xc18f8120, 0x1144ab0)
        for i, address in enumerate((0x1002C018, 0x1002C024, 0x1002C030)):
            struct.pack_into('<3I', data, address - boot_probe.BASE, 0x12000000 + i, 0xc1800000 + i, 32 + i)
        copies, zero_destination, zero_size = boot_probe.native_initialization_ranges(data)
        self.assertEqual(copies[0]['size'], 32)
        self.assertEqual((zero_destination, zero_size), (0xc18f8120, 0x1144ab0))

    def test_kernel_descriptor_name_is_at_0x30(self):
        data = bytearray(64)
        struct.pack_into('<5I', data, 0, 0, 0x41, 0x12340000, 7, 8192)
        data[48:56] = b'TestTask'
        d = boot_probe.describe_kernel_task(data)
        self.assertEqual(d['name'], 'TestTask')
        self.assertEqual(d['priority'], 7)
        self.assertEqual(d['entry'], '0x12340000')
        self.assertEqual(d['stack_bytes'], 8192)

    def test_short_or_non_ascii_descriptor_is_not_a_task_name(self):
        with self.assertRaises(ValueError):
            boot_probe.describe_kernel_task(bytes(48))
        data = bytearray(64)
        data[48] = 0xff
        self.assertIsNone(boot_probe.describe_kernel_task(data)['name'])

    def test_stop_reply_preserves_multiprocess_thread_id(self):
        self.assertEqual(boot_probe.stop_thread('T05thread:p1.2;core:1;'), 'p1.2')
        self.assertEqual(boot_probe.stop_thread('T05thread:2;'), '2')
        with self.assertRaises(ValueError):
            boot_probe.stop_thread('W02')

    def test_milestone_needs_scatter_proof_kernel_and_init_task_execution(self):
        state = dict(scatter_verified=True, kernel_start_seen=True,
                     init_task_started=False, tasks=[{'name':'InitTask'}])
        self.assertFalse(boot_probe.q1_complete(state))
        state['init_task_started'] = True
        self.assertTrue(boot_probe.q1_complete(state))
        state['scatter_verified'] = False
        self.assertFalse(boot_probe.q1_complete(state))

    def test_forced_failure_preserves_stack_and_selects_return_instruction_set(self):
        regs = {f'r{i}': hex(0x1000 + i * 4) for i in range(16)}
        regs.update(cpsr='0x60000013', packet_bytes=68, r14='0x12345679')
        words = struct.unpack('<17I', boot_probe.forced_failure_registers(regs, 6))
        self.assertEqual(words[0], 6)
        self.assertEqual(words[1:15], tuple(int(regs[f'r{i}'], 16) for i in range(1, 15)))
        self.assertEqual(words[15:], (0x12345678, 0x60000033))
        regs.update(r14='0x12345678', cpsr='0x60000033')
        words = struct.unpack('<17I', boot_probe.forced_failure_registers(regs, 6))
        self.assertEqual(words[16], 0x60000013)
        regs['packet_bytes'] = 168
        with self.assertRaises(ValueError):
            boot_probe.forced_failure_registers(regs, 6)

    def test_q2_rejects_only_created_tasks_or_only_a_gui_function_pc(self):
        state = dict(scatter_verified=True, kernel_start_seen=True, init_task_started=True,
                     tasks=[{'name': 'InitTask'}], ui_loop={'verified': True},
                     task_trace=[dict(name=n, created=True, entry_observed=True)
                                 for n in boot_probe.Q2_TASKS])
        self.assertTrue(boot_probe.q2_complete(state))
        state['task_trace'][0]['entry_observed'] = False
        self.assertFalse(boot_probe.q2_complete(state))
        state['task_trace'][0]['entry_observed'] = True
        state['ui_loop']['verified'] = False
        self.assertFalse(boot_probe.q2_complete(state))


if __name__ == '__main__':
    unittest.main()
