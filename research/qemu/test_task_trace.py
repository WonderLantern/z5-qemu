# SPDX-License-Identifier: GPL-2.0-or-later
"""任务实体核对：创建调用、返回和实际入口须分别有证据。"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from task_trace import TaskLedger, gui_wait_evidence, task_from_stack


class TaskTraceTests(unittest.TestCase):
    def test_stack_match_requires_unique_observed_created_task(self):
        a = dict(name='GUISRV', task_id=3, created=True, entry_observed=True,
                 entry_stack_pointer='0xc2001000', stack_bytes=4096)
        b = dict(a, name='other', task_id=4, entry_stack_pointer='0xc2003000')
        self.assertEqual(task_from_stack([a, b], 0xc2000f00)['name'], 'GUISRV')
        self.assertIsNone(task_from_stack([a, b], 0xc2001001))
        self.assertIsNone(task_from_stack([a, dict(a, name='overlap')], 0xc2000f00))
        self.assertIsNone(task_from_stack([dict(a, entry_observed=False)], 0xc2000f00))

    def task(self, name, exinf):
        return dict(name=name, entry='0x10232858', exinf=exinf, priority=5)

    def test_creation_attempt_does_not_count_as_created_or_running(self):
        ledger = TaskLedger()
        task = ledger.begin(self.task('Worker', 0x1000), 0x9000, 0xA000)
        self.assertFalse(task['created'])
        self.assertFalse(task['entry_observed'])
        ledger.returned(0x9000, 0xA000, 0xFFFFFFFB)
        self.assertFalse(task['created'])
        self.assertEqual(task['create_error'], -5)

    def test_return_tracks_descriptor_identity_across_cpu_migration(self):
        ledger = TaskLedger()
        a = ledger.begin(self.task('First', 0x1000), 0x9000, 0xA000)
        b = ledger.begin(self.task('Second', 0x2000), 0x9000, 0xB000)
        ledger.returned(0x9000, 0xB000, 8)
        self.assertEqual(b['task_id'], 8)
        self.assertFalse(a['created'])

    def test_shared_trampoline_uses_task_context_not_only_pc(self):
        ledger = TaskLedger()
        a = ledger.begin(self.task('First', 0x1000), 0x9000, 0xA000)
        b = ledger.begin(self.task('Second', 0x2000), 0x9000, 0xB000)
        ledger.returned(0x9000, 0xA000, 7)
        ledger.returned(0x9000, 0xB000, 8)
        self.assertIs(ledger.entered(0x10232858, 0x1000, 0x1000, 'p1.2'), a)
        self.assertTrue(a['entry_observed'])
        self.assertFalse(b['entry_observed'])
        self.assertIsNone(ledger.entered(0x10232858, 0, 0x3000, 'p1.1'))

    def test_gui_wait_needs_created_task_entry_handler_and_its_own_stack(self):
        task = dict(name='GUISRV', created=True, entry_observed=True, task_id=181,
                    native_handler='0x10467BB7', entry_stack_pointer='0xC2001000')
        regs = dict(r15='0x10467bbe', r13='0xc2000ff8', r0='0xc1d91a74', r1='0x13', r2='0xc2000ff8')
        self.assertTrue(gui_wait_evidence([task], regs)['verified'])
        for change in [dict(r13='0xc3000ff8'), dict(r0='0xc1d91a70'), dict(r1='0x1')]:
            self.assertFalse(gui_wait_evidence([task], dict(regs, **change))['verified'])
        task['entry_observed'] = False
        self.assertFalse(gui_wait_evidence([task], regs)['verified'])


if __name__ == '__main__':
    unittest.main()
