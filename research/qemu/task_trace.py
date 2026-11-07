# SPDX-License-Identifier: GPL-2.0-or-later
"""只整理任务观察证据，不控制 CPU，也不把创建调用当成运行成功。"""


def gui_wait_evidence(tasks, regs):
    """C1.50 GUISRV 循环首个等待点；核对任务、栈和事件参数。"""
    candidates = [t for t in tasks if t['name'] == 'GUISRV' and t['created'] and
                  t['entry_observed'] and t.get('native_handler') == '0x10467BB7']
    if len(candidates) != 1:
        return dict(verified=False, reason='GUISRV task identity or entry not confirmed')
    task = candidates[0]
    expected = dict(r15=0x10467BBE, r0=0xC1D91A74, r1=0x13,
                    r13=int(task['entry_stack_pointer'], 16) - 8)
    expected['r2'] = expected['r13']
    valid = all(int(regs[k], 16) == v for k, v in expected.items())
    return dict(verified=valid, task='GUISRV', task_id=task['task_id'],
                pc=regs['r15'], event_object=regs['r0'], event_mask=regs['r1'],
                stack_pointer=regs['r13'], loop_handler='0x10467BB6',
                observation='native first-iteration wait call; no GUI event injected',
                draw_dispatch_verified=False)


class TaskLedger:
    def __init__(self):
        self.tasks = []
        self.pending = {}

    def begin(self, descriptor, return_pc, call_context):
        key = (return_pc & ~1, call_context)
        if key in self.pending:
            raise ValueError('overlapping kernel create calls with the same context')
        task = dict(descriptor, created=False, task_id=None, entry_observed=False, entry_threads=[])
        self.tasks.append(task)
        self.pending[key] = task
        return task

    def returned(self, pc, call_context, value):
        task = self.pending.pop((pc & ~1, call_context), None)
        if task is None:
            return None
        signed = value if value < 0x80000000 else value - 0x100000000
        task['create_return'] = signed
        if signed > 0:
            task.update(created=True, task_id=signed)
        else:
            task['create_error'] = signed
        return task

    def entered(self, pc, r0, r1, thread):
        candidates = [t for t in self.tasks if t['created'] and
                      int(t['entry'], 16) & ~1 == pc & ~1 and t['exinf'] == r1]
        if len(candidates) != 1:
            return None
        task = candidates[0]
        task['entry_observed'] = True
        task['start_code'] = r0
        if thread not in task['entry_threads']:
            task['entry_threads'].append(thread)
        return task
