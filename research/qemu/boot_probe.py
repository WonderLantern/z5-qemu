# SPDX-License-Identifier: GPL-2.0-or-later
"""原厂启动/任务探针；Q1 无辅助，Q2 可显式选择处理单元失败返回。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time

from inspect_inputs import BASE, COPY, MAIN_SHA256, MAIN_SIZE, SCATTER_END, SCATTER_START, ZERO
from inspect_inputs import check_identity, read_scatter

from publication_paths import output_root

ROOT = Path(__file__).resolve().parents[2]
# Inherited Z6 photo-liveview device models (functional hypotheses; Z5 equivalence
# unproven): TG frame/half-frame pulses (IRQ 87) and the EX MCU test peer.
LIVEVIEW_HW_TEST_ENV = {'tg': {'Z5_TG_PERIODIC_TEST': '1', 'Z5_TG_PAIRED_TEST': '1'},
                        'exmcu': {'Z5_EXMCU_TEST_DEVICE': '1', 'Z5_EXMCU_NO_LENS': '1',
                                  'Z5_EXMCU_CAPTURE_SYNC_TEST': '1'},
                        # Route experiment: keep ISP boundary events while Z5 engine 1 runs.
                        'lv1': {'Z5_LV_ENGINE1_EVENTS': '1'}}
RAW_INPUT_LAYOUTS = {'ingress': 2272 * 1006, 'native0': 4080 * 1434}


def raw_input_env(directory):
    """Z5 RAW inputs from make_z5_raw.py; check sizes and hashes before QEMU starts.

    Enables the inherited ingress (engine 0x200), native0 (engine 0x400), ISP
    boundary and image-processing models. All are functional hypotheses."""
    directory = directory.resolve()
    if not directory.is_relative_to(output_root()):
        raise ValueError('directory must be below output/')
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    env = {}
    for kind, size in RAW_INPUT_LAYOUTS.items():
        path = directory / manifest[kind]['file']
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != manifest[kind]['sha256']:
            raise ValueError(f'{kind} input does not match its manifest or the expected size')
        env['Z5_RAW_INGRESS_TEST' if kind == 'ingress' else 'Z5_RAW_NATIVE0_TEST'] = str(path)
    env.update(Z5_ISP_BOUNDARY_TEST='1', Z5_IMAGE_PROCESS_TEST='1', Z5_IMAGE_CONFIG_RECORD='1')
    return env


Q2_TASKS = ('APPCTL', 'SYSCTL', 'GUISRV', 'GRAPHIC', 'DISPVDSR', 'FILESRV', 'SWSRV')
POINTS = {0x1002C234: 'native_zero', 0x1002BE80: 'native_copy',
          0x1002BEDC: 'native_copy', 0x1002BF38: 'native_copy',
          0x1027E118: 'post_scatter', 0x10035708: 'kernel_start',
          0x1003BD58: 'kernel_create_task', 0x100356B8: 'init_task_entry'}


def describe_kernel_task(data):
    if len(data) < 56:
        raise ValueError('short T_CTSK descriptor')
    words = struct.unpack_from('<5I', data)
    name = data[48:56].split(b'\0', 1)[0]
    return dict(name=name.decode('ascii') if name and all(32 <= c < 127 for c in name) else None,
                entry=f'0x{words[2]:08X}', priority=words[3], stack_bytes=words[4],
                attributes=f'0x{words[1]:08X}', exinf=words[0])


def stop_thread(packet):
    match = re.search(r'(?:^|;)thread:([^;]+);', packet[3:] if packet.startswith('T') else packet)
    if not match:
        raise ValueError(f'no stopped thread in {packet}')
    return match[1]


def q1_complete(state):
    return bool(state['scatter_verified'] and state['kernel_start_seen'] and
                state['init_task_started'] and any(t.get('name') == 'InitTask' for t in state['tasks']))


def q2_complete(state):
    running = {t['name'] for t in state['task_trace'] if t['created'] and t['entry_observed']}
    return q1_complete(state) and set(Q2_TASKS) <= running and state['ui_loop']['verified']


def forced_failure_registers(regs, value):
    """显式辅助：仅模拟 ABI 返回，不改固件、内存或栈。"""
    if regs['packet_bytes'] != 68:
        raise ValueError('forced return requires negotiated ARM registers')
    words = [int(regs[f'r{i}'], 16) for i in range(16)]
    lr = words[14]
    words[0] = value
    words[15] = lr & ~1
    cpsr = int(regs['cpsr'], 16)
    words.append(cpsr | 0x20 if lr & 1 else cpsr & ~0x20)
    return struct.pack('<17I', *words)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def limit_qemu_resources():
    """只限制本次子进程，不改 Windows/WSL 全局配置。"""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (6 * 1024**3, 6 * 1024**3))
    os.sched_setaffinity(0, set(sorted(os.sched_getaffinity(0))[:2]))
    os.nice(10)


class QMP:
    def __init__(self, port):
        self.sock = socket.create_connection(('127.0.0.1', port), 10)
        self.sock.settimeout(10)
        self.stream = self.sock.makefile('rb')
        self.read()
        self.command('qmp_capabilities')

    def read(self):
        line = self.stream.readline()
        if not line:
            raise EOFError('QMP closed')
        return json.loads(line)

    def command(self, name, arguments=None):
        request = {'execute': name}
        if arguments is not None:
            request['arguments'] = arguments
        self.sock.sendall(json.dumps(request).encode() + b'\n')
        while True:
            packet = self.read()
            if 'error' in packet:
                raise RuntimeError(packet['error'])
            if 'return' in packet:
                return packet['return']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--main', required=True, type=Path)
    parser.add_argument('--patched-main', type=Path,
                        help='运行自建补丁固件（EG165050.BIN，需同名 .json 报告）；先用原厂 --main 与报告逐字节核对，通过才加载')
    parser.add_argument('--out', required=True, type=Path, help='新的 output/ 子目录')
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--trace-tasks', action='store_true', help='Q2：观察主要任务入口和 GUISRV 主循环等待点')
    parser.add_argument('--skip-processing-init', action='store_true', help='显式辅助：102e0b70 返回原厂失败值 6，跳过处理单元初始化')
    parser.add_argument('--display', action='store_true', help='Q3：在 Q2 之后继续诊断原厂显示输出')
    parser.add_argument('--processing-init-standin', action='store_true', help='Q3 诊断模型：原厂处理初始化配置后提供合成就绪状态')
    parser.add_argument('--startup-environment-standin', action='store_true', help='Q3 诊断：合成启动测量值并清除已核对的设置初始化故障标志')
    parser.add_argument('--application-ready-standin', action='store_true', help='Q3 诊断：通过原厂队列发送合成应用就绪报告 02000004/05')
    parser.add_argument('--trace-error-producer', action='store_true',
                        help='Q3 诊断（只观察）：记录元素编号为错误文字 0x27E/0x27F/0x280 的文字控件构造及其调用栈')
    parser.add_argument('--sensor-standin', action='store_true',
                        help='Q3 诊断：未建模图像传感器；跳过并记录 CSEQ 设备错误报告 0x34-0x36/0x3E-0x44（1020327c 强制返回）')
    parser.add_argument('--card-standin', action='store_true',
                        help='Q3 诊断：未建模 SD 卡；介质状态查询 102abfc2 强制返回 1（无卡）并记录')
    parser.add_argument('--q4-keys', default='',
                        help='Q4：拍摄画面出现后经原厂 AO 入口依次按键并逐张截图，如 menu,left,down*6,right')
    parser.add_argument('--q4-require-change', action='store_true', help='Q4：仅当画面相对按键前改变且连续稳定时标记通过')
    parser.add_argument('--dump-ram', default='',
                        help='诊断：Q4 结束后把客体内存写入 output（逗号分隔 地址:长度，十六进制，每段最多 0x100000）')
    parser.add_argument('--q4-trace-pcs', default='',
                        help='Q4 诊断（只观察，需 --q4-trace-keys）：逗号分隔的十六进制地址，按键后记录命中时寄存器与栈上代码地址')
    parser.add_argument('--q4-trace-keys', action='store_true',
                        help='Q4 诊断（只观察）：每次按键后记录应用任务回调与 GUI 分发收到的消息（每键最多 40 条）')
    parser.add_argument('--liveview-hw-test', default='',
                        help="实时取景实验：逗号分隔 tg（继承 Z6 的 TG 周期/成对脉冲）、exmcu（EXMCU 测试设备、无镜头、拍摄同步）、raw=<output 下由 make_z5_raw.py 生成的目录>（需 tg；ingress/native0 输入及 ISP 边界和图像处理模型）")
    parser.add_argument('--capture-status-standin', action='store_true', help='诊断：在原厂读取前将已核对的未初始化捕获状态 2 改为 0')
    parser.add_argument('--sensor-calibration-standin', action='store_true', help='诊断：在版本检查前填入合成传感器校准字节')
    parser.add_argument('--sensor-reply-standin', action='store_true', help='诊断：启用 EX MCU 对端并让传感器错误 0x34 原样传播')
    parser.add_argument('--expose-sensor-3f', action='store_true', help='诊断：让传感器错误 0x3F 原样传播')
    parser.add_argument('--start-liveview-test', action='store_true', help='诊断：调用候选原厂 StartLV 动作并记录返回')
    parser.add_argument('--observe-guest-ms', type=int, default=0, help='额外运行并观察指定毫秒的客体时间（上限 120000）')
    parser.add_argument('--lv-background', type=Path,
                        help='界面参考：主机把 720x480 RGB24 底图合成到空的取景底层（make_lv_background.py 生成；不是固件取景管线）')
    parser.add_argument('--interactive-port', type=int, default=0,
                        help='交互查看：启动后在 127.0.0.1:<端口> 提供网页画面和按键（需 --display）')
    parser.add_argument('--interactive-minutes', type=int, default=30, help='交互会话上限（1..120 分钟）')
    parser.add_argument('--keep-awake', action='store_true',
                        help='经原厂设置接口把待机计时器 0x1121 设为 9（0 秒，不关屏），仅本次模拟器会话')
    args = parser.parse_args()
    if os.name == 'nt':
        parser.error('run this probe in the Linux build environment')
    if args.skip_processing_init and not args.trace_tasks:
        parser.error('--skip-processing-init requires --trace-tasks')
    if args.display and not args.trace_tasks:
        parser.error('--display requires --trace-tasks')
    if args.processing_init_standin and (not args.display or args.skip_processing_init):
        parser.error('processing stand-in requires --display and forbids --skip-processing-init')
    if args.startup_environment_standin and not args.display:
        parser.error('startup environment stand-in requires --display')
    if args.application_ready_standin and not args.startup_environment_standin:
        parser.error('application readiness stand-in requires --startup-environment-standin')
    if args.trace_error_producer and not args.display:
        parser.error('--trace-error-producer requires --display')
    if args.capture_status_standin and not args.trace_error_producer:
        parser.error('--capture-status-standin requires --trace-error-producer')
    if args.sensor_calibration_standin and not args.sensor_standin:
        parser.error('--sensor-calibration-standin requires --sensor-standin')
    if args.sensor_reply_standin and not args.sensor_standin:
        parser.error('--sensor-reply-standin requires --sensor-standin')
    if args.expose_sensor_3f and not args.sensor_standin:
        parser.error('--expose-sensor-3f requires --sensor-standin')
    if args.start_liveview_test and not args.display:
        parser.error('--start-liveview-test requires --display')
    if not 0 <= args.observe_guest_ms <= 120000 or (args.observe_guest_ms and not args.display):
        parser.error('--observe-guest-ms requires --display and must be 0..120000')
    if args.sensor_standin and not args.display:
        parser.error('--sensor-standin requires --display')
    if args.interactive_port and (not args.display or not 1024 <= args.interactive_port <= 65535
                                  or not 1 <= args.interactive_minutes <= 120):
        parser.error('--interactive-port needs --display, a port 1024..65535 and 1..120 minutes')
    if (args.lv_background or args.keep_awake) and not args.display:
        parser.error('--lv-background and --keep-awake require --display')
    if args.lv_background:
        background = args.lv_background.resolve()
        if not background.is_relative_to(output_root()) or background.stat().st_size != 720 * 480 * 3:
            parser.error('--lv-background must be a 720x480 RGB24 file below output/')
    if args.card_standin and not args.display:
        parser.error('--card-standin requires --display')
    q4_keys = []
    for item in filter(None, args.q4_keys.split(',')):
        name, _, count = item.partition('*')
        q4_keys += [name.strip()] * int(count or 1)
    from q3_display import Q4_KEYS
    if any(k not in Q4_KEYS for k in q4_keys) or len(q4_keys) > 40:
        parser.error('--q4-keys: unknown key or more than 40 presses; keys: ' + ','.join(Q4_KEYS))
    liveview_env = {}
    if args.lv_background:
        liveview_env['Z5_LV_BACKGROUND'] = str(args.lv_background.resolve())
    for part in filter(None, args.liveview_hw_test.split(',')):
        if part.startswith('raw='):
            try:
                liveview_env.update(raw_input_env(Path(part[4:])))
            except ValueError as exc:
                parser.error(f'--liveview-hw-test raw: {exc}')
            continue
        if part not in LIVEVIEW_HW_TEST_ENV:
            parser.error('--liveview-hw-test parts: ' + ','.join(LIVEVIEW_HW_TEST_ENV))
        liveview_env.update(LIVEVIEW_HW_TEST_ENV[part])
    if 'Z5_RAW_INGRESS_TEST' in liveview_env and 'Z5_TG_PERIODIC_TEST' not in liveview_env:
        parser.error('--liveview-hw-test raw=<dir> requires tg')
    if args.sensor_reply_standin:
        liveview_env['Z5_EXMCU_TEST_DEVICE'] = '1'
    if q4_keys and not args.display:
        parser.error('--q4-keys requires --display')
    if args.q4_require_change and not q4_keys:
        parser.error('--q4-require-change requires --q4-keys')
    if not 1 <= args.seconds <= 600:
        parser.error('--seconds must be 1..600')
    out = args.out.resolve()
    if not out.is_relative_to(output_root()) or out.exists():
        parser.error('--out must be a new directory below shared output/')
    image = args.main.read_bytes()
    check_identity(image, MAIN_SIZE, MAIN_SHA256)
    firmware_path, firmware_sha256, patched_summary = args.main.resolve(), MAIN_SHA256, None
    if args.patched_main:
        from patched_main import verify
        firmware_path = args.patched_main.resolve()
        report = json.loads(firmware_path.with_name(firmware_path.name + '.json').read_text(encoding='utf-8'))
        try:
            patched_summary = verify(image, firmware_path.read_bytes(), report, MAIN_SHA256)
        except ValueError as exc:
            parser.error(f'--patched-main rejected: {exc}')
        firmware_sha256 = patched_summary['patched_sha256']
    loaded = firmware_path.read_bytes() if patched_summary else image
    scatter = read_scatter(image, BASE, SCATTER_START, SCATTER_END, COPY, ZERO)
    # 实际 ARM reset 路径独立初始化 RW/ZI，随后直达 CRT continuation。
    native_copies = [dict(source=source, destination=destination, size=size)
                     for source, destination, size in
                     (struct.unpack_from('<3I', image, a - BASE)
                      for a in (0x1002C018, 0x1002C024, 0x1002C030))]
    zero_destination, zero_size = struct.unpack_from('<2I', image, 0x1002C010 - BASE)
    project = ROOT / 'reference/z5-qemu'
    build = json.loads((project / '.local/build-manifest.json').read_text())
    if hashlib.sha256(Path(build['binary']).read_bytes()).hexdigest() != build['binary_sha256']:
        parser.error('QEMU binary changed; rebuild first')
    for name, digest in build['sources'].items():
        if hashlib.sha256((project / name).read_bytes()).hexdigest() != digest:
            parser.error('QEMU source changed; rebuild first')
    sys.path.insert(0, str(project / 'tools'))
    from rsp import Remote
    out.mkdir(parents=True)
    port, qmp_port = free_port(), free_port()
    command = [build['binary'], '-M', 'nikon-z5-display', '-smp', '2', '-display', 'none',
               '-serial', 'none', '-monitor', 'none', '-nic', 'none', '-bios', str(firmware_path),
               '-device', 'loader,addr=0x10020000,cpu-num=0', '-device', 'loader,addr=0x10020000,cpu-num=1',
               '-chardev', f'file,id=z5uart,path={out / "uart.log"}', '-S',
               '-gdb', f'tcp:127.0.0.1:{port}', '-qmp', f'tcp:127.0.0.1:{qmp_port},server=on,wait=off',
               '-accel', 'tcg,thread=single', '-icount', 'shift=6,align=off,sleep=off']
    state = dict(milestone='Q1', emulator_verified=False, camera_verified=False,
                 scatter_verified=False, kernel_start_seen=False, init_task_started=False,
                 tasks=[], events=[], firmware_sha256=firmware_sha256, firmware_modified=bool(patched_summary), patched_main=patched_summary,
                 host_ram_fixtures=[], hle_calls=[], command=command, build=build,
                 resource_limits=dict(address_space_mib=6144, host_cpu_count=2, nice=10),
                 processing_init_standin=args.processing_init_standin,
                 display_budget_s=60 if 'Z5_RAW_INGRESS_TEST' in liveview_env else 30,
                 startup_environment_standin=args.startup_environment_standin,
                 application_ready_standin=args.application_ready_standin,
                 trace_error_producer=args.trace_error_producer,
                 capture_status_standin=args.capture_status_standin,
                 sensor_calibration_standin=args.sensor_calibration_standin,
                 sensor_reply_standin=args.sensor_reply_standin,
                 expose_sensor_3f=args.expose_sensor_3f,
                 start_liveview_test=args.start_liveview_test,
                 observe_guest_ms=args.observe_guest_ms,
                 sensor_standin=args.sensor_standin,
                 card_standin=args.card_standin,
                 keep_awake=args.keep_awake,
                 interactive_port=args.interactive_port or None,
                 interactive_minutes=args.interactive_minutes,
                 lv_background=str(args.lv_background.resolve()) if args.lv_background else None,
                 liveview_hw_test=liveview_env or None,
                 q4_keys=q4_keys,
                 q4_require_change=args.q4_require_change,
                 q4_trace_keys=args.q4_trace_keys,
                 dump_ranges=[(int(a, 16), min(int(n, 16), 0x100000)) for a, n in (x.split(':') for x in filter(None, args.dump_ram.split(',')))],
                 q4_trace_pcs=[int(x, 16) for x in filter(None, args.q4_trace_pcs.split(','))],
                 assumptions=['Cortex-A15', 'CBAR 0x2C000000', 'GIC revision 1', '48 MHz timer',
                              'inherited Z6 peripheral models; unknown guest accesses stop'])
    from task_trace import TaskLedger, gui_wait_evidence
    ledger = TaskLedger()
    if args.trace_tasks:
        state.update(milestone='Q2-exploration', q1_verified=False, q2_verified=False,
                     task_trace=ledger.tasks, ui_loop=dict(verified=False), required_tasks=Q2_TASKS)
    points = dict(POINTS)
    if args.trace_tasks:
        points[0x1003C064] = 'kernel_create_exit'
        points[0x10467BBE] = 'gui_loop_wait'
    if args.display:
        points[0x10445CB8] = 'pre_gui_allocation'
    if args.skip_processing_init:
        points[0x102E0B70] = 'processing_init_skipped'
    proc = remote = monitor = None
    started = time.monotonic()
    with (out / 'qemu.log').open('x') as log:
        try:
            proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                    preexec_fn=limit_qemu_resources,
                                    env=dict(os.environ, Z5_MMIO_QUIET='1',
                                        **({'Z5_ALLOWED_MAIN_SHA256': firmware_sha256} if patched_summary else {}),
                                        **({'Z5_LCD_SCANOUT_TEST': '1'} if args.display else {}),
                                        **({'Z5_PROCESSING_INIT_STANDIN': '1'} if args.processing_init_standin else {}),
                                        **liveview_env))
            remote = Remote(port)
            remote.command('qSupported:multiprocess+;xmlRegisters=arm')
            remote.command('qXfer:features:read:target.xml:0,fff')
            remote.command('Hg0')
            if ';s' not in remote.command('vCont?'):
                raise RuntimeError('QEMU lacks explicit per-thread stepping')
            monitor = QMP(qmp_port)
            for address in points:
                if remote.command(f'Z1,{address:x},2') != 'OK':
                    raise RuntimeError(f'breakpoint rejected {address:x}')
            active = set(points)
            def add_point(address):
                address &= ~1
                if address not in active:
                    if remote.command(f'Z1,{address:x},2') != 'OK':
                        raise RuntimeError(f'dynamic breakpoint rejected {address:x}')
                    active.add(address)

            while time.monotonic() - started < args.seconds:
                remote.sock.settimeout(min(30, args.seconds - (time.monotonic() - started) + 1))
                packet = remote.command('vCont;c')
                thread = stop_thread(packet)
                remote.command('Hg' + thread)
                regs = remote.registers()
                pc = int(regs['r15'], 16)
                event = dict(pc=regs['r15'], thread=thread, name=points.get(pc, 'unexpected_stop'),
                             registers=regs, elapsed_seconds=round(time.monotonic() - started, 3))
                state['events'].append(event)
                if pc not in active:
                    raise RuntimeError('stopped away from expected checkpoint')
                if pc == 0x10445CB8 and args.display:
                    if args.trace_error_producer:
                        from q3_display import CARD_SLOT_STATE
                        state['slot_state_at_display'] = remote.memory(CARD_SLOT_STATE, 8).hex()
                    for address in active:
                        remote.command(f'z1,{address:x},2')
                    state['display_startpoint'] = '0x10445CB8 before native GUI allocation'
                    from q3_display import run_display
                    run_display(remote, monitor, state, out, image)
                    break
                if pc == 0x102E0B70 and args.skip_processing_init:
                    forced = forced_failure_registers(regs, 6)
                    if remote.command('G' + forced.hex()) != 'OK':
                        raise RuntimeError('explicit forced failure rejected')
                    state['hle_calls'].append(dict(kind='forced failure return; native body skipped',
                        function='0x102E0B70', return_r0=6, before=regs, after=remote.registers(),
                        reason='processing hardware 2b200000/2a900000 unmodeled; Q2 assisted boot'))
                    print(json.dumps(dict(name=event['name'], pc=event['pc'], thread=thread)), flush=True)
                    continue
                if args.trace_tasks:
                    # 内核退出处 R5 仍是描述符，R4 是返回值；CPU 迁移后 SP 可变。
                    returned = ledger.returned(pc, int(regs['r5'], 16), int(regs['r4'], 16))
                    if returned:
                        event.update(name='task_create_return', task=returned['name'], create_return=returned['create_return'])
                    entered = ledger.entered(pc, int(regs['r0'], 16), int(regs['r1'], 16), thread)
                    if entered:
                        event.update(name='task_entry', task=entered['name'], task_id=entered['task_id'])
                        entered['entry_stack_pointer'] = regs['r13']
                        if pc == 0x10232858:
                            handler = struct.unpack('<I', remote.memory(entered['exinf'] + 4, 4))[0]
                            entered['native_handler'] = f'0x{handler:08X}'
                    if pc == 0x10467BBE:
                        state['ui_loop'] = gui_wait_evidence(ledger.tasks, regs)
                        if not state['ui_loop']['verified']:
                            raise RuntimeError('GUI wait checkpoint does not match the observed task context')
                if event['name'] == 'native_copy':
                    event['arguments'] = dict(source=int(regs['r0'], 16), destination=int(regs['r1'], 16), size=int(regs['r2'], 16))
                if event['name'] == 'native_zero':
                    event['arguments'] = dict(destination=int(regs['r0'], 16), size=int(regs['r1'], 16))
                if pc == 0x1027E118:
                    copies = []
                    for row in native_copies:
                        src, dst, size = row['source'], row['destination'], row['size']
                        if size:
                            actual = remote.memory(dst, size)
                            equal = actual == image[src - BASE:src - BASE + size]
                            copies.append(dict(destination=f'0x{dst:08X}', size=size, matches=equal))
                    state['copied_ram_checks'] = copies
                    observed = [e['arguments'] for e in state['events'] if e['name'] == 'native_copy']
                    zero = remote.memory(zero_destination, zero_size)
                    observed_zero = [e['arguments'] for e in state['events'] if e['name'] == 'native_zero']
                    state['zero_ram_check'] = dict(destination=f'0x{zero_destination:08X}', size=zero_size, all_zero=not any(zero))
                    state['initialization_path'] = 'native ARM reset code; generic Thumb scatter dispatcher is bypassed'
                    state['scatter_table_records'] = len(scatter)
                    state['scatter_verified'] = (all(c['matches'] for c in copies) and observed == native_copies and
                        not any(zero) and observed_zero == [dict(destination=zero_destination, size=zero_size)])
                    if not state['scatter_verified']:
                        raise RuntimeError('scatter execution or copied RAM differs from stock table')
                if pc == 0x10035708:
                    state['kernel_start_seen'] = True
                if pc == 0x1003BD58:
                    task = describe_kernel_task(remote.memory(int(regs['r0'], 16), 64))
                    task.update(thread=thread, descriptor=regs['r0'])
                    state['tasks'].append(task)
                    if args.trace_tasks:
                        ledger.begin(task, 0x1003C064, int(regs['r0'], 16))
                        add_point(int(task['entry'], 16))
                if pc == 0x100356B8:
                    state['init_task_started'] = True
                print(json.dumps({k: event[k] for k in ['name', 'pc', 'thread', 'elapsed_seconds', 'task'] if k in event}), flush=True)
                if q1_complete(state):
                    if args.trace_tasks:
                        state['q1_verified'] = True
                        if q2_complete(state) and not state['q2_verified']:
                            checks = []
                            for src, dst, size, prefix in [(0x10000000, 0xCC400000, 0x300000, 0x20000),
                                    (0x10300000, 0xCC700000, 0x400000, 0),
                                    (0x11F45090, 0x80300000, 0x27800, 0)]:
                                # ROM copies may contain our verified edits: compare with the loaded image.
                                expected = b'\xff' * prefix + loaded[src + prefix - BASE:src + size - BASE]
                                actual = remote.memory(dst, size)
                                checks.append(dict(source=hex(src), destination=hex(dst), size=size,
                                    erased_prefix=prefix, matches=actual == expected,
                                    observed_sha256=hashlib.sha256(actual).hexdigest()))
                            state['native_dma_checks'] = checks
                            if not all(c['matches'] for c in checks):
                                raise RuntimeError('native boot DMA result differs from checked input')
                            state.update(milestone='Q2', q2_verified=True, emulator_verified=True)
                            if not args.display:
                                break
                    else:
                        state['emulator_verified'] = True
                        break
                remote.command(f'z1,{pc:x},2')
                repeat = pc in (0x10035708, 0x1003BD58, 0x1003C064)
                if args.trace_tasks:
                    repeat |= (any(int(t['entry'], 16) & ~1 == pc for t in ledger.tasks) or
                               any(ret_pc == pc for ret_pc, _ in ledger.pending))
                if not repeat:
                    active.remove(pc)
                step = remote.command('vCont;s:' + thread)
                if not step.startswith('T05') or stop_thread(step) != thread:
                    raise RuntimeError(f'unexpected single-step reply: {step}')
                if pc in active:
                    remote.command(f'Z1,{pc:x},2')
            if args.trace_tasks and not args.display and not state['q2_verified'] and 'error' not in state:
                state['error'] = 'time budget expired before Q2 acceptance'
            elif args.display and not state.get('q3_verified') and 'error' not in state:
                state['error'] = 'time budget expired before Q3 acceptance'
            elif not q1_complete(state):
                state['error'] = 'time budget expired before Q1 completion'
        except Exception as exc:
            state['error'] = f'{type(exc).__name__}: {exc}'
            if isinstance(exc, TimeoutError) and proc is not None and proc.poll() is None:
                try:
                    trace = subprocess.run(['gdb', '-batch', '-ex', 'set pagination off',
                        '-ex', 'thread apply all bt 8', '-p', str(proc.pid)],
                        capture_output=True, text=True, timeout=10)
                    (out / 'host-backtrace.log').write_text(trace.stdout + trace.stderr)
                except (OSError, subprocess.TimeoutExpired) as trace_error:
                    state['host_backtrace_error'] = str(trace_error)
            if monitor is not None and proc is not None and proc.poll() is None:
                try:
                    monitor.command('stop')
                    state['last_cpus'] = monitor.command('query-cpus-fast')
                    state['last_cpu_registers'] = monitor.command('human-monitor-command',
                        {'command-line': 'info registers -a'})
                except Exception as capture_error:
                    state['capture_error'] = str(capture_error)
        finally:
            if proc is not None and proc.poll() is None:
                if monitor is not None:
                    try:
                        monitor.command('quit')
                    except (OSError, EOFError, RuntimeError):
                        pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                        state['forced_host_kill'] = True
            state['process_exit_code'] = proc.returncode if proc is not None else None
            import resource
            state['children_peak_rss_kib'] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            state['elapsed_seconds'] = round(time.monotonic() - started, 3)
            with (out / 'result.json').open('x', encoding='utf-8') as report:
                json.dump(state, report, indent=2)
                report.write('\n')
    passed = state.get('q3_verified', False) if args.display else state['q2_verified'] if args.trace_tasks else q1_complete(state)
    print(json.dumps(dict(passed=passed, milestone=state['milestone'], error=state.get('error'), out=str(out))), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
