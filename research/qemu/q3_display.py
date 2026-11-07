# SPDX-License-Identifier: GPL-2.0-or-later
"""Q3 原厂绘制诊断；图像只来自 QMP，不由宿主补画界面。"""
import hashlib
import signal
import socket
import struct
import time
import zlib

# --trace-error-producer only: return addresses of the status sub-calls OR'd by
# FUN_1011e1e4 / FUN_1011deb0 / FUN_1011fe96 (the device-status word that
# FUN_100f0a0a turns into error-list codes).  return address -> callee.
STATUS_RETURNS = {
    0x1011E1F0: '1012da8c', 0x1011E200: '101401b6', 0x1011E218: '1011df06', 0x1011E22C: '1013a2a4',
    0x1011DECE: '1013f6c6', 0x1011DED6: '1013f8fa', 0x1011DEE0: '1013f9f4', 0x1011DEEA: '1011de84',
    0x1011DEF2: '1011db1a', 0x1011DEFA: '1011dca6',
    0x1011FEA4: '1011de84', 0x1011FEBE: '1013f6c6', 0x1011FEC8: '1013f8fa', 0x1011FED2: '1013f9f4',
    0x1011FEDA: '1011db1a',
    # inside FUN_1011dca6(0), which returned 0x20 (-> code 0x3E)
    0x1011DCCA: '1013a2a4', 0x1011DCD4: '1013a2a4', 0x1011DCDE: '1013a2a4', 0x1011DCE8: '1013a474',
    0x1011DCF2: '1013a548', 0x1011DD0C: '10121478', 0x1011DD1C: '1013b006', 0x1011DD28: '1013b006',
    0x1011DD34: '1013a894', 0x1011DD40: '1013a894', 0x1011DD52: '1013a946', 0x1011DD5A: '1013a91c',
    0x1011DD6A: '1019a25e', 0x1011DD9C: '1013a946', 0x1011DDAC: '1013b006', 0x1011DDB8: '1013b006',
    0x1011DDC4: '1013a894', 0x1011DDCC: '1013a95c', 0x1011DDD4: '1013a562', 0x1011DDDE: '1013a894',
    0x1011DDE6: '1013a588', 0x1011DDEE: '1013a5a6', 0x1011DDFA: '1013b006', 0x1011DE04: '1013a976',
    0x1011DE0E: '1013a946', 0x1011DE16: '1013a91c', 0x1011DE26: '101213ea',
}

# --sensor-standin: the emulator has no image-sensor model.  Root causes found with
# --trace-error-producer (emulator_verified, camera_verified: false):
#   0x44  FUN_101401b6 (sensor control) reads the sensor adjustment block (factory
#         data, region id 0x4A, base *(0xC18E62E4+0x18), byte +0xB8012 must be 0x19);
#         the block is all zero here -> status 0x400 -> FUN_100f0a0a index 14.
#   0x3E  FUN_1011dca6 waits 50 ms for a sensor frame event (flag 0xC2A14DE0 mask 8)
#         -> timeout -> status 0x20 -> index 8.
#   0x34  CaptureSequenceService FUN_10205528 waits 3000 ms for the sensor operation
#         started by FUN_10121d6c -> timeout -> FUN_1020408a.
#   0x3F  sensor control status 0x100 reported later by FUN_100f0e22 -> index 9.
# CaptureSequenceService FUN_1020327c(report{code u8, param u32, mask u16}) is the
# single entry that applies a device error (warning mask, error list 0x1921, state).
# With --sensor-standin the reports with sensor-path codes are skipped (forced
# return, native body not run) and recorded; every other code passes unchanged.
# --trace-error-producer: settings read by the card warnings (0x2F00/0x2F01 slot
# state bytes, 0x2F02/0x2F03, 0x1905 card bit field, 0x1918, 0x1B04).
CARD_SETTINGS = {0x2F00, 0x2F01, 0x2F02, 0x2F03, 0x1905, 0x1918, 0x1B04}
CARD_SLOT_STATE = 0xC253DC80   # storage of settings 0x2F00/0x2F01 (descriptor default 0)
# Setting-core functions using descriptor table 0x115C286C (except the hot getter
# 0x100B6520); with --trace-error-producer calls naming 0x2F00/0x2F01 are recorded.
# The slot-state writer found this way is FUN_100b682c(id, value) from FUN_103aa404.
SETTING_CORE = (0x100B65F8, 0x100B66E2, 0x100B682C, 0x100B67E4, 0x100B656E, 0x100B68AA, 0x100B6774,
                0x100B665E, 0x100B6730, 0x100B67AA, 0x100B68FC, 0x100B6BB6, 0x100B69E4, 0x100B6992, 0x100B6C32)
SENSOR_ERROR_REPORT = 0x1020327C
# --keep-awake: SettingDataService read 10456098(id) / write 104560A4(id, value),
# AppC standby state C1819254 (+0 mode byte, +0x10 seconds), recompute 1008D790.
SETTING_READ, SETTING_WRITE = 0x10456098, 0x104560A4
STANDBY_STATE, STANDBY_RECOMPUTE = 0xC1819254, 0x1008D790
# --q4-keys: native AO key indices (C1.50 AO table 0x1072FE84, 16-byte entries
# {enabled, bank, group, mask}); masks matched to the ID_SW name table
# (40-byte entries, ID_SW1_MENU at 0x107375B8).  Same indices as the Z7 emulator.
# disp/help/zoom: matched by (bank, group, mask) to ID_SW1_INFO (the Z5 DISP
# button keeps the DSLR name), ID_SW1_HELP, ID_SW1_ZOOM and ID_SW1_THUMBNAIL.
Q4_KEYS = {'right': 34, 'left': 35, 'up': 36, 'down': 37,
           'menu': 67, 'play': 68, 'delete': 69, 'i': 72, 'ok': 74,
           'help': 70, 'disp': 71, 'zoom_in': 75, 'zoom_out': 76}
# --trace-error-producer (open lead, see handoff): with --liveview-hw-test tg the
# guest stops at ~23.4 s on an unmodeled NOR flash command write 0x10000AAA=0xAA
# from RAM 0xC2A9065A (flash routines copied from ROM 0x1211C100 to 0xC2A90000;
# lr 0xC2A9013F lies in RAM 0xC2A9012C, which calls the writer 0xC2A90656).
# The two points below were tried as entry traces and did NOT fire in that run.
FLASH_WRITE = 0x101A98CE            # wrapper of veneer 0x1017EB58 -> RAM 0xC2A9061E
EXCEPTION_LOG_ACTION = 0xC2A90038   # RAM reader behind veneer 0x1017EAFC (FUN_101fa308, "A:\CPUEXCEP.LOG")
# --card-standin: the emulator has no SD host/card model.  C1.50 FUN_102a49e8
# (per slot) asks the file service for the media status with FUN_102abfc2(drive)
# (request code 2) and maps the reply: 1 -> internal 0 -> setting 0x2F00/0x2F01 = 0
# ("no memory card", cf. warning 5 FUN_103716ca); 0 -> 1; 3 -> 2; other -> internal
# 4 -> setting 3 ("[1][2] Cannot access these memory cards", text 0x956).  Without
# a card model the reply is "other".  The stand-in returns 1 (no media) at entry.
FLASH_PROGRAM_ENTRY = 0xC2A9012C
FLASH_TRANSACTION_ENTRY = 0xC2A90494
CPU_EXCEPTION_ENTRY = 0x10054680
CAPTURE_INFO_POINTS = (0x10071E1C, 0x10071E22)
CAPTURE_STATUS_SETTER = 0x10184C96
CARD_MEDIA_STATUS = 0x102ABFC2
CARD_NO_MEDIA = 1
SENSOR_ERROR_CODES = set(range(0x34, 0x37)) | set(range(0x3E, 0x45))
SENSOR_CALIBRATION_CHECK = 0x101401B6
TG_CONTROL_WRITES = (0x1012B046, 0x1012B04C, 0x1012B07A, 0x1012B082)
CSEQ_SENSOR_POINTS = (0x10205528, 0x10205570, 0x10205582, 0x10205586, 0x10208772, 0x102087AA,
                      0x10121D6C, 0x1005929E, 0x100592AA, 0x1027AC32, 0x1027AD3E, 0x1005944E)


def sensor_error_suppressed(code, calibration_standin, reply_standin=False, expose_3f=False):
    return (code in SENSOR_ERROR_CODES and not (calibration_standin and code == 0x44)
            and not (reply_standin and code == 0x34) and not (expose_3f and code == 0x3f))


class SafeRemote:
    """复用固定上游 call_fixture，同时修正其 legacy c/s 的双核语义。"""
    def __init__(self, remote):
        self.remote = remote
        self.step_thread = None

    def __getattr__(self, name):
        return getattr(self.remote, name)

    def translate(self, value):
        if value.startswith('Hc'):
            if value != 'Hc-1': self.step_thread = value[2:]
            return None
        if value == 'c': return 'vCont;c'
        if value == 's':
            if not self.step_thread: raise ValueError('explicit step thread required')
            return 'vCont;s:' + self.step_thread
        return value

    def command(self, value):
        translated = self.translate(value)
        return 'OK' if translated is None else self.remote.command(translated)

    def send(self, value):
        translated = self.translate(value)
        if translated is None: raise ValueError('send cannot suppress a reply-bearing command')
        return self.remote.send(translated)


def frame_stats(data):
    try:
        magic, dimensions, maximum, pixels = data.split(b'\n', 3)
        width, height = map(int, dimensions.split())
    except ValueError as exc:
        raise ValueError('invalid QMP P6 header') from exc
    if magic != b'P6' or maximum != b'255' or not (0 < width <= 4096 and 0 < height <= 4096) or len(pixels) != width * height * 3:
        raise ValueError('invalid QMP screenshot size or packing')
    colors = {pixels[i:i+3] for i in range(0, len(pixels), 3)}
    return dict(width=width, height=height, unique_colors=len(colors), nonuniform=len(colors) > 1,
                rgb_sha256=hashlib.sha256(pixels).hexdigest())


def q3_accepted(frame, native_draw_seen, lcd_scanout_seen):
    return bool(frame['nonuniform'] and native_draw_seen and lcd_scanout_seen)


def q4_frame_settled(previous, hashes, nonuniform, require_change):
    return bool(len(hashes) >= 2 and hashes[-1] == hashes[-2] and nonuniform and
                (not require_change or hashes[-1] != previous))


def checked_ram_fixture(remote, records, reason, address, before, after):
    if not (0xC1800000 <= address < address + len(before) <= 0xC8700000) or len(before) != len(after):
        raise ValueError('fixture must stay within guest RAM and preserve size')
    if remote.memory(address, len(before)) != before:
        raise ValueError(f'fixture original bytes differ at {address:#x}')
    if remote.command(f'M{address:x},{len(after):x}:' + after.hex()) != 'OK':
        raise RuntimeError('guest RAM fixture rejected')
    records.append(dict(kind='synthetic guest RAM fixture', reason=reason, address=hex(address),
                        before=before.hex(), after=after.hex()))


def apply_capture_status_standin(remote, records):
    current = remote.memory(0xC18C8C6B, 1)
    if current == b'\x02':
        checked_ram_fixture(remote, records,
            'synthetic capture-info status; native status 2 cleared the pointer used unconditionally',
            0xC18C8C6B, b'\x02', b'\x00')
    elif current != b'\x00' or not records:
        raise ValueError('unexpected capture-info status')


def capture(monitor, out, name):
    ppm = out / (name + '.ppm')
    png = out / (name + '.png')
    if ppm.exists() or png.exists(): raise ValueError('refusing to overwrite a screenshot')
    monitor.command('screendump', {'filename': str(ppm)})
    data = ppm.read_bytes()
    stats = frame_stats(data)
    pixels = data.split(b'\n', 3)[3]
    width, height = stats['width'], stats['height']
    def chunk(kind, payload):
        return struct.pack('>I', len(payload)) + kind + payload + struct.pack('>I', zlib.crc32(kind + payload))
    rows = b''.join(b'\0' + pixels[y*width*3:(y+1)*width*3] for y in range(height))
    with png.open('xb') as stream:
        stream.write(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)) +
                     chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))
    return dict(stats, png=str(png), ppm=str(ppm))


def run_display(remote, monitor, state, out, image):
    from boot_probe import stop_thread, forced_failure_registers
    import probe
    state.update(milestone='Q3-exploration', q3_verified=False, emulator_verified=False)
    frame = capture(monitor, out, 'pre-display-baseline')
    frame['lcd_scanout_active'] = False
    state['frames'] = [frame]
    state['q3_calls'] = []
    state['display_events'] = []
    adapter = SafeRemote(remote)
    watches = {0x104B1F58: 'native_widget_draw', 0x1046CDDC: 'native_gui_dispatch',
               0x10445CB8: 'native_gui_allocation', 0x102AEF88: 'gui_allocation_return',
               0x102AEF8C: 'gui_init_phase2_return', 0x102AEF90: 'gui_init_phase3_return',
               0x102AEFAA: 'gui_info_reset_return',
               0x100699CA: 'startup_check_service_return',
               0x100699D0: 'startup_check_environment_return',
               0x100699DA: 'startup_check_settings_return',
               0x10069A30: 'startup_checks_completed',
               0x10058AD0: 'app_state_bridge', 0x104A50B6: 'native_ui_state_notification',
               0x103864E0: 'native_text_widget_draw'}
    state['native_callbacks'] = {}
    for name in ('APPCTL', 'SYSCTL', 'SWSRV'):
        known = {'APPCTL': (0xC18183AC, 0x1005C98B), 'SYSCTL': (0xC2097F2C, 0x10059049),
                 'SWSRV': (0xC1F9941C, 0x101ED4FD)}
        object_address, known_callback = known[name]
        data = remote.memory(object_address, 64)
        callback = struct.unpack_from('<I', data, 0x2c)[0]
        state['native_callbacks'][name] = dict(object=hex(object_address), callback=hex(callback), bytes=data.hex())
        watches[known_callback & ~1] = name + '_callback'
    for task in state.get('tasks', []):
        if task.get('name') not in ('APPIDLE', 'APPMENU', 'APPPLAY', 'APPLV', 'APPMSG'): continue
        object_address = task['exinf']
        data = remote.memory(object_address, 64)
        callback = struct.unpack_from('<I', data, 0x2c)[0]
        if not (callback & 1 and 0x10020000 <= callback < 0x12120000):
            raise ValueError('unexpected native application task callback')
        state['native_callbacks'][task['name']] = dict(object=hex(object_address), callback=hex(callback), bytes=data.hex())
        watches[callback & ~1] = task['name'] + '_callback'
    # Opt-in, observation only: text widgets (class 4) are built by the native
    # constructor 0x1038692A with the text/element id already stored at +8.
    # Record only the error texts (0x27E "Press shutter release", 0x27F
    # "Initialization error", 0x280 "Turn camera off and then on") with LR and
    # the code-looking words on the stack, to locate who raises the error.
    ERROR_TEXTS = {0x27E, 0x27F, 0x280}
    if state.get('trace_error_producer'):
        watches[0x1038692A] = 'text_widget_construct'
        watches[0x1019971E] = 'message_send'     # native queue send (task object, message)
        watches[0x10329352] = 'info_item_build'  # shooting-screen item r0 (0..63), enabled by 10388234
        watches[0x10197556] = 'error_add'        # adds a code to the camera error list 0x1921
        watches[0x1009F0F4] = 'event_post'       # native event post (code, data); keep 0x0420xxxx
        watches[0x102032D8] = 'cseq_event'       # capture-sequence device event handler (code, data)
        # Device-status words: FUN_100f0a0a(status) turns bit 10 into error index 14
        # (code 0x44) and bit 5 into index 8 (code 0x3E).  The status is the OR of
        # the sub-calls below; break on each return address and keep r0.
        for address in SETTING_CORE:
            watches[address] = 'setting_core'          # slot ids 0x2F00/0x2F01 (or index 2641/2642) only
        watches[EXCEPTION_LOG_ACTION] = 'exception_log_action'
        watches[FLASH_PROGRAM_ENTRY] = 'flash_program_entry'
        watches[FLASH_TRANSACTION_ENTRY] = 'flash_transaction_entry'
        watches[CPU_EXCEPTION_ENTRY] = 'cpu_exception_entry'
        watches[CAPTURE_STATUS_SETTER] = 'capture_status_setter'
        for address in TG_CONTROL_WRITES:
            watches[address] = 'tg_control_write'
        for address in CSEQ_SENSOR_POINTS:
            watches[address] = 'cseq_sensor_step'
        for address in CAPTURE_INFO_POINTS:
            watches[address] = 'capture_info_snapshot'
        watches[0x100F0A0A] = 'status_report'
        for ret, callee in STATUS_RETURNS.items():
            watches[ret] = 'status_return'
        state['error_text_constructs'] = []
        state['error_text_construct_hits'] = 0
        state['message_sends'] = []
    if state.get('card_standin'):
        state['card_standin_records'] = []
        watches[CARD_MEDIA_STATUS] = 'card_media_status'
    if state.get('sensor_standin'):
        state['sensor_standin_records'] = []
        watches[SENSOR_ERROR_REPORT] = 'sensor_error_report'
    if state.get('sensor_calibration_standin'):
        watches[SENSOR_CALIBRATION_CHECK] = 'sensor_calibration_check'
    probe.TRACE_CALL = list(watches)
    probe.TRACE_REPEAT = set(watches)
    # Shared host budget for the whole display stage. Device models that log
    # every frame (RAW input) slow the guest, so the probe may raise it.
    deadline = time.monotonic() + state.get('display_budget_s', 30)

    def processing_failure(connection, regs):
        if len(state['hle_calls']) >= 8:
            raise RuntimeError('processing init repeatedly retried; stop instead of hiding the loop')
        if connection.command('G' + forced_failure_registers(regs, 6).hex()) != 'OK':
            raise RuntimeError('processing failure return rejected')
        state['hle_calls'].append(dict(kind='forced failure return; native body skipped',
            function='0x102E0B70', return_r0=6, before=regs, after=connection.registers(),
            reason='same Q2 processing-unit omission, triggered again by Q3 system report'))

    def observe(regs, thread=None):
        pc = int(regs['r15'], 16)
        if pc in CSEQ_SENSOR_POINTS and state.get('trace_error_producer'):
            if pc == 0x1005944E and int(regs['r6'], 16) != state.get('cseq_request_address'):
                return
            if pc == 0x1027AC32:
                address = int(regs['r0'], 16)
                if not 0xC0000000 <= address < 0xCD800000 or remote.memory(address, 1) != b'\x02':
                    return
            rows = state.setdefault('cseq_sensor_steps', [])
            if len(rows) < 256:
                row = dict(pc=hex(pc), thread=thread, ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0], registers=regs)
                if pc == 0x10121D6C:
                    table = struct.unpack('<I', remote.memory(0xC18E6490, 4))[0]
                    row['dispatch_table'] = hex(table)
                    receiver, receiver_context = struct.unpack('<2I', remote.memory(0xC18E64AC, 8))
                    row['dispatch_receiver'] = hex(receiver)
                    row['dispatch_context'] = hex(receiver_context)
                    if 0xC0000000 <= table <= 0xCD800000-0x20 or 0x10020000 <= table <= 0x12120000-0x20:
                        row['dispatch_entry'] = hex(struct.unpack('<I', remote.memory(table + 0x10, 4))[0])
                    address = int(regs['r0'], 16)
                    if 0xC0000000 <= address <= 0xCD800000-64:
                        row['arguments'] = remote.memory(address, 64).hex()
                if pc == 0x1027AD3E:
                    address = int(regs['r4'], 16)
                    if 0xC0000000 <= address <= 0xCD800000-6:
                        row['request_bytes'] = remote.memory(address, 6).hex()
                        state['cseq_request_address'] = address
                if pc == 0x1005944E:
                    address = int(regs['r0'], 16)
                    if 0xC0000000 <= address <= 0xCD800000-64:
                        row['transport_object'] = remote.memory(address, 64).hex()
                if pc == 0x1027AC32:
                    table = int(regs['r3'], 16)
                    if 0xC0000000 <= table <= 0xCD800000-36:
                        row['request_handler_row'] = remote.memory(table + 24, 12).hex()
                rows.append(row)
            return
        if pc in TG_CONTROL_WRITES and state.get('trace_error_producer'):
            rows = state.setdefault('tg_control_writes', [])
            if len(rows) < 256:
                rows.append(dict(pc=hex(pc), thread=thread, ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0], registers=regs))
            return
        if pc == SENSOR_CALIBRATION_CHECK and state.get('sensor_calibration_standin'):
            base = struct.unpack('<I', remote.memory(0xC18E62FC, 4))[0]
            if base != 0xC8500000: raise ValueError('unexpected sensor calibration block')
            address = base + 0xB8012
            records = state.setdefault('sensor_calibration_fixtures', [])
            value = remote.memory(address, 1)
            if value == b'\x00':
                checked_ram_fixture(remote, records, 'synthetic sensor calibration version', address, b'\x00', b'\x19')
            elif value != b'\x19' or not records:
                raise ValueError('unexpected sensor calibration byte')
            return
        if pc == CAPTURE_STATUS_SETTER and state.get('trace_error_producer'):
            records = state.setdefault('capture_status_setters', [])
            if len(records) < 256:
                records.append(dict(thread=thread, value=regs['r0'], other=regs['r1'], lr=regs['r14'],
                    ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]))
            return
        if pc in CAPTURE_INFO_POINTS and state.get('trace_error_producer'):
            state.setdefault('capture_info_snapshots', []).append(dict(pc=hex(pc), thread=thread,
                status=remote.memory(0xC18C8C68, 32).hex(), result=remote.memory(0xC25A3888, 16).hex(), registers=regs))
            if pc == CAPTURE_INFO_POINTS[0] and state.get('capture_status_standin'):
                apply_capture_status_standin(remote, state.setdefault('capture_status_fixtures', []))
            return
        if pc == CPU_EXCEPTION_ENTRY and state.get('trace_error_producer'):
            address = int(regs['r1'], 16)
            saved = struct.unpack('<17I', remote.memory(address, 68))
            state.setdefault('cpu_exceptions', []).append(dict(thread=thread, kind=regs['r0'],
                saved_address=hex(address), saved_registers=[hex(x) for x in saved], registers=regs))
            return
        if pc in (FLASH_WRITE, EXCEPTION_LOG_ACTION, FLASH_PROGRAM_ENTRY, FLASH_TRANSACTION_ENTRY) and state.get('trace_error_producer'):
            sp = int(regs['r13'], 16)
            words = struct.unpack('<128I', remote.memory(sp, 0x200))
            state.setdefault('flash_writes', []).append(dict(function=hex(pc), r0=regs['r0'], r1=regs['r1'], r2=regs['r2'],
                r3=regs['r3'], lr=regs['r14'], thread=thread,
                ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                stack_code=[hex(w) for w in words if w & 1 and 0x10020000 <= w < 0x12120000][:20]))
            return
        if state.get('card_standin') and pc == CARD_MEDIA_STATUS:
            records = state['card_standin_records']
            records.append(dict(kind='forced return; native body skipped', function=hex(pc),
                drive=regs['r0'], return_r0=CARD_NO_MEDIA, lr=regs['r14'], thread=thread,
                ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                reason='no SD host/card model; media status reported as absent'))
            if remote.command('G' + forced_failure_registers(regs, CARD_NO_MEDIA).hex()) != 'OK':
                raise RuntimeError('card media status stand-in rejected')
            if len(records) > 64:
                raise RuntimeError('card stand-in repeated; stop instead of hiding a loop')
            return
        if state.get('sensor_standin') and pc == SENSOR_ERROR_REPORT:
            report = int(regs['r0'], 16)
            body = remote.memory(report, 12)
            code = body[0]
            row = dict(kind='sensor error report', code=hex(code), report=body.hex(), lr=regs['r14'],
                       ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                       suppressed=sensor_error_suppressed(code, state.get('sensor_calibration_standin', False),
                                                          state.get('sensor_reply_standin', False),
                                                          state.get('expose_sensor_3f', False)))
            state['sensor_standin_records'].append(row)
            if row['suppressed']:
                if remote.command('G' + forced_failure_registers(regs, 0).hex()) != 'OK':
                    raise RuntimeError('sensor error report skip rejected')
                row['reason'] = 'no image-sensor model; device error report skipped (native body not run)'
            if len(state['sensor_standin_records']) > 64:
                raise RuntimeError('sensor stand-in repeated; stop instead of hiding a loop')
            return
        if pc in watches and watches[pc] == 'setting_core':
            if int(regs['r0'], 16) in (0x2F00, 0x2F01, 2641, 2642) and len(state.setdefault('card_slot_calls', [])) < 200:
                sp = int(regs['r13'], 16)
                state['card_slot_calls'].append(dict(function=hex(pc), r0=regs['r0'], r1=regs['r1'], r2=regs['r2'],
                    lr=regs['r14'], thread=thread, slot_state=remote.memory(CARD_SLOT_STATE, 8).hex(),
                    ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                    stack_code=[hex(w) for w in struct.unpack('<64I', remote.memory(sp, 0x100))
                                if w & 1 and 0x10020000 <= w < 0x12120000][:12]))
            return
        if pc in watches and watches[pc] in ('status_report', 'status_return'):
            rows = state.setdefault('device_status', [])
            if len(rows) < 400:
                rows.append(dict(kind=watches[pc], pc=hex(pc), callee=STATUS_RETURNS.get(pc),
                    r0=regs['r0'], lr=regs['r14'], thread=thread,
                    ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]))
            return
        if pc in watches and watches[pc] == 'event_post':
            code = int(regs['r0'], 16)
            if code >> 16 == 0x0420 and len(state.setdefault('event_posts', [])) < 200:
                data = int(regs['r1'], 16)
                body = remote.memory(data, 16).hex() if 0xC0000000 <= data < 0xCD800000 else None
                sp = int(regs['r13'], 16)
                words = struct.unpack('<128I', remote.memory(sp, 0x200))
                state['event_posts'].append(dict(code=hex(code), data=regs['r1'], body=body, lr=regs['r14'],
                    ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0], thread=thread,
                    stack_code=[hex(w) for w in words if w & 1 and 0x10020000 <= w < 0x12120000][:20]))
            return
        if pc in watches and watches[pc] == 'error_add':
            sp = int(regs['r13'], 16)
            words = struct.unpack('<128I', remote.memory(sp, 0x200))
            state.setdefault('error_adds', []).append(dict(
                r0=regs['r0'], r1=regs['r1'], r2=regs['r2'], r3=regs['r3'], lr=regs['r14'], thread=thread,
                ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                stack_code=[hex(w) for w in words if w & 1 and 0x10020000 <= w < 0x12120000][:20]))
            return
        if pc in watches and watches[pc] == 'info_item_build':
            items = state.setdefault('info_items_built', [])
            if len(items) < 300:
                items.append(dict(item=int(regs['r0'], 16), ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                                  lr=regs['r14']))
            return
        if pc in watches and watches[pc] == 'message_send':
            message = int(regs['r1'], 16)
            if 0xC0000000 <= message < 0xCD800000 and len(state['message_sends']) < 300:
                data = remote.memory(message, 0x30)
                sp = int(regs['r13'], 16)
                stack = remote.memory(sp, 0x100)
                state['message_sends'].append(dict(target=regs['r0'], code=data[0x10:0x14][::-1].hex(),
                    value=data[0x1c], lr=regs['r14'], ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                    stack_code=[hex(w) for w in struct.unpack('<64I', stack)
                                if w & 1 and 0x10020000 <= w < 0x12120000][:12]))
            return
        if pc in watches and watches[pc] == 'native_text_widget_draw' and state.get('trace_error_producer'):
            # Find which drawn text widget carries the "Error." string: scan its
            # pointer fields for UTF-16 text starting with "Error".
            widget = int(regs['r0'], 16)
            seen = state.setdefault('error_text_draws', [])
            if 0xC0000000 <= widget < 0xCD800000 and len(seen) < 20:
                body = remote.memory(widget, 0x120)
                for off in range(0, 0x120, 4):
                    ptr = struct.unpack_from('<I', body, off)[0]
                    if not (0xC0000000 <= ptr < 0xCD800000 or 0x10020000 <= ptr < 0x12120000): continue
                    try:
                        text = remote.memory(ptr, 12)
                    except Exception:
                        continue
                    if text == 'Error.'.encode('utf-16-le'):
                        seen.append(dict(widget=hex(widget), field=hex(off), text_ptr=hex(ptr),
                                         element=hex(struct.unpack_from('<I', body, 8)[0]),
                                         ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]))
                        break
        if pc in watches and watches[pc] == 'text_widget_construct':
            state['error_text_construct_hits'] += 1
            widget = int(regs['r0'], 16)
            if not 0xC0000000 <= widget < 0xCD800000: return
            element = struct.unpack('<I', remote.memory(widget + 8, 4))[0]
            sp = int(regs['r13'], 16)
            if len(state.setdefault('text_widget_constructs_all', [])) < 400:
                stack = remote.memory(sp, 0x100)
                state['text_widget_constructs_all'].append(dict(element=hex(element), lr=regs['r14'], widget=hex(widget),
                    ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                    stack_code=[hex(w) for w in struct.unpack('<64I', stack)
                                if w & 1 and 0x10020000 <= w < 0x12120000][:12]))
            if element not in ERROR_TEXTS: return
            stack = remote.memory(sp, 0x200)
            code = [hex(w) for w in struct.unpack('<128I', stack)
                    if w & 1 and 0x10020000 <= w < 0x12120000]
            state['error_text_constructs'].append(dict(element=hex(element), widget=hex(widget),
                thread=thread, lr=regs['r14'], sp=hex(sp), stack_code_words=code[:40], registers=regs,
                milliseconds=remote.memory(0xC18EB388, 4).hex()))
            return
        if pc in watches:
            row = dict(name=watches[pc], pc=hex(pc), thread=thread, registers=regs)
            if watches[pc].startswith('startup_check'):
                row['processing_initialized_word'] = remote.memory(0xC18015D8, 4).hex()
                row['app_startup_flags'] = remote.memory(0xC18183AC + 0x35c, 4).hex()
                row['interface_state'] = remote.memory(0xC1819004 + 0x104, 0x38).hex()
            if watches[pc] == 'gui_allocation_return':
                context = struct.unpack_from('<I', image, 0x10445DA0 - 0x10020000)[0]
                row['gui_context_address'] = hex(context)
                row['gui_context'] = remote.memory(context, 0x150).hex()
            if watches[pc] == 'APPCTL_callback':
                table = struct.unpack('<I', remote.memory(0xC18183AC + 0x154, 4))[0]
                row['app_state_table'] = hex(table)
                row['message'] = remote.memory(int(regs['r1'], 16), 68).hex()
                if 0x10020000 <= table < 0x12100000 or 0xC0000000 <= table < 0xCD800000:
                    row['state_table'] = remote.memory(table, 0x100).hex()
            elif state.get('q4_trace_active') and watches[pc].endswith('_callback'):
                pointer = int(regs['r1'], 16)
                if 0xC0000000 <= pointer < 0xCD800000:
                    row['message'] = remote.memory(pointer, 68).hex()
            if state.get('q4_trace_active'):
                row['guest_ms'] = struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]
                event = {k: row[k] for k in ('name', 'guest_ms', 'message') if k in row} | {'r0': regs['r0'], 'r1': regs['r1']}
                if watches[pc].startswith('trace_'):
                    event['registers'] = {k: regs[k] for k in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r14')}
                    stack = remote.memory(int(regs['r13'], 16), 0x100)
                    event['stack_code'] = [hex(w) for w in struct.unpack('<64I', stack)
                                           if w & 1 and 0x10020000 <= w < 0x12120000][:12]
                state['q4_trace'][-1]['events'].append(event)
                if len(state['q4_trace'][-1]['events']) >= (150 if state.get('q4_trace_pcs') else 40):
                    state['q4_trace_active'] = False      # bound the trace per press
                return
            state['display_events'].append(row)

    def call(name, function, payload, arguments, timeout=10):
        remote.sock.settimeout(timeout)
        packet = remote.command('?')
        row = dict(name=name, function=hex(function), completed=False)
        state['q3_calls'].append(row)
        try:
            result = probe.call_fixture(adapter, packet, function, payload, arguments,
                services={} if state.get('processing_init_standin') else {0x102E0B70: processing_failure},
                observers={pc: (lambda connection, regs: observe(regs)) for pc in watches})
        except Exception:
            row['incomplete_fixture'] = probe.ACTIVE_FIXTURE
            raise
        row.update(completed=True, result=result)
        print('Q3 native call completed: ' + name, flush=True)
        return result

    def read_card_settings(tag):
        values = dict(guest_ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0])
        for ident in sorted(CARD_SETTINGS):
            got = call(f'diagnostic_read_setting_{ident:04x}_{tag}', 0x10456098, bytes(4), [ident])
            values[hex(ident)] = got.get('return_r0')
        values['FUN_10442294'] = call(f'diagnostic_card_gate_10442294_{tag}', 0x10442294, bytes(4), []).get('return_r0')
        return values

    def run_to(address):
        remote.sock.settimeout(10)
        packet = remote.command('?')
        thread = stop_thread(packet)
        remote.command('Hg' + thread)
        if int(remote.registers()['r15'], 16) == address:
            reply = remote.command('vCont;s:' + thread)
            if stop_thread(reply) != thread: raise RuntimeError('wrong CPU stepped')
        points = set(watches) | {address}
        if not state.get('processing_init_standin'): points.add(0x102E0B70)
        for pc in points: remote.command(f'Z1,{pc:x},2')
        # Opt-in: write watchpoint on the shooting-screen status array whose first
        # byte item 10 shows ("Err" for codes 0x21/0x22). Record writer and value.
        # Armed only between screenshots output-03 and output-04 (the window in
        # which the error screen first appears); the array is cleared every
        # display cycle, so watching longer floods the stub.
        watch_status = (state.get('trace_error_producer') and state.get('status_watch_armed')
                        and len(state.setdefault('status_writes', [])) < 200)
        if watch_status and remote.command('Z2,c1822258,7') != 'OK':
            state['status_watch_unsupported'] = True
            watch_status = False
        while time.monotonic() < deadline:
            packet = remote.command('vCont;c')
            thread = stop_thread(packet)
            remote.command('Hg' + thread)
            regs = remote.registers()
            pc = int(regs['r15'], 16)
            if watch_status and 'watch:' in packet:
                array = remote.memory(0xC1822258, 7).hex()
                state['status_watch_stops'] = state.get('status_watch_stops', 0) + 1
                if array != state.get('status_last_array'):      # record changes only
                    state['status_last_array'] = array
                    sp = int(regs['r13'], 16)
                    stack = remote.memory(sp, 0x100)
                    state['status_writes'].append(dict(pc=hex(pc), lr=regs['r14'], array=array,
                        ms=struct.unpack('<I', remote.memory(0xC18EB388, 4))[0],
                        stack_code=[hex(w) for w in struct.unpack('<64I', stack)
                                    if w & 1 and 0x10020000 <= w < 0x12120000][:12]))
                if len(state['status_writes']) >= 200 or state['status_watch_stops'] >= 20000:
                    remote.command('z2,c1822258,7')
                    watch_status = False
                continue
            if pc == address and watch_status:
                remote.command('z2,c1822258,7')
            if pc not in points: raise RuntimeError(f'unexpected display stop {pc:#x}')
            if pc == 0x102E0B70:
                processing_failure(remote, regs)
                continue
            if pc == address:
                for point in points: remote.command(f'z1,{point:x},2')
                return packet
            observe(regs, thread)
            remote.command(f'z1,{pc:x},2')
            reply = remote.command('vCont;s:' + thread)
            if stop_thread(reply) != thread: raise RuntimeError('wrong CPU stepped')
            if len(state['display_events']) < 256: remote.command(f'Z1,{pc:x},2')
            else: points.remove(pc)
        raise TimeoutError('Q3 display execution budget exhausted')

    def capture_output(name):
        frame = capture(monitor, out, name)
        frame['lcd_scanout_active'] = 'Z5_LCD_SCANOUT frame=' in (out / 'qemu.log').read_text(errors='replace')
        frame['native_draw_seen'] = any(e['name'] in ('native_widget_draw', 'native_text_widget_draw')
                                        for e in state['display_events'])
        frame['q3_candidate'] = q3_accepted(frame, frame['native_draw_seen'], frame['lcd_scanout_active'])
        if state.get('trace_error_producer'):
            frame['guest_ms'] = struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]
            if name == 'output-03': state['status_watch_armed'] = True
            if name == 'output-04': state['status_watch_armed'] = False
        state['frames'].append(frame)

    configuration = call('native_image_pool_configuration', 0x10152DDC, bytes(12), [2, 0, ('scratch', 0)])
    payload = bytes.fromhex(configuration['output'])
    call('native_image_pool_init', 0x10141696, payload, [('scratch', 0)])
    run_to(0x100531BC)
    call('diagnostic_power_report', 0x10233F7C, bytes(72), [0x43090010, ('scratch', 0)])
    report = bytes.fromhex('000100000200000000000000000000000000000002000000000000000000000000000000')
    call('diagnostic_system_report', 0x10058D18, report, [0x03040002, ('scratch', 0)])
    run_to(0x102AF134)
    power = bytearray(remote.memory(0xC1F995C4, 0x34))
    struct.pack_into('<I', power, 0, struct.unpack_from('<I', power)[0] | 0x200)
    call('diagnostic_control_power_on', 0x101ED678, bytes(power), [('scratch', 0)])
    run_to(0x100531BC)
    if state.get('startup_environment_standin'):
        records = state.setdefault('startup_environment_fixtures', [])
        config = struct.unpack('<I', remote.memory(0xC1807E34, 4))[0]
        state['startup_threshold_pointer'] = hex(config)
        if not (0x10020000 <= config <= 0x12120000 - 0x44 or
                0xC0000000 <= config <= 0xCD8A0000 - 0x44):
            raise ValueError('unexpected startup threshold configuration pointer')
        threshold = struct.unpack('<h', remote.memory(config + 0x38, 2))[0]
        measurement = remote.memory(0xC1D4AB2A, 2)
        state['startup_measurement'] = dict(configuration=hex(config), threshold=threshold,
                                          original_measurement=measurement.hex())
        if threshold >= 32767: raise ValueError('cannot construct in-range startup measurement')
        checked_ram_fixture(remote, records, 'ADC0 above native startup minimum; synthetic measurement',
                            0xC1D4AB2A, measurement, struct.pack('<h', threshold + 1))
        thermal_limit = struct.unpack('<h', remote.memory(config + 0x2c, 2))[0]
        if thermal_limit <= -32768: raise ValueError('cannot construct in-range thermal measurement')
        state['startup_thermal_measurement'] = dict(threshold=thermal_limit,
            original_measurement=remote.memory(0xC1D4AB10, 2).hex())
        checked_ram_fixture(remote, records, 'temperature below native startup maximum; synthetic measurement',
                            0xC1D4AB10, remote.memory(0xC1D4AB10, 2), struct.pack('<h', thermal_limit - 1))
        checked_ram_fixture(remote, records, 'settings initialization fault flag; no persistent storage modeled',
                            0xC18A45F0, b'\x01\0\0\0', bytes(4))
    # C1.50 02000003 -> interface+18 (100699ae): completes the power report.
    # Unlike notification02000001, this sender copies the full word parameter.
    call('native_application_start_complete', 0x1005D3B4, bytes(8), [0xC18183AC, 0])
    run_to(0x100531BC)
    if state.get('application_ready_standin'):
        # C1.50 APPCTL group2 jump table: 04 -> caf0 (ready bit2),
        # 05 -> cb2e (ready bit1). Follow d138's pool-copy/send sequence.
        # Reports are synthetic; native task consumes them asynchronously.
        for event, value in ((0x02000004, 0), (0x02000005, 1)):
            message = bytearray(0x44)
            struct.pack_into('<I', message, 0x10, event)
            message[0x1c] = value
            allocated = call(f'diagnostic_readiness_{event:08x}_allocate', 0x1008C9D0,
                             bytes(message), [('scratch', 0)])
            pointer = int(allocated['return_r0'], 16)
            if not 0xC1800000 <= pointer <= 0xCD8A0000 - 0x44:
                raise ValueError('native application message allocation failed')
            call(f'diagnostic_readiness_{event:08x}_send', 0x1019971E, bytes(8), [0xC18183AC, pointer])
        run_to(0x100531BC)
    app_data = remote.memory(0xC18183AC, 0x3a0)
    state['app_sync_before_menu'] = dict(mode=app_data[0x158:0x15c].hex(),
        synchronization=[hex(x) for x in struct.unpack_from('<4I', app_data, 0x328)],
        callback=hex(struct.unpack_from('<I', app_data, 0x90)[0]))
    pending = struct.unpack_from('<4I', app_data, 0x328)
    state['startup_wait_overrides'] = []
    if pending[2] == 0x40 and pending[3] & 4:
        override = dict(kind='explicit startup readiness wait bypass', address='0xC18186DC',
                        index=2, expected_mask='0x40', before=state['app_sync_before_menu'],
                        reason='service bit6 has not completed in the emulator; display-only assistance')
        state['startup_wait_overrides'].append(override)
        call('explicit_service_bit6_wait_bypass', 0x1005C870, bytes(8), [0xC18183AC, 2, 0, 0x40])
        override['after'] = remote.memory(0xC18183AC + 0x328, 16).hex()
    state['app_settle'] = []
    for i in range(8):
        run_to(0x100531BC)
        data = remote.memory(0xC18183AC, 0x3a0)
        interface = struct.unpack_from('<I', data, 0x154)[0]
        state['app_settle'].append(dict(interface=hex(interface), mode=data[0x158:0x15c].hex(),
            synchronization=[hex(x) for x in struct.unpack_from('<4I', data, 0x328)]))
        if interface != 0xC1819004: break
    if struct.unpack_from('<I', data, 0x328)[0] == 2:
        override = dict(kind='explicit initial readiness wait bypass', address='0xC18186D4',
                        index=0, expected_mask='0x2', before=data[0x328:0x338].hex(),
                        reason='initial app readiness bit1 remains pending; display-only assistance')
        state['startup_wait_overrides'].append(override)
        call('explicit_service_bit1_wait_bypass', 0x1005C870, bytes(8), [0xC18183AC, 0, 0, 2])
        override['after'] = remote.memory(0xC18183AC + 0x328, 16).hex()
    # C1.50 AO table1072fe84 index67 = enabled/bank1/mask8000,
    # independently matched to ID_SW1_MENU at107375b8.
    keys = [0] * 8
    keys[2] = 1 << 3
    keys[4] = 100
    call('native_menu_key_for_display', 0x1059AE16, struct.pack('<8I', *keys),
         [('scratch', 0), 5, ('scratch', 20)])
    call('native_gui_refresh_request', 0x10467D3E, bytes(8), [])
    state['gui_event_injected'] = True
    for i in range(6):
        run_to(0x100531BC)
        capture_output(f'output-{i+1:02d}')
        if state.get('trace_error_producer') and i == 3:
            # Warning 0x22 ("Err", text 0x280) is raised when setting 0x1921 (the
            # camera error list, read with the native SettingDataService reader
            # 0x10234B30(id, buf, len)) holds a code in 0x3E..0x44. Read it.
            got = call('diagnostic_read_error_list_0x1921', 0x10234B30, bytes(0x118),
                       [0x1921, ('scratch', 0), 0x118])
            data = bytes.fromhex(got['output'])
            words = struct.unpack('<70I', data)
            state['error_list_0x1921'] = dict(return_r0=got.get('return_r0'), raw=data.hex(),
                                              count=words[0x110 // 4] if len(words) > 0x44 else None,
                                              entries=[hex(w) for w in words[:0x110 // 4] if w])
            # FUN_101401b6 returns 0x400 (-> code 0x44) unless the 12-bit id at
            # *(0xC18E62E4+0x18)+0xB8012 is >= 0x150, and 0x200 unless byte
            # +0xB8012 == 0x19. Record the base and the id bytes the emulator gives.
            base = struct.unpack('<I', remote.memory(0xC18E62E4 + 0x18, 4))[0]
            row = dict(base=hex(base), object=remote.memory(0xC18E62E4, 0x40).hex())
            try:
                row['id_bytes_b8010'] = remote.memory(base + 0xB8010, 8).hex()
            except Exception as exc:
                row['id_read_error'] = str(exc)
            state['device_id_check_101401b6'] = row
            # Card warnings 0x16..0x1B/0x20 (checks 0x10371916..0x10371a6c) read these
            # settings with hist_svc_a 0x10456098(id); 0x10442294() gates them too.
            state['card_settings'] = read_card_settings('04')
    # Heartbeat breakpoints prove ordering but can stop before the next
    # virtual LCD timer deadline. Allow bounded uninterrupted execution too.
    state['display_free_runs'] = []

    def free_run(name, seconds=.25, capture_frame=True):
        # Uninterrupted guest time, except that explicit stand-in breakpoints stay
        # armed: without them a stand-in would silently stop applying here (e.g.
        # leaving the menu restarts live view and the sensor path again).
        before = remote.memory(0xC18EB388, 4).hex()
        points = set()
        if state.get('sensor_standin'): points.add(SENSOR_ERROR_REPORT)
        if state.get('sensor_calibration_standin'): points.add(SENSOR_CALIBRATION_CHECK)
        if state.get('card_standin'): points.add(CARD_MEDIA_STATUS)
        if state.get('q4_trace_active'):
            points |= {pc for pc, n in watches.items() if n.startswith('trace_') or (
                       not state.get('q4_trace_pcs') and (n.endswith('_callback') or n == 'native_gui_dispatch'))}
        if state.get('trace_error_producer'): points |= {FLASH_WRITE, EXCEPTION_LOG_ACTION, FLASH_PROGRAM_ENTRY, FLASH_TRANSACTION_ENTRY, CPU_EXCEPTION_ENTRY, CAPTURE_STATUS_SETTER, *CAPTURE_INFO_POINTS, *TG_CONTROL_WRITES, *CSEQ_SENSOR_POINTS}
        for pc in points: remote.command(f'Z1,{pc:x},2')
        end, standin_stops = time.monotonic() + seconds, 0
        while True:
            remote.send('vCont;c')
            remote.sock.settimeout(max(end - time.monotonic(), 0.001))
            try:
                packet = remote.receive()
                interrupted = False
            except socket.timeout:
                remote.sock.settimeout(10)
                remote.sock.sendall(b'\x03')
                packet = remote.receive()
                interrupted = True
            remote.sock.settimeout(10)
            thread = stop_thread(packet)
            remote.command('Hg' + thread)
            regs = remote.registers()
            pc = int(regs['r15'], 16)
            if pc not in points:
                if not interrupted: raise RuntimeError(f'unexpected free-run stop {pc:#x}')
                break
            standin_stops += 1
            observe(regs, thread)
            remote.command(f'z1,{pc:x},2')
            reply = remote.command('vCont;s:' + thread)
            if stop_thread(reply) != thread: raise RuntimeError('wrong CPU stepped')
            remote.command(f'Z1,{pc:x},2')
            if interrupted: break
        for pc in points: remote.command(f'z1,{pc:x},2')
        state['display_free_runs'].append(dict(host_seconds=seconds, stop=packet,
            milliseconds_before=before, milliseconds_after=remote.memory(0xC18EB388, 4).hex(),
            registers=remote.registers(), frame=name, standin_stops=standin_stops))
        if capture_frame: capture_output(name)

    if state.get('keep_awake'):
        # Standby timer off through the native setting API (like Z6 setting 0x1021).
        # C1.50 1008D42C reads setting 0x1121 in normal shooting; enum 9 maps to
        # 0 seconds. 1008D790(mode) recomputes AppC state C1819254+0x10 from it.
        # Emulator session only; no flash save is modeled or claimed.
        run_to(0x100531BC)
        rec = dict(setting='0x1121', value=9, scope='standby timer; emulator session only',
                   mode_byte=remote.memory(STANDBY_STATE, 1).hex(),
                   seconds_field_before=struct.unpack('<I', remote.memory(STANDBY_STATE + 0x10, 4))[0])
        rec['before'] = call('keep_awake_read_before', SETTING_READ, bytes(4), [0x1121]).get('return_r0')
        rec['set'] = call('keep_awake_set_1121', SETTING_WRITE, bytes(4), [0x1121, 9]).get('return_r0')
        rec['after'] = call('keep_awake_read_after', SETTING_READ, bytes(4), [0x1121]).get('return_r0')
        call('keep_awake_recompute', STANDBY_RECOMPUTE, bytes(4), [int(rec['mode_byte'], 16)])
        rec['seconds_field_after'] = struct.unpack('<I', remote.memory(STANDBY_STATE + 0x10, 4))[0]
        state['keep_awake_record'] = rec
        if int(rec['after'], 16) != 9 or rec['seconds_field_after'] != 0:
            raise RuntimeError('standby timer setting did not take effect')
    for i in range(3):
        free_run(f'scanout-{i+1:02d}')
    if state.get('start_liveview_test'):
        # Z5 10599840 matches Z6 StartLV 10525A70 instruction structure;
        # acknowledgement is not proof of RAW, ISP, or LCD live view.
        # free_run pauses at an arbitrary instruction, possibly inside a locked
        # kernel critical section. Return to the same rendezvous used for Q4
        # before injecting a potentially blocking native call.
        deadline = time.monotonic() + 30
        run_to(0x100531BC)
        # Keep the essential stand-ins active, but avoid saturating the fixture's
        # shared trace limit with unrelated high-frequency UI/settings events.
        saved_watches = watches.copy()
        saved_trace, saved_repeat = probe.TRACE_CALL, probe.TRACE_REPEAT
        watches.clear()
        watches.update({pc: f'start_liveview_{pc:08x}' for pc in
                        (0x10219C3A, 0x10219C44, 0x10219C6E, 0x10599852, 0x10599858,
                         0x10599862, 0x10599868, 0x10599876, 0x1059989C, 0x105998AE)})
        for pc in (SENSOR_ERROR_REPORT, SENSOR_CALIBRATION_CHECK, CARD_MEDIA_STATUS,
                   CPU_EXCEPTION_ENTRY, CAPTURE_STATUS_SETTER, FLASH_WRITE, EXCEPTION_LOG_ACTION,
                   FLASH_PROGRAM_ENTRY, FLASH_TRANSACTION_ENTRY, *CAPTURE_INFO_POINTS):
            if pc in saved_watches:
                watches[pc] = saved_watches[pc]
        probe.TRACE_CALL = list(watches)
        probe.TRACE_REPEAT = {pc for pc in watches if not watches[pc].startswith('start_liveview_')}
        def start_timeout(_signum, _frame):
            raise TimeoutError('StartLV fixture wall-clock deadline exceeded')
        if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
            raise RuntimeError('StartLV fixture requires an unused real-time alarm')
        previous_handler = signal.signal(signal.SIGALRM, start_timeout)
        signal.setitimer(signal.ITIMER_REAL, 30)
        try:
            result = call('diagnostic_native_start_liveview', 0x10599840, bytes(32),
                          [('scratch', 0), 0, ('scratch', 16)], timeout=30)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            watches.clear()
            watches.update(saved_watches)
            probe.TRACE_CALL, probe.TRACE_REPEAT = saved_trace, saved_repeat
        state['start_liveview_result'] = result
        free_run('start-liveview-output')
    observe_ms = state.get('observe_guest_ms', 0)
    if observe_ms:
        start_ms = struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]
        end_time = time.monotonic() + 75
        while True:
            current_ms = struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]
            if (current_ms - start_ms) & 0xffffffff >= observe_ms: break
            if time.monotonic() >= end_time: raise TimeoutError('guest observation budget exhausted')
            free_run('extended-observation', capture_frame=False)
        state['guest_observation'] = dict(start_ms=start_ms, end_ms=current_ms,
                                         elapsed_ms=(current_ms-start_ms) & 0xffffffff)
        capture_output('extended-observation')
    if state.get('q4_keys'):
        # Q4: once the shooting screen is up (the early MENU press above lands
        # during startup), press native keys through the same AO entry
        # 0x1059AE16.  Press duration 10 (x10 virtual ms) as in the Z7 emulator.
        state['q4_presses'] = []
        for pc in state.get('q4_trace_pcs', []):   # opt-in breakpoints recorded only during traced presses
            watches[pc & ~1] = f'trace_{pc & ~1:08x}'
        deadline = time.monotonic() + 30 + 10 * len(state['q4_keys'])   # run_to budget for the presses
        for n, name in enumerate(state['q4_keys'], 1):
            run_to(0x100531BC)
            if state.get('q4_require_change'):
                capture_output(f'q4-{n:02d}-before')
            previous_hash = state['frames'][-1]['rgb_sha256']
            press = [0] * 8
            press[Q4_KEYS[name] // 32] = 1 << (Q4_KEYS[name] % 32)
            press[4] = 10
            ms = struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]
            if state.get('q4_trace_keys'):
                state.setdefault('q4_trace', []).append(dict(key=name, guest_ms=ms, events=[]))
                state['q4_trace_active'] = True
            call(f'q4_key_{n:02d}_{name}', 0x1059AE16, struct.pack('<8I', *press),
                 [('scratch', 0), 5, ('scratch', 20)])
            # Capture until two consecutive frames match (screen settled), at most 4;
            # single captures can land in a menu/shooting transition (blank frame).
            hashes = []
            for k in range(12 if state.get('q4_require_change') else 4):
                frame = f'q4-{n:02d}-{name}' + (f'-{k}' if k else '')
                free_run(frame, .5)
                hashes.append(state['frames'][-1]['rgb_sha256'])
                # a uniform (blank) frame is a transition, never a settled screen
                settled = q4_frame_settled(previous_hash, hashes, state['frames'][-1]['nonuniform'], state.get('q4_require_change', False))
                if settled: break
            state['q4_presses'].append(dict(key=name, ao_index=Q4_KEYS[name], guest_ms=ms, frame=frame,
                rgb_sha256=hashes[-1], prior_rgb_sha256=previous_hash, changed=hashes[-1] != previous_hash,
                settled=settled, captures=len(hashes)))
            state['q4_trace_active'] = False
            if state.get('q4_require_change') and not settled:
                raise RuntimeError(f'Q4 key {name} did not produce a changed, stable frame')
    for address, size in state.get('dump_ranges', []):
        # Opt-in diagnostic: guest RAM after the Q4 sequence (output/ only, never committed).
        (out / f'ram-{address:08x}-{size:x}.bin').write_bytes(remote.memory(address, size))
    if state.get('interactive_port'):
        # Interactive viewer: the page queues keys; this thread alone talks to
        # the guest (same AO entry and press duration as Q4) and publishes the
        # newest LCD screendump. Ends on the page's stop button or time limit.
        import interactive_view
        session = interactive_view.Session(state['interactive_port'], Q4_KEYS)
        session.start()
        print(f"INTERACTIVE_READY http://127.0.0.1:{state['interactive_port']}/", flush=True)
        presses = state['interactive_presses'] = []
        live = out / 'interactive-live.ppm'
        end = time.monotonic() + 60 * state.get('interactive_minutes', 30)
        reason = 'time limit'
        try:
            while True:
                if session.stopped:
                    reason = 'stopped from page'
                    break
                if time.monotonic() >= end:
                    break
                name = session.next_key()
                if name:
                    deadline = time.monotonic() + 30
                    run_to(0x100531BC)
                    press = [0] * 8
                    press[Q4_KEYS[name] // 32] = 1 << (Q4_KEYS[name] % 32)
                    press[4] = 10
                    ms = struct.unpack('<I', remote.memory(0xC18EB388, 4))[0]
                    call(f'ui_key_{len(presses) + 1:03d}_{name}', 0x1059AE16, struct.pack('<8I', *press),
                         [('scratch', 0), 5, ('scratch', 20)])
                    presses.append(dict(key=name, ao_index=Q4_KEYS[name], guest_ms=ms))
                    del state['q3_calls'][:-50]
                free_run('interactive', .2, capture_frame=False)
                del state['display_free_runs'][:-10]
                if live.exists(): live.unlink()
                monitor.command('screendump', {'filename': str(live)})
                png = interactive_view.ppm_to_png(live.read_bytes())
                session.publish(png, struct.unpack('<I', remote.memory(0xC18EB388, 4))[0], len(presses),
                                '取景底图：主机合成参考图' if state.get('lv_background') else '')
        finally:
            session.close()
            if live.exists(): live.unlink()
        state['interactive_end'] = reason
        capture_output('interactive-final')
    if state.get('trace_error_producer'):
        state['card_settings_after_scanout'] = read_card_settings('end')
    data = remote.memory(0xC18183AC, 0x3a0)
    state['app_after_menu'] = dict(interface=hex(struct.unpack_from('<I', data, 0x154)[0]),
        mode=data[0x158:0x15c].hex(), synchronization=[hex(x) for x in struct.unpack_from('<4I', data, 0x328)])
    state['display_registers'] = {}
    for bank in range(3):
        values = {}
        for offset in (0x110, 0x200, 0x204, 0x210, 0x220, 0x240, 0x250, 0x260, 0x1200, 0x2204):
            address = 0x20140000 + bank * 0x4000 + offset
            values[hex(offset)] = hex(struct.unpack('<I', remote.memory(address, 4))[0])
        state['display_registers'][str(bank)] = values
    text = (out / 'qemu.log').read_text(errors='replace')
    draw = any(e['name'] in ('native_widget_draw', 'native_text_widget_draw') for e in state['display_events'])
    scanout = 'Z5_LCD_SCANOUT frame=' in text
    candidates = [frame for frame in state['frames'] if frame.get('q3_candidate')]
    passed = bool(candidates)
    state['accepted_frame'] = candidates[-1]['png'] if candidates else None
    state['q3_scope'] = 'native LCD pixels with explicit startup assistance; normal startup and menu operation unverified'
    state.update(q3_verified=passed, emulator_verified=passed,
                 native_draw_verified=draw, lcd_scanout_verified=scanout)
    if passed: state.update(milestone='Q3')
    else: state['error'] = 'native widget pixels and LCD scanout have not both been observed'
    return passed
