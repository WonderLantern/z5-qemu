"""不载入固件：校验 720×480 LCD 就绪门限、NV16 采样和帧完成中断。"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from boot_probe import ROOT, QMP, free_port
from q3_display import capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to((ROOT / 'output').resolve()):
        parser.error('--out must be a new shared output directory')
    out.mkdir(parents=True)
    build = json.loads((ROOT / 'reference/z5-qemu/.local/build-manifest.json').read_text())
    port, qmp = free_port(), free_port()
    command = [build['binary'], '-M', 'nikon-z5-display', '-accel', 'qtest', '-display', 'none',
               '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off',
               '-qmp', f'tcp:127.0.0.1:{qmp},server=on,wait=off']
    result = dict(scope='synthetic LCD test; no Nikon firmware executed', camera_verified=False,
                  binary_sha256=build['binary_sha256'], passed=False)
    with (out / 'qemu.log').open('x') as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
            env=dict(os.environ, Z5_MMIO_QUIET='1', Z5_LCD_SCANOUT_TEST='1'))
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    sock = socket.create_connection(('127.0.0.1', port), .2)
                    break
                except OSError:
                    if proc.poll() is not None or time.monotonic() > deadline: raise RuntimeError('QTest not ready')
                    time.sleep(.05)
            monitor = QMP(qmp)
            sock.settimeout(5)
            with sock, sock.makefile('rwb', buffering=0) as stream:
                def request(value):
                    stream.write(value.encode() + b'\n')
                    while True:
                        response = stream.readline().decode().strip()
                        if response.startswith('IRQ '): continue
                        if not response.startswith('OK'): raise RuntimeError(response)
                        return response.split()[1:]
                def write(offset, value): request(f'writel {0x20144000+offset:#x} {value:#x}')
                def status(): return int(request('readl 0x20145214')[0], 16)
                # Two full-height interleaved UV samples: black then white.
                # Rest of the RAM is zero; only these two pixels are asserted.
                request('write 0xc2000000 2 0x10eb')
                request('write 0xc2100000 2 0x8080')
                for off, value in ((0x200, 0x300100), (0x204, 480 << 16 | 720),
                                   (0x210, 0xC2000000), (0x220, 0xC2100000),
                                   (0x240, 720), (0x250, 720), (0x1200, 0x11)):
                    write(off, value)
                request('clock_step 100000000')
                if status() & 0x10000: raise AssertionError('frame completed with input disabled')
                write(0x110, 1)
                request('clock_step 100000000')
                if not status() & 0x10000: raise AssertionError('no frame completion after native LCD configuration')
                frame = capture(monitor, out, 'synthetic-lcd')
                pixels = (out / 'synthetic-lcd.ppm').read_bytes().split(b'\n', 3)[3]
                if (frame['width'], frame['height'], pixels[:6]) != (720, 480, b'\0\0\0\xff\xff\xff'):
                    raise AssertionError('LCD pixel coordinates or NV16 sampling differ')
                result['frame'] = frame
                # C1.50 native YYUV422A overlay format has bit4 set.
                request('write 0xc2200000 4 0xeb108080')
                request('write 0xc2300000 2 0xff00')
                for off, value in ((0x2110, 1), (0x2200, 0x30016), (0x2440, 0xC2200000),
                                   (0x2400, 1 << 16 | 2), (0x24c0, 0xC2300000),
                                   (0x2500, 4), (0x2540, 2), (0x25c0, 1)):
                    write(off, value)
                request('clock_step 100000000')
                result['overlay_frame'] = capture(monitor, out, 'synthetic-overlay')
                overlay = (out / 'synthetic-overlay.ppm').read_bytes().split(b'\n', 3)[3]
                if overlay[:6] != b'\xff' * 6:
                    raise AssertionError('native overlay format or opaque/transparent alpha differs')
                write(0x1214, 0x10000)
                if status() & 0x10000: raise AssertionError('frame completion W1C failed')
                write(0x110, 0)
                request('clock_step 100000000')
                if status() & 0x10000: raise AssertionError('disabled LCD generated a frame')
                # Unrecognized geometry remains rejected.
                write(0x204, 480 << 16 | 718)
                write(0x110, 1)
                request('clock_step 100000000')
                if status() & 0x10000: raise AssertionError('unsupported geometry generated a frame')
                result['passed'] = True
        except Exception as exc:
            result['error'] = f'{type(exc).__name__}: {exc}'
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    with (out / 'result.json').open('x') as report: json.dump(result, report, indent=2)
    print(json.dumps(result), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
