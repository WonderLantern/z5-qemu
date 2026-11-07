"""用自建数据检查实际 QEMU 的映射、启动寄存器、输入保护与未知访问停止。"""
import argparse
from publication_paths import output_root
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

from boot_probe import ROOT, free_port
from inspect_inputs import MAIN_SIZE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--processing-init-standin', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(output_root()):
        parser.error('--out must be a new shared output/ directory')
    build = json.loads((ROOT / 'reference/z5-qemu/.local/build-manifest.json').read_text())
    binary = build['binary']
    out.mkdir(parents=True)
    results = {}
    port = free_port()
    command = [binary, '-M', 'nikon-z5-display', '-accel', 'qtest', '-display', 'none',
               '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off']
    with (out / 'qtest.log').open('x') as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
            env=dict(os.environ, Z5_MMIO_QUIET='1', **({'Z5_PROCESSING_INIT_STANDIN': '1'}
                     if args.processing_init_standin else {})))
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    sock = socket.create_connection(('127.0.0.1', port), .2)
                    break
                except OSError:
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('QTest did not start')
                    time.sleep(.05)
            sock.settimeout(5)
            with sock, sock.makefile('rwb', buffering=0) as stream:
                def request(text):
                    stream.write(text.encode() + b'\n')
                    while True:
                        line = stream.readline().decode().strip()
                        if not line:
                            raise EOFError('QTest closed')
                        if line.startswith('IRQ '):
                            continue
                        if not line.startswith('OK'):
                            raise RuntimeError(line)
                        return line.split()[1:]

                def roundtrip(address, value):
                    request(f'writel {address:#x} {value:#x}')
                    actual = int(request(f'readl {address:#x}')[0], 16)
                    if actual != value:
                        raise AssertionError(f'{address:#x}: {actual:#x} != {value:#x}')

                try:
                    for i, address in enumerate([0x80800000, 0x82D13880, 0x8B0BC400,
                                                 0x8D917400, 0xBEFD4C00, 0xBFB00000, 0xFFEEF800,
                                                 0xC18F8120, 0xC86FFFFC, 0xC87680EC, 0xCC3FFFFC,
                                                 0xCC400000, 0xCC6FFFFC, 0xCCAFFffc,
                                                 0x80100000, 0x80300000, 0xBF300000,
                                                 0xC0000000, 0xC17FFFFC]):
                        roundtrip(address, 0x13570000 + i)
                    results['z5_ram_mapping'] = 'PASS'
                except Exception as exc:
                    results['z5_ram_mapping'] = str(exc)
                try:
                    for address, value in [(0x20016D50, 0x40000000), (0x20016D54, 0x80000000),
                                           (0x20016D58, 0x40000000), (0x20016D5C, 0xC0000000),
                                           (0x20016000, 1), (0x20016D40, 1), (0x04280044, 0x40),
                                           (0x2B200024, 0x10001), (0x2B20000C, 0x31111033),
                                           (0x2B200010, 0x10111), (0x2B200000, 4),
                                           (0x2B200004, 0x111), (0x2B200008, 0x1101),
                                           (0x2B20003C, 0x70010011), (0x2B20004C, 0x10001),
                                           (0x2B200050, 0x11111111), (0x2B200054, 0x10001),
                                           (0x2B200100, 0x100), (0x2B200300, 1),
                                           (0x2C012000, 0x57FF), (0x2C012008, 0x1CFF)]:
                        roundtrip(address, value)
                    results['early_register_latches'] = 'PASS'
                except Exception as exc:
                    results['early_register_latches'] = str(exc)
                if args.processing_init_standin:
                    try:
                        roundtrip(0x2A900004, 0x147)
                        request('writel 0x2b200000 4')
                        if int(request('readl 0x2b200058')[0], 16) != 0:
                            raise AssertionError('ready before configuration')
                        request('writel 0x2a9008bc 1')
                        if int(request('readl 0x2b200058')[0], 16) != 0:
                            raise AssertionError('ready while configuration active')
                        request('writel 0x2a9008bc 0')
                        if int(request('readl 0x2b200058')[0], 16) != 0x110000:
                            raise AssertionError('missing diagnostic ready after configuration')
                        request('writel 0x2b200000 0')
                        if int(request('readl 0x2b200058')[0], 16) != 0:
                            raise AssertionError('ready with command disabled')
                        results['processing_init_standin'] = 'PASS'
                    except Exception as exc:
                        results['processing_init_standin'] = str(exc)
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    # 自建 ARM 程序：默认关闭诊断设备，开启后也不能放行未知寄存器。
    for name, address, standin in [('unknown_guest_access_stops', 0x60000000, False),
                                   ('processing_standin_disabled_by_default', 0x2A900004, False),
                                   ('processing_standin_unknown_register_stops', 0x2A900028, True)]:
        fixture = out / ('owned-' + name + '.bin')
        with fixture.open('xb') as f:
            f.write(struct.pack('<4I', 0xE59F0004, 0xE5901000, 0xEAFFFFFE, address))
        command = [binary, '-M', 'nikon-z5-display', '-smp', '2', '-display', 'none', '-nic', 'none',
                   '-device', f'loader,file={fixture},addr=0xc1800000,cpu-num=0,force-raw=on',
                   '-device', 'loader,addr=0xc1800008,cpu-num=1']
        environment = dict(os.environ)
        environment.pop('Z5_PROCESSING_INIT_STANDIN', None)
        if standin: environment['Z5_PROCESSING_INIT_STANDIN'] = '1'
        p = subprocess.run(command, capture_output=True, text=True, timeout=15, env=environment)
        with (out / (name + '.log')).open('x') as f:
            f.write(p.stdout + p.stderr)
        results[name] = ('PASS' if p.returncode == 2 and
            f'Z5_LAB_UNMODELED read addr=0x{address:08x}' in p.stderr else f'FAIL exit={p.returncode}')
    for name, size, message in [('bad-length', 16, 'Expected extracted Z5'),
                                ('bad-hash', MAIN_SIZE, 'SHA-256 mismatch')]:
        fixture = out / (name + '.bin')
        with fixture.open('xb') as f:
            f.truncate(size)
        p = subprocess.run([binary, '-M', 'nikon-z5-display', '-S', '-display', 'none',
                            '-bios', str(fixture)], capture_output=True, text=True, timeout=15)
        with (out / (name + '.log')).open('x') as f:
            f.write(p.stdout + p.stderr)
        results[name + '_rejected'] = 'PASS' if p.returncode != 0 and message in p.stderr else f'FAIL exit={p.returncode}'
    with (out / 'result.json').open('x') as f:
        json.dump(dict(scope='synthetic QEMU checks; no Nikon code executed', camera_verified=False,
                       binary_sha256=build['binary_sha256'], results=results), f, indent=2)
    print(json.dumps(results, indent=2), flush=True)
    return 0 if all(v == 'PASS' for v in results.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
