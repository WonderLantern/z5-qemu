# SPDX-License-Identifier: GPL-2.0-or-later
"""用自建 ARM 循环核对：单步指定核时，另一核的寄存器必须保持不变。"""
import argparse
from publication_paths import output_root
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

from boot_probe import ROOT, free_port, limit_qemu_resources, stop_thread


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--legacy', action='store_true', help='负向对照：旧 Hc/s 命令')
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(output_root()):
        parser.error('--out must be a new shared output/ directory')
    project = ROOT / 'reference/z5-qemu'
    build = json.loads((project / '.local/build-manifest.json').read_text())
    if hashlib.sha256(Path(build['binary']).read_bytes()).hexdigest() != build['binary_sha256']:
        parser.error('QEMU binary differs from manifest')
    sys.path.insert(0, str(project / 'tools'))
    from rsp import Remote
    out.mkdir(parents=True)
    fixture = out / 'owned-step-loop.bin'
    fixture.write_bytes(struct.pack('<3I', 0xE3A00000, 0xE2800001, 0xEAFFFFFD))
    port = free_port()
    command = [build['binary'], '-M', 'nikon-z5-display', '-smp', '2', '-display', 'none',
        '-nic', 'none', '-serial', 'none', '-S', '-gdb', f'tcp:127.0.0.1:{port}',
        '-accel', 'tcg,thread=single', '-icount', 'shift=6,align=off,sleep=off',
        '-device', f'loader,file={fixture},addr=0xc1800000,cpu-num=0,force-raw=on',
        '-device', 'loader,addr=0xc1800000,cpu-num=1']
    state = dict(passed=False, camera_verified=False, scope='owned ARM loop; no Nikon code',
                 mode='legacy Hc/s' if args.legacy else 'vCont per-thread step', trace=[])
    with (out / 'qemu.log').open('x') as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                preexec_fn=limit_qemu_resources)
        try:
            remote = Remote(port)
            remote.command('qSupported:multiprocess+;xmlRegisters=arm')
            remote.command('qXfer:features:read:target.xml:0,fff')
            threads = []
            packet = remote.command('qfThreadInfo')
            while packet.startswith('m'):
                threads.extend(packet[1:].split(','))
                packet = remote.command('qsThreadInfo')
            if len(threads) != 2:
                raise RuntimeError(f'expected two guest CPUs: {threads}')
            def registers(thread):
                remote.command('Hg' + thread)
                return remote.registers()
            for i in range(12):
                selected, other = threads[i % 2], threads[1 - i % 2]
                before = registers(other)
                if args.legacy:
                    remote.command('Hc' + selected)
                    reply = remote.command('s')
                    remote.command('Hc-1')
                else:
                    reply = remote.command('vCont;s:' + selected)
                after = registers(other)
                row = dict(selected=selected, stopped=stop_thread(reply),
                           other=other, before=before, after=after)
                state['trace'].append(row)
                if row['stopped'] != selected or before != after:
                    raise AssertionError('unselected CPU ran during the requested single step')
            state['passed'] = True
        except Exception as exc:
            state['error'] = f'{type(exc).__name__}: {exc}'
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    (out / 'result.json').write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps({k: v for k, v in state.items() if k != 'trace'}))
    return 0 if state['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
