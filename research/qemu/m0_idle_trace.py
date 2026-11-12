# SPDX-License-Identifier: GPL-2.0-or-later
"""Find evidence that a GUISRV wait occurred before a menu target route."""
import argparse
import json
from pathlib import Path


def wait_before_target(events, target):
    wait = None
    saw_previous_page = False
    for event in events:
        if event.get('name') == 'trace_10467bbe' and wait is None:
            wait = event.get('guest_ms')
        if event.get('name') != 'trace_1047897a':
            continue
        page = event.get('native_page') or {}
        if 'page_id' not in page or 'row' not in page:
            continue
        current = (page['page_id'], page['row'])
        if current == tuple(target):
            if wait is not None and saw_previous_page and event.get('guest_ms') is not None:
                return wait, event['guest_ms']
            return None
        saw_previous_page = True
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('result', type=Path)
    args = parser.parse_args()
    state = json.loads(args.result.read_text(encoding='utf-8'))
    evidence = []
    for trace, press in zip(state.get('q4_trace', []), state.get('q4_presses', [])):
        target = press.get('menu_expected')
        if trace.get('key') != press.get('key') or target is None or not press.get('menu_expected_met'):
            continue
        pair = wait_before_target(trace.get('events', []), target)
        if pair:
            evidence.append(dict(key=trace['key'], target=target, wait_guest_ms=pair[0],
                                 target_guest_ms=pair[1], elapsed_ms=(pair[1] - pair[0]) & 0xffffffff))
    print(json.dumps(dict(counterexamples=evidence, camera_verified=False,
                          scope='trace ordering only; not an idle detector'), indent=2))
    return 0 if evidence else 1


if __name__ == '__main__':
    raise SystemExit(main())
