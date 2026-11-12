# SPDX-License-Identifier: GPL-2.0-or-later
"""Check three bounded Simplified Chinese i-panel baseline result files."""
import argparse
from collections import Counter
import json
from pathlib import Path

EXPECTED_KEYS = ('i', 'right', 'ok', 'up', 'ok', 'ok', 'down', 'ok')
REQUIRED_STANDINS = ('processing_init_standin', 'startup_environment_standin',
                     'application_ready_standin', 'shooting_ui_standin', 'i_menu_settings_standin',
                     'zh_hans_standin', 'sensor_standin', 'card_standin')
EXPECTED_HASHES = (
    '1e71b9c8eed46af556898a3d1a0f47c01c873ba4522e79076ba066930d71376a',
    '8306708bfea00b7a13f47748ef649a1a92c9f215971f0dcbd9fca0d7cdf4a5c9',
    '3f8a00db7b1838af6c57086ca08e6deb2820f19e9977983f6910a07ef09b1855',
    'c631206e9348e81a0f769f0d61899f13571396126af0827137b7f18be8b6a81e',
    '6e7230eb57ed0caf19f788a6fa7164d1f5724c1fb1387b9d10a48b85c358aeb8',
    '53626cc6f024bdeaa08facc127cabac65ede2ae52d85160a9c4b22d9bce1351d',
    'ff8dcdc7010eb6e06b81bcbf992a136d64715d213cbc5744cc0ac6dc94d9376b',
    '8306708bfea00b7a13f47748ef649a1a92c9f215971f0dcbd9fca0d7cdf4a5c9')
MENU_EXPECTED_HASHES = (
    'c9e5b20110a4ed921ea903e21b07a46a582a401054b0c98fbd8e242fcf68efcd',
    '2736904bbba28a57ea47814420c6ba9138b3d06906b7efecad0b4a95c587924d',
    'dc511ec50764679005f3ba0ad075a20f76b69728bd745ab56fd7e1522a9181f1',
    'e34bbb4c027c7457a41d933b10acf8384e1e7d813cf2610fcd82d370d7144524',
    'fc39f97f976ebd5485aef028b7a7c1c66db27a328f0213c69809b1655a7638dc',
    '178d60627981b3f20c43359830410acb93addf0b2c9f29382b61b2a721e129b3')
CARD_FILES = {
    'A:\\Z5APP.BIN': 'b1e336f5f70255bf23e171219e37f2e3e22f62a8d685c7e04ba1ccac3b441dbd',
    'A:\\SHUTTER\\MENU.DAT': '8438b3fe0bb6767ec1cf7ebf7f46e6c7ecbbc36b9c2a22668dd2cbd5ea9d8f2b',
    'A:\\SHUTTER\\1.WAV': '69649ece764b1979108db1de924d5f98438ba88ee88c5f0b471c65f5e9045109',
}


def inherited_qemu_environment(environment):
    return {key: value if value in ('0', '1') else '<nonboolean>'
            for key, value in environment.items() if key.startswith(('Z5_', 'Z6_'))}


def observation_summary(state):
    reports = (Counter(r.get('code') for r in state['sensor_standin_records'] if r.get('code') != '0x0')
               if 'sensor_standin_records' in state else None)
    host_assists = [key for key in ('q3_startup_assist', 'lv_background', 'keep_awake', 'card_files', 'card_fail_opens',
                                    'early_settings', 'write_settings', 'liveview_hw_test', 'synthetic_calibration',
                                    'skip_processing_init', 'start_liveview_test', 'q4_mailbox_probe', 'mailbox_self_test')
                    if state.get(key)]
    host_assists += [r['name'] for r in state.get('q3_calls', []) if r.get('name') in
                     ('native_application_start_complete', 'native_menu_key_for_display', 'native_gui_refresh_request')]
    return dict(enabled_standins=sorted(k for k, v in state.items() if k.endswith('_standin') and v is True),
                host_assists=host_assists,
                host_guest_calls=sorted({r['name'] for r in state.get('q3_calls', []) if r.get('name')}),
                forced_returns=[{k: r[k] for k in ('function', 'return_r0') if k in r}
                                for r in state.get('hle_calls', [])],
                inherited_qemu_environment=state.get('inherited_qemu_environment'),
                sensor_error_reports=dict(reports) if reports is not None else None,
                run_error=state.get('error'), native_liveview_frames=None, autofocus_events=None,
                camera_verified=False, scope='observed sensor reports only; native LV/AF counters uninstrumented')


def unexpected_host_assistance(state):
    hardware = state.get('liveview_hw_test') or {}
    expected_hardware = {'Z5_LV_BACKGROUND': state['lv_background']} if state.get('lv_background') else {}
    return ((bool(hardware) and hardware != expected_hardware) or
            any(state.get(key) for key in ('card_files', 'card_fail_opens', 'early_settings', 'synthetic_calibration',
                                            'write_settings', 'start_liveview_test', 'q4_mailbox_probe',
                                            'mailbox_self_test', 'hle_calls')))


def summarize(state):
    presses = state.get('q4_presses', [])
    failures = []
    if unexpected_host_assistance(state):
        failures.append('unexpected host assistance or forced return')
    if (not state.get('q3_verified') or state.get('firmware_modified') is not False or
            state.get('firmware_sha256') != '1d9742a951ea8a8ebe695fa9bb1f29a3be73e16dfe4a8372d997e903bbc58e98'):
        failures.append('Q3 or original firmware check failed')
    if (state.get('startup_wait_standin') is not False or state.get('startup_wait_overrides') != [] or
            state.get('skip_processing_init') is not False or state.get('inherited_qemu_environment') != {}):
        failures.append('startup wait bypass active or unrecorded')
    active = {key for key, value in state.items() if key.endswith('_standin') and value is True}
    if (active != set(REQUIRED_STANDINS) or not state.get('lv_background') or
            state.get('keep_awake') is not True or state.get('q3_startup_assist') is not True):
        failures.append('required assisted UI baseline differs')
    if tuple(p.get('key') for p in presses) != EXPECTED_KEYS:
        failures.append('unexpected key sequence')
    if tuple(p.get('rgb_sha256') for p in presses) != EXPECTED_HASHES:
        failures.append('screen fingerprints differ')
    for item in presses:
        ui = item.get('ui_after', {})
        if (not item.get('visual_stable') or item.get('observation_guest_ms', 0) < 20000 or
                (ui.get('application'), ui.get('display_page'), ui.get('ui_mode')) != (3, 0, 3)):
            failures.append('unstable or unexpected UI state')
            break
    result = observation_summary(state)
    result.update(passed=not failures, failures=failures,
                  scope='assisted UI baseline; visual stability does not prove task idle')
    return result


def summarize_menu(state, minimum_guest_ms=20000):
    expected = ((18, 0), (1, 0), (1, 1), (1, 2), (248, 0), (248, 1))
    presses = state.get('q4_presses', [])
    failures = []
    if unexpected_host_assistance(state):
        failures.append('unexpected host assistance or forced return')
    if (not state.get('q3_verified') or state.get('firmware_modified') is not False or
            state.get('firmware_sha256') != '1d9742a951ea8a8ebe695fa9bb1f29a3be73e16dfe4a8372d997e903bbc58e98'):
        failures.append('Q3 or original firmware check failed')
    if (state.get('startup_wait_standin') is not False or state.get('startup_wait_overrides') != [] or
            state.get('skip_processing_init') is not False or state.get('inherited_qemu_environment') != {}):
        failures.append('startup wait bypass active or unrecorded')
    active = {key for key, value in state.items() if key.endswith('_standin') and value is True}
    if (active != set(REQUIRED_STANDINS) - {'i_menu_settings_standin'} or state.get('q3_startup_assist') is not True or
            state.get('lv_background') or state.get('keep_awake') is not True):
        failures.append('unexpected menu baseline assistance')
    if tuple(p.get('key') for p in presses) != ('menu', 'left', 'down', 'down', 'right', 'down'):
        failures.append('unexpected key sequence')
    for item, want in zip(presses, expected):
        snapshot = item.get('menu_after') or {}
        page = snapshot.get('page') or {}
        digest = item.get('rgb_sha256')
        if (tuple(item.get('menu_expected') or ()) != want or item.get('menu_expected_met') is not True or
                snapshot.get('status') != 'ok' or (page.get('page_id'), page.get('row')) != want or
                not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest) or
                item.get('visual_stable') is not True or item.get('observation_guest_ms', 0) < minimum_guest_ms):
            failures.append('menu page/row or observation mismatch')
            break
    result = observation_summary(state)
    result.update(passed=not failures, failures=failures,
                  screen_hashes=[p.get('rgb_sha256') for p in presses],
                  scope='assisted menu page/row gate; native task idle unverified')
    return result


def summarize_menu_frames(state):
    result = summarize_menu(state, minimum_guest_ms=0)
    presses = state.get('q4_presses', [])
    if (tuple(p.get('rgb_sha256') for p in presses) != MENU_EXPECTED_HASHES or
            tuple(p.get('frame_expected') for p in presses) != MENU_EXPECTED_HASHES or
            not all(p.get('frame_expected_met') is True for p in presses)):
        result['failures'].append('expected target fingerprints not satisfied')
    result['passed'] = not result['failures']
    result['scope'] = 'known menu page/row and fingerprint gate; native task idle unverified'
    return result


def summarize_interactive(state):
    failures = []
    presses = state.get('interactive_presses', [])
    targets = ((18, 0), (1, 0), (1, 1), (1, 2), (248, 0), (248, 1))
    if (not state.get('q3_verified') or state.get('firmware_modified') is not False or
            state.get('firmware_sha256') != '1d9742a951ea8a8ebe695fa9bb1f29a3be73e16dfe4a8372d997e903bbc58e98'):
        failures.append('Q3 or original firmware check failed')
    if (state.get('startup_wait_standin') is not False or state.get('startup_wait_overrides') != [] or
            state.get('skip_processing_init') is not False or state.get('inherited_qemu_environment') != {}):
        failures.append('startup wait bypass active or unrecorded')
    active = {key for key, value in state.items() if key.endswith('_standin') and value is True}
    if (active != set(REQUIRED_STANDINS) - {'i_menu_settings_standin'} or state.get('q3_startup_assist') is not True or
            state.get('lv_background') or state.get('keep_awake') is not True or unexpected_host_assistance(state)):
        failures.append('unexpected interactive assistance')
    if tuple(p.get('key') for p in presses) != ('menu', 'left', 'down', 'down', 'right', 'down'):
        failures.append('unexpected interactive key sequence')
    initial = state.get('interactive_initial_barrier') or {}
    if (initial.get('visual_barrier_passed') is not True or initial.get('native_idle_verified') is not False or
            initial.get('observation_guest_ms', 0) < 20000):
        failures.append('interactive initial barrier not satisfied')
    for item, want in zip(presses, targets):
        menu = item.get('menu_after') or {}
        page = menu.get('page') or {}
        if (item.get('visual_barrier_passed') is not True or item.get('native_idle_verified') is not False or
                item.get('observation_guest_ms', 0) < 20000 or menu.get('status') != 'ok' or
                (page.get('page_id'), page.get('row')) != want):
            failures.append('interactive barrier or page mismatch')
            break
    if not state.get('frames') or state['frames'][-1].get('rgb_sha256') != MENU_EXPECTED_HASHES[-1]:
        failures.append('interactive final fingerprint mismatch')
    result = observation_summary(state)
    result.update(passed=not failures, failures=failures,
                  scope='interactive visual and page barrier; native task idle unverified')
    return result


def summarize_card(state):
    failures = []
    def hex_is(value, expected):
        try:
            return isinstance(value, str) and int(value, 16) == expected
        except ValueError:
            return False
    presses = state.get('q4_presses', [])
    if (not state.get('q1_verified') or not state.get('q2_verified') or not state.get('q3_verified') or
            state.get('error') is not None or state.get('process_exit_code') != 0 or state.get('forced_host_kill') or
            state.get('firmware_modified') is not True or
            state.get('firmware_sha256') != 'e7e4ec5477a301f6128d30352429f2e6d31eaaa22f13255ceebf531215e24d61'):
        failures.append('Q3 or group 36 firmware check failed')
    if (state.get('startup_wait_standin') is not False or state.get('startup_wait_overrides') != [] or
            state.get('skip_processing_init') is not False or state.get('inherited_qemu_environment') != {}):
        failures.append('startup wait bypass active or unrecorded')
    active = {key for key, value in state.items() if key.endswith('_standin') and value is True}
    if (active != set(REQUIRED_STANDINS) - {'i_menu_settings_standin'} or state.get('q3_startup_assist') is not True or
            state.get('lv_background') or state.get('keep_awake') is not True or
            any(state.get(k) for k in ('card_fail_opens', 'write_settings', 'liveview_hw_test', 'synthetic_calibration',
                                       'start_liveview_test', 'q4_mailbox_probe', 'mailbox_self_test', 'hle_calls'))):
        failures.append('unexpected card baseline assistance')
    settings = state.get('setting_probe') or []
    language = state.get('zh_hans_fixture') or []
    if (state.get('early_settings') != [[0x1400, 26]] or len(settings) != 1 or
            settings[0].get('op') != 'early_write' or settings[0].get('key') != '0x1400' or
            settings[0].get('value') != 26 or settings[0].get('before') is None or
            not hex_is(settings[0].get('result'), 1) or not hex_is(settings[0].get('after'), 26) or
            len(language) != 1 or not hex_is(language[0].get('before'), 26) or
            language[0].get('setting') != 26 or language[0].get('resource_index') != 8):
        failures.append('early Simplified Chinese selection not verified')
    files = state.get('card_files') or {}
    if {path: value.get('sha256') for path, value in files.items()} != CARD_FILES:
        failures.append('card input fingerprints differ')
    if state.get('card_file_writes') != {'A:\\SHUTTER\\MENU.DAT': '5a35534d00010500'}:
        failures.append('card substitute write differs')
    if (state.get('trace_error_producer') is not True or state.get('cpu_exceptions') != [] or
            state.get('cpu_exception_coverage') != '0x10054680 from reset through Q3; other exception paths unverified'):
        failures.append('CPU exception trace missing or nonempty')
    if tuple(p.get('key') for p in presses) != ('menu', 'left', 'left', 'down', 'down', 'down', 'down', 'right', 'up', 'up', 'ok', 'ok'):
        failures.append('unexpected card key sequence')
    for item in presses:
        digest = item.get('rgb_sha256')
        if (item.get('visual_stable') is not True or item.get('observation_guest_ms', 0) < 20000 or
                not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest)):
            failures.append('card screen or observation mismatch')
            break
    result = observation_summary(state)
    result.update(passed=not failures, failures=failures,
                  screen_hashes=[p.get('rgb_sha256') for p in presses],
                  card_file_writes=state.get('card_file_writes'),
                  scope='group 36 firmware and simulator window-60 module; CPU hook coverage limited')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--menu', action='store_true', help='check the six-step native menu gate baseline')
    group.add_argument('--menu-frames', action='store_true', help='check the known page/row and frame target gate')
    group.add_argument('--interactive', action='store_true', help='check six-key interactive barrier baseline')
    group.add_argument('--card', action='store_true', help='check group 36 and simulator card-module baseline')
    parser.add_argument('results', type=Path, nargs=3)
    args = parser.parse_args()
    if len({p.resolve() for p in args.results}) != 3:
        parser.error('three distinct result files required')
    check = (summarize_card if args.card else summarize_interactive if args.interactive else summarize_menu_frames if args.menu_frames
             else summarize_menu if args.menu else summarize)
    results = [dict(path=str(p), **check(json.loads(p.read_text(encoding='utf-8')))) for p in args.results]
    if (args.menu or args.menu_frames or args.card) and len({tuple(r['screen_hashes']) for r in results}) != 1:
        for result in results:
            result['passed'] = False
            result['failures'].append('screen fingerprints differ between runs')
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0 if all(r['passed'] for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
