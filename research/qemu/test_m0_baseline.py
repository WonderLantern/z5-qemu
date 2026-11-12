import unittest
from m0_baseline import summarize, summarize_menu, summarize_menu_frames, summarize_interactive, summarize_card, observation_summary, inherited_qemu_environment, EXPECTED_KEYS, EXPECTED_HASHES, REQUIRED_STANDINS, MENU_EXPECTED_HASHES, CARD_FILES


class BaselineTest(unittest.TestCase):
    def test_inherited_qemu_environment_is_visible_without_revealing_paths(self):
        env = {'Z5_TG_PERIODIC_TEST': '1', 'Z6_GPU_ICON_DUMP_DIR': '/private/path', 'OTHER': 'secret'}
        self.assertEqual(inherited_qemu_environment(env),
                         {'Z5_TG_PERIODIC_TEST': '1', 'Z6_GPU_ICON_DUMP_DIR': '<nonboolean>'})
    def sample(self):
        return dict(**{name: True for name in REQUIRED_STANDINS}, lv_background='fixture.rgb', keep_awake=True,
                    q3_verified=True, firmware_modified=False, startup_wait_standin=False, q3_startup_assist=True,
                    skip_processing_init=False, inherited_qemu_environment={},
                    firmware_sha256='1d9742a951ea8a8ebe695fa9bb1f29a3be73e16dfe4a8372d997e903bbc58e98',
                    startup_wait_overrides=[], sensor_standin_records=[{'code': '0x44', 'suppressed': True}],
                    q4_presses=[dict(key=k, rgb_sha256=h, visual_stable=True, observation_guest_ms=20000,
                                     ui_after={'application': 3, 'display_page': 0, 'ui_mode': 3})
                                for k, h in zip(EXPECTED_KEYS, EXPECTED_HASHES)])

    def test_good_run_and_unobserved_counts(self):
        result = summarize(self.sample())
        self.assertTrue(result['passed'])
        self.assertEqual(result['sensor_error_reports'], {'0x44': 1})
        self.assertIsNone(result['native_liveview_frames'])
        self.assertIsNone(result['autofocus_events'])
        self.assertIn('lv_background', result['host_assists'])
        self.assertEqual(observation_summary(self.sample())['sensor_error_reports'], {'0x44': 1})
        self.assertIsNone(observation_summary({})['sensor_error_reports'])
        extra = self.sample()
        extra['liveview_hw_test'] = {'Z5_TG_PERIODIC_TEST': '1'}
        extra['hle_calls'] = [{'function': '0x102E0B70', 'return_r0': 6}]
        self.assertIn('liveview_hw_test', observation_summary(extra)['host_assists'])
        self.assertEqual(observation_summary(extra)['forced_returns'], [{'function': '0x102E0B70', 'return_r0': 6}])

    def test_rejects_bypass_changed_screen_or_missing_frame(self):
        for change in ('bypass', 'screen', 'missing', 'firmware', 'standin', 'extra', 'implicit', 'environment'):
            state = self.sample()
            if change == 'bypass': state['startup_wait_overrides'] = [{}]
            if change == 'screen': state['q4_presses'][4]['rgb_sha256'] = 'bad'
            if change == 'missing': state['q4_presses'].pop()
            if change == 'firmware': state['firmware_sha256'] = 'bad'
            if change == 'standin': state[REQUIRED_STANDINS[0]] = False
            if change == 'extra': state['sensor_reply_standin'] = True
            if change == 'implicit': state['q3_startup_assist'] = False
            if change == 'environment': state['inherited_qemu_environment'] = {'Z5_TG_PERIODIC_TEST': '1'}
            self.assertFalse(summarize(state)['passed'])

    def test_menu_baseline_requires_expected_page_and_row(self):
        state = self.sample()
        state['i_menu_settings_standin'] = False
        state['lv_background'] = None
        expected = [(18, 0), (1, 0), (1, 1), (1, 2), (248, 0), (248, 1)]
        state['q4_presses'] = [dict(key=k, rgb_sha256=f'{i:064x}', visual_stable=True,
                                    observation_guest_ms=20000, menu_expected=list(e),
                                    menu_expected_met=True, menu_after={'status': 'ok',
                                        'page': {'page_id': e[0], 'row': e[1]}})
                               for i, (k, e) in enumerate(zip(('menu', 'left', 'down', 'down', 'right', 'down'), expected))]
        self.assertTrue(summarize_menu(state)['passed'])
        digest = state['q4_presses'][2].pop('rgb_sha256')
        self.assertFalse(summarize_menu(state)['passed'])
        state['q4_presses'][2]['rgb_sha256'] = digest
        state['q4_presses'][2]['menu_after']['page']['row'] = 4
        self.assertFalse(summarize_menu(state)['passed'])

    def test_menu_baseline_rejects_an_extra_standin(self):
        state = self.sample()
        state['sensor_reply_standin'] = True
        self.assertIn('unexpected menu baseline assistance', summarize_menu(state)['failures'])

    def test_menu_frame_gate_requires_the_exact_expected_fingerprints(self):
        state = self.sample()
        state['i_menu_settings_standin'] = False
        state['lv_background'] = None
        expected = [(18, 0), (1, 0), (1, 1), (1, 2), (248, 0), (248, 1)]
        state['q4_presses'] = [dict(key=k, rgb_sha256=h, frame_expected=h, frame_expected_met=True,
                                    visual_stable=True, observation_guest_ms=1000, menu_expected=list(e),
                                    menu_expected_met=True, menu_after={'status': 'ok',
                                        'page': {'page_id': e[0], 'row': e[1]}})
                               for k, e, h in zip(('menu', 'left', 'down', 'down', 'right', 'down'), expected, MENU_EXPECTED_HASHES)]
        self.assertTrue(summarize_menu_frames(state)['passed'])
        state['q4_presses'][0]['frame_expected'] = '0' * 64
        self.assertFalse(summarize_menu_frames(state)['passed'])

    def test_interactive_requires_each_page_and_completed_barrier(self):
        state = self.sample()
        state['i_menu_settings_standin'] = False
        state['lv_background'] = None
        expected = [(18, 0), (1, 0), (1, 1), (1, 2), (248, 0), (248, 1)]
        state['interactive_presses'] = [dict(key=k, visual_barrier_passed=True, native_idle_verified=False, observation_guest_ms=20000,
            menu_after={'status': 'ok', 'page': {'page_id': page, 'row': row}})
            for k, (page, row) in zip(('menu', 'left', 'down', 'down', 'right', 'down'), expected)]
        state['frames'] = [{'rgb_sha256': MENU_EXPECTED_HASHES[-1]}]
        state['interactive_initial_barrier'] = {'visual_barrier_passed': True, 'observation_guest_ms': 20000,
                                                'native_idle_verified': False}
        self.assertTrue(summarize_interactive(state)['passed'])
        state['interactive_presses'][2]['visual_barrier_passed'] = False
        self.assertFalse(summarize_interactive(state)['passed'])
        state['interactive_presses'][2]['visual_barrier_passed'] = True
        state['interactive_initial_barrier']['visual_barrier_passed'] = False
        self.assertFalse(summarize_interactive(state)['passed'])

    def test_card_baseline_requires_inputs_writes_and_exception_trace(self):
        state = self.sample()
        state['i_menu_settings_standin'] = False
        state['lv_background'] = None
        state['firmware_modified'] = True
        state['q1_verified'] = True
        state['q2_verified'] = True
        state['process_exit_code'] = 0
        state['firmware_sha256'] = 'e7e4ec5477a301f6128d30352429f2e6d31eaaa22f13255ceebf531215e24d61'
        state['card_files'] = {path: {'sha256': digest} for path, digest in CARD_FILES.items()}
        state['card_file_writes'] = {'A:\\SHUTTER\\MENU.DAT': '5a35534d00010500'}
        state['trace_error_producer'] = True
        state['early_settings'] = [[0x1400, 26]]
        state['setting_probe'] = [dict(op='early_write', key='0x1400', value=26,
                                       before='0x00000003', result='0x00000001', after='0x0000001a')]
        state['zh_hans_fixture'] = [dict(before='0x0000001a', setting=26, resource_index=8)]
        state['cpu_exception_coverage'] = '0x10054680 from reset through Q3; other exception paths unverified'
        state['cpu_exceptions'] = []
        keys = ('menu', 'left', 'left', 'down', 'down', 'down', 'down', 'right', 'up', 'up', 'ok', 'ok')
        state['q4_presses'] = [dict(key=k, rgb_sha256=f'{i:064x}', visual_stable=True,
                                    observation_guest_ms=20000) for i, k in enumerate(keys)]
        self.assertTrue(summarize_card(state)['passed'])
        state['error'] = 'late error'
        self.assertFalse(summarize_card(state)['passed'])
        del state['error']
        state['early_settings'] = []
        self.assertFalse(summarize_card(state)['passed'])
        state['early_settings'] = [[0x1400, 26]]
        state['setting_probe'][0]['result'] = None
        self.assertFalse(summarize_card(state)['passed'])
        state['setting_probe'][0]['result'] = '0x00000001'
        state['cpu_exceptions'] = [{'phase': 'boot'}]
        self.assertFalse(summarize_card(state)['passed'])
        state['cpu_exceptions'] = []
        state['card_file_writes'] = {}
        self.assertFalse(summarize_card(state)['passed'])

    def test_baselines_reject_unexpected_host_assistance(self):
        for field, value in (('card_files', ['fixture']), ('synthetic_calibration', '/tmp/profile'), ('liveview_hw_test', {'tg': True}), ('q4_mailbox_probe', True), ('mailbox_self_test', True),
                             ('hle_calls', [{'function': '0x102e0b70', 'return_r0': 6}])):
            for check in (summarize, summarize_menu):
                state = self.sample()
                state[field] = value
                self.assertIn('unexpected host assistance or forced return', check(state)['failures'])
