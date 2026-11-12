import json
import unittest
import urllib.error
import urllib.request

import interactive_view as view


class InteractiveViewTest(unittest.TestCase):
    def test_synthetic_i_settings_are_visible_in_session_status(self):
        self.assertIn('模拟值', view.session_message(True, True))
        self.assertNotIn('模拟值', view.session_message(True, False))
        self.assertIn('简体中文', view.session_message(True, True, True))

    def test_ppm_with_whitespace_pixel_bytes(self):
        pixels = bytes([0x0a, 0x20, 0x09, 1, 2, 3])
        png = view.ppm_to_png(b'P6\n2 1\n255\n' + pixels)
        self.assertTrue(png.startswith(b'\x89PNG'))

    def test_rejects_short_ppm(self):
        with self.assertRaises(ValueError):
            view.ppm_to_png(b'P6\n2 2\n255\n\0\0\0')

    def test_key_queue_and_status(self):
        session = view.Session(0, ['menu', 'ok'])
        session.start()
        try:
            base = f'http://127.0.0.1:{session.server.server_address[1]}/'
            urllib.request.urlopen(urllib.request.Request(base + 'key?name=menu', method='POST'))
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(urllib.request.Request(base + 'key?name=shutter', method='POST'))
            self.assertEqual(session.next_key(), 'menu')
            self.assertIsNone(session.next_key())
            session.publish(b'png', 1234, 1)
            status = json.loads(urllib.request.urlopen(base + 'status.json').read())
            self.assertEqual((status['frame'], status['guest_ms'], status['presses']), (1, 1234, 1))
        finally:
            session.close()


if __name__ == '__main__':
    unittest.main()
