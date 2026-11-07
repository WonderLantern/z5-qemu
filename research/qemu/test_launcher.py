from pathlib import Path
import unittest
from launcher import build_command


class LauncherTest(unittest.TestCase):
    def test_commands_include_startup_fixtures_and_local_viewer(self):
        command = build_command(Path('/input/main.bi'), Path('/results/run'),
                                Path('/results/background.rgb'), 8765)
        self.assertIn('--sensor-standin', command)
        self.assertIn('--card-standin', command)
        self.assertIn('--keep-awake', command)
        self.assertEqual(command[command.index('--lv-background') + 1], str(Path('/results/background.rgb')))
        self.assertEqual(command[command.index('--interactive-port') + 1], '8765')

