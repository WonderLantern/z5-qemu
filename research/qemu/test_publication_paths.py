import os
from pathlib import Path
import unittest
from unittest.mock import patch

from publication_paths import output_root, within_output


class PublicationPathsTest(unittest.TestCase):
    def test_output_root_can_be_configured(self):
        with patch.dict(os.environ, {'Z5_QEMU_OUTPUT': str(Path.cwd() / 'custom-results')}):
            self.assertEqual(output_root(), (Path.cwd() / 'custom-results').resolve())
            self.assertTrue(within_output(output_root() / 'run'))
            self.assertFalse(within_output(output_root().parent / 'custom-results-other' / 'run'))

    def test_default_is_project_output(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(output_root(), (Path(__file__).resolve().parents[2] / 'output').resolve())

