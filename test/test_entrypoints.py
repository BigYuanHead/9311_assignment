from pathlib import Path
import subprocess
import sys
import unittest

from dns_test_utils import BASE_DIR, RESOURCE_DIR



class parserEntrypointTest_C(unittest.TestCase):

    def test_parser_uses_supplied_command_line_file(self):
        filename = RESOURCE_DIR / 'unsw.edu.au-A-44325-query.bin'

        result = subprocess.run(
            [
                sys.executable,
                str(BASE_DIR / 'parser.py'),
                str(filename)
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=5
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, '')
        self.assertIn('ID: 44325', result.stdout)
        self.assertIn('unsw.edu.au. IN A', result.stdout)
        self.assertNotIn('[DEBUG]', result.stdout)
        self.assertNotIn('[INFO]', result.stdout)


if __name__ == '__main__':
    unittest.main()

