from pathlib import Path
import sys
import unittest



TEST_DIR = Path(__file__).resolve().parent


def main():
    suite = unittest.defaultTestLoader.discover(
        str(TEST_DIR),
        pattern='test_*.py'
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    if result.wasSuccessful():
        return 0

    return 1


if __name__ == '__main__':
    sys.exit(main())

