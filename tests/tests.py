import unittest
from vt_eyre.cli import main
import sys

class TestCLI(unittest.TestCase):

    def test_help_display(self):
        sys.argv = ["cli.py"]
        main()  # Should print help, just check no crash

if __name__ == "__main__":
    unittest.main()
