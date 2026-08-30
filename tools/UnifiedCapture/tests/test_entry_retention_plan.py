from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from entry_retention_plan import derive


class RetentionDerivationTests(unittest.TestCase):
    def test_invalid_capacity_is_rejected_before_io(self):
        with self.assertRaisesRegex(ValueError, "power of two"):
            derive(Path("missing-plan"), Path("missing-summary"), Path("missing-output"), 3)


if __name__ == "__main__":
    unittest.main()
