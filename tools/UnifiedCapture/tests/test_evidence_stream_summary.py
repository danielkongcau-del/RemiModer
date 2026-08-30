from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence_stream_summary import classify


class StreamingSummaryTests(unittest.TestCase):
    def test_classification_preserves_loss_uncertainty(self):
        self.assertEqual(classify(4, 3, True, [1, 2], True),
                         "OBSERVED_WITH_INCOMPLETE_STREAM")
        self.assertEqual(classify(0, 3, True, [1, 2], True), "UNKNOWN")
        self.assertEqual(classify(0, 0, True, [1, 2], True),
                         "NOT_OBSERVED_IN_COVERED_WINDOW")
        self.assertEqual(classify(1, 0, True, [1, 2], True), "OBSERVED")
        self.assertEqual(classify(1, 0, False, [1, 2], True), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
