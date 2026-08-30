import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from checkpoint_delta import build_deltas


def checkpoint(identifier, callbacks, loss=0, caller_count=0, admission=0, encoded=0):
    reasons = {"record_pool_exhausted": {"events": loss, "occurrences": loss}}
    return {"checkpoint_id": identifier, "label": f"m{identifier}",
        "snapshot_begin_qpc": identifier * 100, "snapshot_end_qpc": identifier * 100 + 3,
        "point_metrics": [{"generation": 7, "point": "bridge", "callbacks_observed": callbacks,
            "records_captured": 1, "records_store_attempted": 1, "records_encoded": 1,
            "filtered_by_plan": 0, "suppressed_by_retention_policy": max(0, callbacks - 1)}],
        "loss": [{"generation": 7, "point": "bridge", "events": loss, "reasons": reasons}],
        "retention": [{"generation": 7, "point": "bridge", "keys": [
            {"entry_return_address": 0x1234, "count": caller_count}]}],
        "storage": {"events_attempted": encoded, "events_encoded": encoded,
            "encoded_record_bytes": encoded * 10, "store_backpressure_events": 0,
            "sealed_chunks": 0, "sealed_raw_payload_bytes": 0, "sealed_file_bytes": 0,
            "manifest_flushes": identifier, "manifest_bytes": identifier * 10},
        "admission": {"drops": admission}, "unattributed_storage_loss_events": 0}


class CheckpointDeltaTests(unittest.TestCase):
    def test_lossless_caller_and_metric_delta(self):
        interval = build_deltas([checkpoint(1, 10, caller_count=10, encoded=1),
                                 checkpoint(2, 25, caller_count=25, encoded=2)],
                                manifest_complete=True)[0]
        point = interval["points"][0]
        self.assertEqual(point["counter_delta"]["callbacks_observed"], 15)
        self.assertEqual(point["caller_key_deltas"], [{"entry_return_address": 0x1234,
            "callbacks": 15, "lane": "unknown", "full_records_persisted": 0}])
        self.assertEqual(point["integrity"], "LOSSLESS_COUNTER_DELTA_BETWEEN_BOUNDED_SNAPSHOTS")
        self.assertEqual(interval["storage_delta"]["events_encoded"], 1)

    def test_any_integrity_gap_prevents_lossless_claim(self):
        interval = build_deltas([checkpoint(1, 10), checkpoint(2, 20, loss=2, admission=1)],
                                manifest_complete=True)[0]
        point = interval["points"][0]
        self.assertEqual(point["lost_events"], 2)
        self.assertEqual(point["loss_reason_delta"]["record_pool_exhausted"]["events"], 2)
        self.assertEqual(point["integrity"], "UNKNOWN_WITH_INTEGRITY_GAP")

    def test_non_monotonic_counter_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-monotonic"):
            build_deltas([checkpoint(1, 10), checkpoint(2, 9)], manifest_complete=True)

    def test_generation_without_prior_checkpoint_is_not_called_lossless(self):
        first, second = checkpoint(1, 0), checkpoint(2, 4)
        first["point_metrics"] = []
        first["loss"] = []
        first["retention"] = []
        point = build_deltas([first, second], manifest_complete=True)[0]["points"][0]
        self.assertFalse(point["baseline_checkpoint_contains_generation"])
        self.assertEqual(point["integrity"], "UNKNOWN_GENERATION_BASELINE_ABSENT")

    def test_invalid_or_backwards_qpc_intervals_are_rejected(self):
        for mutate in (
            lambda rows: rows[0].update(snapshot_end_qpc=99),
            lambda rows: rows[0].update(snapshot_begin_qpc=-1),
            lambda rows: rows[1].update(snapshot_begin_qpc=102),
            lambda rows: rows[1].update(snapshot_begin_qpc="200"),
        ):
            rows = [checkpoint(1, 10), checkpoint(2, 20)]
            mutate(rows)
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "QPC"):
                build_deltas(rows, manifest_complete=True)


if __name__ == "__main__":
    unittest.main()
