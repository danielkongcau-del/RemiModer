"""Exercise asynchronous multi-chunk sealing in an owned process only."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import uuid

from native_integration import ROOT, records
from uc.store import inspect_session


def main():
    root = ROOT / "test-output" / ("native-store-async-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    completed = subprocess.run([str(ROOT / "build/StoreProbe.exe"), str(root)],
                               check=True, capture_output=True, text=True, encoding="utf-8")
    result = json.loads(completed.stdout)
    directory = Path(result["directory"])
    inspection = inspect_session(directory)
    chunk_ids = [chunk["chunk_id"] for chunk in inspection["chunks"]]
    if not inspection["storage_complete"] or inspection["cleanup"] != "STOPPED_CLEAN":
        raise AssertionError(inspection)
    if chunk_ids != [0, 1, 2] or len(records(directory)) != 5:
        raise AssertionError({"chunks": chunk_ids, "events": len(records(directory))})
    status = result["status"]
    if status["sealed_chunks"] != 3 or status["outstanding_seal_bytes"] != 0:
        raise AssertionError(status)
    report = {"ok": True, "chunks": chunk_ids, "events": 5,
              "unique_enqueue_time_ids": True, "bounded_outstanding_bytes": True}
    path = root / "report.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(path), **report}))


if __name__ == "__main__":
    main()
