"""Native proof for exact caller-continuation normal-return pairing."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from caller_continuation_apply import run as apply_continuations
from caller_continuation_prepare import run as prepare_continuations
from native_integration import Host, records
from uc.model import canonical
from uc.store import read_manifest


def main():
    root = ROOT / "test-output" / ("native-caller-continuation-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False}
    try:
        discovery = host.make_probe_pair_plan((("recursive", "pair_recursive"),), slots=128)
        point = discovery["observations"][0]
        point["exit_capture_requirement"] = "none"
        point["retention"] = {"mode": "first_per_entry_return_address", "max_keys": 16}
        applied_discovery = host.control("apply", plan=discovery)
        host.invoke("pair_recursive", depth=3)
        host.invoke("pair_recursive", depth=2)
        host.stop()
        manifest, errors = read_manifest(Path(applied_discovery["directory"]) / "session.manifest")
        if errors:
            raise AssertionError(errors)
        summaries = []
        for row in manifest:
            if row.get("kind") == "retention_summary":
                summary = row.get("retention", {})
                if summary.get("point") == "recursive":
                    summaries.append(summary)
            elif row.get("kind") == "generation_point_retired":
                summary = row.get("retention", {})
                if summary.get("point") == "recursive":
                    summaries.append(summary)
        summary = summaries[-1]
        if not summary.get("complete_for_caller_counts") or len(summary.get("keys", [])) != 2:
            raise AssertionError(summary)
        exact = copy.deepcopy(discovery)
        exact["plan_id"] += "-exact"
        exact["plan_revision"] += 1
        exact_point = exact["observations"][0]
        exact_point["retention"]["exact_callers"] = [{
            "module": "fixture", "return_rva": int(row["entry_return_address"]) - host.info["base"],
            "evidence": ["fixture"],
        } for row in summary["keys"]]
        exact_path = root / "exact-plan.json"
        exact_path.write_bytes(canonical(exact))

        prepared_dir = root / "prepared"
        prepare_continuations(exact_path, prepared_dir)
        qualification = json.loads((prepared_dir / "qualification-request.json").read_text(encoding="utf-8"))
        qualification_response = host.control("qualify-sites", qualification=qualification,
                                              request_id="caller-continuation-qualification")
        if not qualification_response.get("ok") or qualification_response.get("capture_generation_published"):
            raise AssertionError(qualification_response)
        envelope_path = root / "qualification-evidence.json"
        envelope_path.write_bytes(canonical({
            "schema": "uc.target-site-qualification-evidence.v1",
            "request": qualification, "response": qualification_response,
        }))
        activated_dir = root / "activated"
        apply_continuations(exact_path, prepared_dir / "caller-continuation-candidates.json",
                            envelope_path, activated_dir)
        completed_plan = json.loads((activated_dir / "capture-plan.caller-continuations.json").read_text())
        applied = host.control("apply", plan=completed_plan,
                               request_id="caller-continuation-apply")
        host.invoke("pair_recursive", depth=4)
        host.stop()
        events = [row for row, _ in records(applied["directory"]) if row.get("point") == "recursive"]
        entries = [row for row in events if row.get("kind") == "enter"]
        leaves = [row for row in events if row.get("kind") == "leave"]
        if len(entries) != 5 or len(leaves) != 5:
            raise AssertionError({"entries": len(entries), "leaves": len(leaves), "events": events})
        invocations = {row["invocation_id"] for row in entries}
        if invocations != {row["invocation_id"] for row in leaves} or 0 in invocations:
            raise AssertionError("entry/leave invocation pairing mismatch")
        if any(row.get("exceptional") for row in leaves):
            raise AssertionError("normal continuation was marked exceptional")
        result = {
            "ok": True, "discovered_callers": len(summary["keys"]),
            "continuation_sites": len(qualification["sites"]),
            "recursive_entries": len(entries), "normal_continuation_leaves": len(leaves),
            "same_process_discovery_stop_qualification_apply": True,
            "semantics": "normal_return_to_observed_callsite_continuation",
        }
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **result}, ensure_ascii=False))


if __name__ == "__main__":
    main()
