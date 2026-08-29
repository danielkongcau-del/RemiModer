"""Derived views with raw byte references. Neither projection is original evidence."""
import json
from pathlib import Path
import subprocess
from .store import decode_chunk, inspect_session, read_manifest

def source_events(directory):
    directory = Path(directory)
    inspection = inspect_session(directory)
    for chunk in inspection["chunks"]:
        _, rows = decode_chunk((directory / chunk["file"]).read_bytes())
        for offset, length, event, blob in rows:
            source = {"file": str((directory / chunk["file"]).resolve()), "sha256": chunk["sha256"],
                      "offset": offset, "length": length, "offset_domain": "decompressed_payload"}
            yield event, blob, source

def execution_graph(directory, destination):
    nodes, events = {}, []
    for event, _, source in source_events(directory):
        if event.get("kind") != "enter":
            continue
        key = str(event["invocation_id"])
        if key in nodes:
            raise ValueError("duplicate invocation identity")
        nodes[key] = {"id": key, "point": event["point"], "generation": event["generation"],
                      "tid": event["tid"], "qpc": event["qpc"], "source": source}
        events.append(event)
    edges, unresolved = [], []
    for event in events:
        parent = str(event.get("observed_parent", 0))
        child = str(event["invocation_id"])
        if parent == "0":
            continue
        if event.get("parent_known") and parent in nodes and nodes[parent]["tid"] == event["tid"]:
            edges.append({"parent": parent, "child": child, "kind": "observed_nesting",
                          "direct_native_call_proven": False, "source": nodes[child]["source"]})
        else:
            unresolved.append({"child": child, "recorded_parent": parent, "reason": "missing_parent_or_thread_proof"})
    graph = {"schema": "uc.execution-projection.v1", "inspection": inspect_session(Path(directory)),
        "nodes": list(nodes.values()), "edges": edges, "unresolved": unresolved,
        "automatic_entity_join": False, "cross_thread_edges_inferred": False, "complete_controller": False}
    with Path(destination).open("x", encoding="utf-8") as stream:
        json.dump(graph, stream, ensure_ascii=False, indent=2)
    return {"nodes": len(nodes), "observed_nesting_edges": len(edges), "unresolved": len(unresolved), "path": str(destination)}

def legacy_projection(directory, destination, decoder):
    """Preserve old field JSON for existing analyses, backed by original new chunks."""
    decoder = Path(decoder).resolve()
    schema = json.loads(subprocess.check_output([str(decoder), "--schema"]))
    manifests, _ = read_manifest(Path(directory) / "session.manifest")
    expected = {}
    for row in manifests:
        if row.get("kind") == "plan_activation":
            for point in row["source"]["points"]:
                if "legacy_reader" in point:
                    expected[row["generation"], point["id"]] = point["legacy_reader"]["source_digest"]
    count = 0
    with Path(destination).open("x", encoding="utf-8") as output:
        for event, blob, source in source_events(directory):
            legacy = event.get("legacy_snapshot")
            if not legacy:
                continue
            if expected.get((event["generation"], event["point"])) != schema["digest"]:
                raise ValueError("decoder does not match captured frozen-reader source")
            start, length = legacy["offset"], legacy["length"]
            if not 0 <= start <= len(blob) or not 0 <= length <= len(blob)-start:
                raise ValueError("snapshot byte span invalid")
            decoded = subprocess.run([str(decoder), legacy["reader"]], input=blob[start:start+length],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            snapshot = json.loads(decoded.stdout)
            row = {"event": "native_step" if legacy["reader"] == "state-step-p1bo-v1" else "native_consumer",
                   "phase": event["kind"], "qpc": event["qpc"], "tid": event["tid"],
                   "callId": event["invocation_id"], "generation": event["generation"],
                   "snapshot": snapshot, "source": source, "projection_not_original": True}
            output.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return {"records": count, "path": str(destination), "source_mutated": False}
