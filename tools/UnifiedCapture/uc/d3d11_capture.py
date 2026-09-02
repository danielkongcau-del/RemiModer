"""Validation for lossless, self-contained D3D11 replay packages.

The JSON Schema owns wire shape.  This module owns the cross-reference and
temporal invariants which JSON Schema cannot express: object lifetime, artifact
identity, resource initialization, shader binding closure, and target-draw
snapshot provenance.
"""
from __future__ import annotations

import json
import math
from pathlib import Path, PureWindowsPath

from jsonschema import Draft202012Validator, FormatChecker

from .model import file_hash


SCHEMA = "uc.d3d11-capture.v1"
OBJECT_GROUPS = ("resources", "views", "shaders", "input_layouts", "states",
                 "class_linkages", "class_instances", "asynchronous")
STAGES = ("vs", "ps", "gs", "hs", "ds", "cs")
DESCRIPTOR_BYTES = {
    "buffer": 24,
    "texture1d": 32,
    "texture2d": 44,
    "texture3d": 36,
    "srv": 24,
    "rtv": 20,
    "dsv": 24,
    "uav": 20,
    "sampler": 52,
    "rasterizer": 40,
    "depth_stencil": 52,
    "blend": 264,
    "class_instance": 28,
    "query": 8,
    "predicate": 8,
    "counter": 4,
}
RESOURCE_FIELDS = {
    "buffer": {"byte_width", "usage", "bind_flags", "cpu_access_flags", "misc_flags", "structure_byte_stride"},
    "texture1d": {"width", "mip_levels", "array_size", "format", "usage", "bind_flags", "cpu_access_flags", "misc_flags"},
    "texture2d": {"width", "height", "mip_levels", "array_size", "format", "sample_desc", "usage", "bind_flags", "cpu_access_flags", "misc_flags"},
    "texture3d": {"width", "height", "depth", "mip_levels", "format", "usage", "bind_flags", "cpu_access_flags", "misc_flags"},
}


def schema_path() -> Path:
    return Path(__file__).resolve().parents[1] / "schemas" / "d3d11-capture-v1.schema.json"


def _load_schema() -> dict:
    with schema_path().open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _schema_validate(package: dict) -> None:
    validator = Draft202012Validator(_load_schema(), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(package), key=lambda error: tuple(str(item) for item in error.path))
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise ValueError(f"schema violation at {location}: {error.message}")


def _unique_index(rows: list[dict], label: str) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for row in rows:
        identity = row["id"]
        if identity in result:
            raise ValueError(f"duplicate {label} id: {identity}")
        result[identity] = row
    return result


def _require_ref(index: dict[str, dict], identity: str | None, label: str) -> dict | None:
    if identity is None:
        return None
    if identity not in index:
        raise ValueError(f"{label} references unknown id: {identity}")
    return index[identity]


def _validate_relative_artifact_path(value: str) -> None:
    path = Path(value)
    windows = PureWindowsPath(value)
    if path.is_absolute() or windows.is_absolute() or ".." in path.parts or ".." in windows.parts:
        raise ValueError(f"artifact path must stay inside package root: {value}")


def _validate_descriptor(row: dict) -> None:
    expected = DESCRIPTOR_BYTES[row["kind"]]
    actual = len(row["descriptor"]["raw_hex"]) // 2
    if actual != expected:
        raise ValueError(f"{row['id']} {row['kind']} descriptor is {actual} bytes; expected {expected}")
    if row["kind"] in RESOURCE_FIELDS:
        decoded = row["descriptor"]["decoded"]
        missing = RESOURCE_FIELDS[row["kind"]] - decoded.keys()
        if missing:
            raise ValueError(f"{row['id']} decoded ResourceDesc lacks: {', '.join(sorted(missing))}")
    elif row["kind"] in {"srv", "rtv", "dsv", "uav"}:
        decoded = row["descriptor"]["decoded"]
        missing = {"format", "view_dimension", "union"} - decoded.keys()
        if missing:
            raise ValueError(f"{row['id']} decoded ViewDesc lacks: {', '.join(sorted(missing))}")


def _subresource_count(resource: dict) -> int:
    decoded = resource["descriptor"]["decoded"]
    if resource["kind"] == "buffer":
        return 1
    dimensions = [decoded["width"]]
    if resource["kind"] in {"texture2d", "texture3d"}:
        dimensions.append(decoded["height"])
    if resource["kind"] == "texture3d":
        dimensions.append(decoded["depth"])
    mip_levels = decoded["mip_levels"]
    if mip_levels == 0:
        mip_levels = math.floor(math.log2(max(dimensions))) + 1
    array_size = decoded.get("array_size", 1)
    return mip_levels * array_size


def _slot_index(rows: list[dict], label: str) -> dict[int, str]:
    result: dict[int, str] = {}
    for row in rows:
        slot = row["slot"]
        if slot in result:
            raise ValueError(f"duplicate {label} slot: {slot}")
        result[slot] = row["object_id"]
    return result


def _validate_snapshot(snapshot: dict, indexes: dict[str, dict[str, dict]]) -> None:
    resources = indexes["resources"]
    views = indexes["views"]
    shaders = indexes["shaders"]
    layouts = indexes["input_layouts"]
    states = indexes["states"]
    class_instances = indexes["class_instances"]
    asynchronous = indexes["asynchronous"]

    ia = snapshot["input_assembler"]
    _require_ref(layouts, ia["input_layout_id"], f"snapshot {snapshot['id']} input layout")
    vertex_slots: set[int] = set()
    for binding in ia["vertex_buffers"]:
        if binding["slot"] in vertex_slots:
            raise ValueError(f"snapshot {snapshot['id']} duplicates vertex-buffer slot {binding['slot']}")
        vertex_slots.add(binding["slot"])
        resource = _require_ref(resources, binding["resource_id"], "vertex buffer")
        if resource["kind"] != "buffer":
            raise ValueError(f"vertex-buffer binding is not a buffer: {binding['resource_id']}")
    index = ia["index_buffer"]
    if index is not None:
        resource = _require_ref(resources, index["resource_id"], "index buffer")
        if resource["kind"] != "buffer":
            raise ValueError(f"index-buffer binding is not a buffer: {index['resource_id']}")

    for stage in STAGES:
        binding = snapshot["stages"][stage]
        if binding is None:
            continue
        shader = _require_ref(shaders, binding["shader_id"], f"{stage} shader")
        if shader["stage"] != stage:
            raise ValueError(f"snapshot {snapshot['id']} binds {shader['stage']} shader as {stage}")
        seen_instances: set[str] = set()
        for identity in binding["class_instance_ids"]:
            if identity in seen_instances:
                raise ValueError(f"snapshot {snapshot['id']} duplicates class instance: {identity}")
            seen_instances.add(identity)
            instance = _require_ref(class_instances, identity, f"{stage} class instance")
            if shader["class_linkage_id"] != instance["linkage_id"]:
                raise ValueError(f"{stage} class instance linkage does not match shader: {identity}")
        groups = {
            "constant_buffers": _slot_index(binding["constant_buffers"], f"{stage} constant-buffer"),
            "srvs": _slot_index(binding["srvs"], f"{stage} SRV"),
            "samplers": _slot_index(binding["samplers"], f"{stage} sampler"),
            "uavs": _slot_index(binding["uavs"], f"{stage} UAV"),
        }
        for slot, identity in groups["constant_buffers"].items():
            resource = _require_ref(resources, identity, f"{stage} cb{slot}")
            if resource["kind"] != "buffer":
                raise ValueError(f"{stage} cb{slot} is not a buffer: {identity}")
        for slot, identity in groups["srvs"].items():
            view = _require_ref(views, identity, f"{stage} t{slot}")
            if view["kind"] != "srv":
                raise ValueError(f"{stage} t{slot} is not an SRV: {identity}")
        for slot, identity in groups["samplers"].items():
            state = _require_ref(states, identity, f"{stage} s{slot}")
            if state["kind"] != "sampler":
                raise ValueError(f"{stage} s{slot} is not a sampler: {identity}")
        for slot, identity in groups["uavs"].items():
            view = _require_ref(views, identity, f"{stage} u{slot}")
            if view["kind"] != "uav":
                raise ValueError(f"{stage} u{slot} is not a UAV: {identity}")
        for group, required_slots in shader["required_bindings"].items():
            missing = set(required_slots) - groups[group].keys()
            if missing:
                raise ValueError(f"snapshot {snapshot['id']} misses {stage} {group} slots: {sorted(missing)}")

    for binding in snapshot["stream_output"]["targets"]:
        resource = _require_ref(resources, binding["object_id"], "stream-output target")
        if resource["kind"] != "buffer":
            raise ValueError(f"stream-output target is not a buffer: {binding['object_id']}")

    rasterizer = snapshot["rasterizer"]
    state = _require_ref(states, rasterizer["state_id"], "rasterizer state")
    if state is not None and state["kind"] != "rasterizer":
        raise ValueError(f"wrong state kind for rasterizer: {state['id']}")

    output = snapshot["output_merger"]
    for slot, identity in _slot_index(output["rtvs"], "RTV").items():
        view = _require_ref(views, identity, f"RTV {slot}")
        if view["kind"] != "rtv":
            raise ValueError(f"output slot {slot} is not an RTV: {identity}")
    for slot, identity in _slot_index(output["uavs"], "OM UAV").items():
        view = _require_ref(views, identity, f"OM UAV {slot}")
        if view["kind"] != "uav":
            raise ValueError(f"OM UAV slot {slot} is not a UAV: {identity}")
    dsv = _require_ref(views, output["dsv_id"], "DSV")
    if dsv is not None and dsv["kind"] != "dsv":
        raise ValueError(f"output depth target is not a DSV: {dsv['id']}")
    for field, kind in (("blend_state_id", "blend"), ("depth_stencil_state_id", "depth_stencil")):
        state = _require_ref(states, output[field], field)
        if state is not None and state["kind"] != kind:
            raise ValueError(f"wrong state kind for {field}: {state['id']}")

    predicate = _require_ref(asynchronous, snapshot["predication"]["predicate_id"], "predicate")
    if predicate is not None and predicate["kind"] != "predicate":
        raise ValueError(f"predication object is not a predicate: {predicate['id']}")


def _snapshot_object_refs(snapshot: dict, indexes: dict[str, dict[str, dict]]) -> set[str]:
    refs: set[str] = set()
    ia = snapshot["input_assembler"]
    if ia["input_layout_id"] is not None:
        refs.add(ia["input_layout_id"])
    refs.update(row["resource_id"] for row in ia["vertex_buffers"])
    if ia["index_buffer"] is not None:
        refs.add(ia["index_buffer"]["resource_id"])
    for binding in snapshot["stages"].values():
        if binding is not None:
            refs.add(binding["shader_id"])
            refs.update(binding["class_instance_ids"])
            for group in ("constant_buffers", "srvs", "samplers", "uavs"):
                refs.update(row["object_id"] for row in binding[group])
    refs.update(row["object_id"] for row in snapshot["stream_output"]["targets"])
    if snapshot["rasterizer"]["state_id"] is not None:
        refs.add(snapshot["rasterizer"]["state_id"])
    output = snapshot["output_merger"]
    refs.update(row["object_id"] for row in output["rtvs"])
    refs.update(row["object_id"] for row in output["uavs"])
    for field in ("dsv_id", "blend_state_id", "depth_stencil_state_id"):
        if output[field] is not None:
            refs.add(output[field])
    if snapshot["predication"]["predicate_id"] is not None:
        refs.add(snapshot["predication"]["predicate_id"])
    return refs


def _input_resources(snapshot: dict, indexes: dict[str, dict[str, dict]]) -> set[str]:
    resources: set[str] = set()
    ia = snapshot["input_assembler"]
    resources.update(row["resource_id"] for row in ia["vertex_buffers"])
    if ia["index_buffer"] is not None:
        resources.add(ia["index_buffer"]["resource_id"])
    for binding in snapshot["stages"].values():
        if binding is None:
            continue
        resources.update(row["object_id"] for row in binding["constant_buffers"])
        for row in binding["srvs"]:
            resources.add(indexes["views"][row["object_id"]]["resource_id"])
    return resources


def _output_resources(snapshot: dict, indexes: dict[str, dict[str, dict]], compute: bool) -> set[str]:
    resources: set[str] = set()
    if compute:
        binding = snapshot["stages"]["cs"]
        if binding is not None:
            resources.update(indexes["views"][row["object_id"]]["resource_id"] for row in binding["uavs"])
        return resources
    resources.update(row["object_id"] for row in snapshot["stream_output"]["targets"])
    output = snapshot["output_merger"]
    for row in output["rtvs"] + output["uavs"]:
        resources.add(indexes["views"][row["object_id"]]["resource_id"])
    if output["dsv_id"] is not None:
        resources.add(indexes["views"][output["dsv_id"]]["resource_id"])
    return resources


def validate_capture(package: dict, *, package_root: Path | None = None, verify_files: bool = False) -> dict:
    """Validate schema, content identity, object graph, and replay chronology."""
    _schema_validate(package)
    if package["schema"] != SCHEMA:
        raise ValueError("unsupported D3D11 capture schema")
    if package["validation_mode"] == "interactive" and package["capture_kind"] == "golden_replay":
        raise ValueError("golden_replay packages must use golden validation mode")

    artifacts = _unique_index(package["artifacts"], "artifact")
    indexes = {group: _unique_index(package["objects"][group], group[:-1]) for group in OBJECT_GROUPS}
    snapshots = _unique_index(package["objects"]["pipeline_snapshots"], "pipeline snapshot")
    checkpoints = _unique_index(package["checkpoints"], "checkpoint")

    all_ids: dict[str, str] = {}
    for label, rows in (("artifact", artifacts), *indexes.items(), ("pipeline_snapshot", snapshots), ("checkpoint", checkpoints)):
        for identity in rows:
            if identity in all_ids:
                raise ValueError(f"global id collision: {identity} ({all_ids[identity]} and {label})")
            all_ids[identity] = label

    root = Path(package_root).resolve() if package_root is not None else None
    for artifact in artifacts.values():
        _validate_relative_artifact_path(artifact["path"])
        if verify_files:
            if root is None:
                raise ValueError("verify_files requires package_root")
            path = (root / artifact["path"]).resolve()
            try:
                path.relative_to(root)
            except ValueError as error:
                raise ValueError(f"artifact escapes package root: {artifact['path']}") from error
            if not path.is_file():
                raise ValueError(f"artifact missing: {artifact['path']}")
            if path.stat().st_size != artifact["size_bytes"]:
                raise ValueError(f"artifact size mismatch: {artifact['path']}")
            if file_hash(path) != artifact["sha256"]:
                raise ValueError(f"artifact hash mismatch: {artifact['path']}")

    for resource in indexes["resources"].values():
        _validate_descriptor(resource)
        initial = resource["initial_data"]
        if resource["content_policy"] == "initial_data" and not initial:
            raise ValueError(f"resource declares initial_data without bytes: {resource['id']}")
        if resource["content_policy"] == "undefined" and initial:
            raise ValueError(f"undefined resource unexpectedly contains initial bytes: {resource['id']}")
        subresources: set[int] = set()
        for item in initial:
            if item["subresource"] in subresources:
                raise ValueError(f"duplicate initial subresource {item['subresource']} for {resource['id']}")
            subresources.add(item["subresource"])
            artifact = _require_ref(artifacts, item["artifact_id"], "resource initial data")
            if artifact["kind"] != "resource_initial_data":
                raise ValueError(f"initial data uses wrong artifact kind: {artifact['id']}")
        if initial and subresources != set(range(_subresource_count(resource))):
            raise ValueError(f"initial data does not cover every subresource for {resource['id']}")

    for view in indexes["views"].values():
        _validate_descriptor(view)
        _require_ref(indexes["resources"], view["resource_id"], f"view {view['id']}")
    for state in indexes["states"].values():
        _validate_descriptor(state)
    for linkage in indexes["class_linkages"].values():
        if set(linkage) != {"id"}:
            raise ValueError(f"class linkage has unexpected data: {linkage['id']}")
    for instance in indexes["class_instances"].values():
        descriptor_row = {"id": instance["id"], "kind": "class_instance", "descriptor": instance["descriptor"]}
        _validate_descriptor(descriptor_row)
        _require_ref(indexes["class_linkages"], instance["linkage_id"], f"class instance {instance['id']}")
    for async_object in indexes["asynchronous"].values():
        _validate_descriptor(async_object)
    for shader in indexes["shaders"].values():
        artifact = _require_ref(artifacts, shader["artifact_id"], f"shader {shader['id']}")
        if artifact["kind"] != "dxbc" or artifact["sha256"] != shader["bytecode_sha256"]:
            raise ValueError(f"shader DXBC artifact/hash mismatch: {shader['id']}")
        _require_ref(indexes["class_linkages"], shader["class_linkage_id"], f"shader {shader['id']} class linkage")
    for layout in indexes["input_layouts"].values():
        artifact = _require_ref(artifacts, layout["signature_artifact_id"], f"input layout {layout['id']} signature")
        if artifact["kind"] != "dxbc" or artifact["sha256"] != layout["shader_signature_sha256"]:
            raise ValueError(f"input-layout signature artifact/hash mismatch: {layout['id']}")
    for snapshot in snapshots.values():
        _validate_snapshot(snapshot, indexes)

    events = package["events"]
    event_by_id: dict[int, dict] = {}
    previous = -1
    for event in events:
        if event["id"] <= previous:
            raise ValueError("event ids must be strictly increasing")
        previous = event["id"]
        event_by_id[event["id"]] = event
    if package["entry_event_id"] not in event_by_id:
        raise ValueError("entry_event_id does not identify an event")

    device_objects = {identity: row for group in OBJECT_GROUPS for identity, row in indexes[group].items()}
    active: set[str] = set()
    created: set[str] = set()
    initialized = {identity for identity, row in indexes["resources"].items() if row["initial_data"]}
    set_event_ids: set[int] = set()
    draw_ids: set[int] = set()
    for event in events:
        op = event["op"]
        if op == "create_object":
            identity = event["object_id"]
            _require_ref(device_objects, identity, "create_object")
            if identity in created:
                raise ValueError(f"object created twice: {identity}")
            created.add(identity)
            active.add(identity)
            continue
        if op == "destroy_object":
            identity = event["object_id"]
            if identity not in active:
                raise ValueError(f"destroy of inactive object: {identity}")
            active.remove(identity)
            continue
        if op == "set_state":
            for identity in event["object_ids"]:
                if identity not in active:
                    raise ValueError(f"{event['call']} uses inactive object: {identity}")
            set_event_ids.add(event["id"])
            continue
        if op == "async":
            identity = event["async_id"]
            if identity not in active or identity not in indexes["asynchronous"]:
                raise ValueError(f"{event['call']} uses inactive async object: {identity}")
            if event.get("artifact_id") is not None:
                _require_ref(artifacts, event["artifact_id"], f"{event['call']} result")
            continue
        if op in {"update_buffer", "update_texture", "map_write"}:
            identity = event["resource_id"]
            if identity not in active or identity not in indexes["resources"]:
                raise ValueError(f"update uses inactive resource: {identity}")
            artifact = _require_ref(artifacts, event["artifact_id"], "resource update")
            if artifact["kind"] != "resource_update_data":
                raise ValueError(f"resource update uses wrong artifact kind: {artifact['id']}")
            initialized.add(identity)
            continue
        if op in {"copy_resource", "copy_subresource_region", "resolve_subresource"}:
            src, dst = event["src_resource_id"], event["dst_resource_id"]
            if src not in active or dst not in active or src not in indexes["resources"] or dst not in indexes["resources"]:
                raise ValueError(f"copy/resolve uses inactive resource at event {event['id']}")
            if src not in initialized:
                raise ValueError(f"copy/resolve reads uninitialized resource: {src}")
            initialized.add(dst)
            continue
        if op in {"clear_rtv", "clear_dsv", "clear_uav", "generate_mips"}:
            view = _require_ref(indexes["views"], event["view_id"], op)
            if view["id"] not in active:
                raise ValueError(f"{op} uses inactive view: {view['id']}")
            expected = {"clear_rtv": "rtv", "clear_dsv": "dsv", "clear_uav": "uav", "generate_mips": "srv"}[op]
            if view["kind"] != expected:
                raise ValueError(f"{op} uses {view['kind']} view: {view['id']}")
            initialized.add(view["resource_id"])
            continue
        if op in {"draw", "dispatch"}:
            snapshot = _require_ref(snapshots, event["snapshot_id"], op)
            if snapshot["event_id"] != event["id"]:
                raise ValueError(f"snapshot {snapshot['id']} belongs to event {snapshot['event_id']}, not {event['id']}")
            missing_binding_events = set(snapshot["binding_event_ids"]) - set_event_ids
            if missing_binding_events:
                raise ValueError(f"snapshot {snapshot['id']} cites unavailable Set events: {sorted(missing_binding_events)}")
            inactive = _snapshot_object_refs(snapshot, indexes) - active
            if inactive:
                raise ValueError(f"snapshot {snapshot['id']} uses inactive objects: {sorted(inactive)}")
            if op == "draw":
                if snapshot["stages"]["vs"] is None or snapshot["stages"]["cs"] is not None:
                    raise ValueError(f"draw snapshot {snapshot['id']} needs VS and no CS")
                if not snapshot["output_merger"]["rtvs"] and snapshot["output_merger"]["dsv_id"] is None:
                    raise ValueError(f"draw snapshot {snapshot['id']} has no output target")
                indexed = event["call"] in {"DrawIndexed", "DrawIndexedInstanced", "DrawIndexedInstancedIndirect"}
                if indexed and snapshot["input_assembler"]["index_buffer"] is None:
                    raise ValueError(f"{event['call']} lacks an index buffer")
                draw_ids.add(event["id"])
            else:
                if snapshot["stages"]["cs"] is None:
                    raise ValueError(f"dispatch snapshot {snapshot['id']} has no CS")
            input_resources = _input_resources(snapshot, indexes)
            if event.get("indirect_args_resource_id") is not None:
                indirect = event["indirect_args_resource_id"]
                if indirect not in active or indirect not in indexes["resources"]:
                    raise ValueError(f"indirect call uses inactive argument buffer: {indirect}")
                input_resources.add(indirect)
            missing_content = input_resources - initialized
            if missing_content:
                raise ValueError(f"event {event['id']} reads uninitialized resources: {sorted(missing_content)}")
            initialized.update(_output_resources(snapshot, indexes, op == "dispatch"))

    missing_creations = device_objects.keys() - created
    if missing_creations:
        raise ValueError(f"objects lack create events: {sorted(missing_creations)}")
    target_draws = set(package["target_draw_event_ids"])
    if not target_draws <= draw_ids:
        raise ValueError(f"target_draw_event_ids include non-draw events: {sorted(target_draws - draw_ids)}")
    if min(target_draws) < package["entry_event_id"]:
        raise ValueError("target draw precedes replay entry event")

    for checkpoint in checkpoints.values():
        if checkpoint["event_id"] not in event_by_id:
            raise ValueError(f"checkpoint {checkpoint['id']} references unknown event")
        for attachment in checkpoint["attachments"]:
            resource = _require_ref(indexes["resources"], attachment["resource_id"], "checkpoint resource")
            if attachment.get("view_id") is not None:
                view = _require_ref(indexes["views"], attachment["view_id"], "checkpoint view")
                if view["resource_id"] != resource["id"]:
                    raise ValueError(f"checkpoint view/resource disagree: {view['id']}")
            artifact = _require_ref(artifacts, attachment["artifact_id"], "checkpoint attachment")
            if artifact["kind"] != "reference_attachment":
                raise ValueError(f"checkpoint uses wrong artifact kind: {artifact['id']}")
            if artifact["encoding"] not in {"raw", "dds", "ucbin"}:
                raise ValueError(f"checkpoint requires native lossless bytes, not {artifact['encoding']}: {artifact['id']}")
            comparison = attachment["comparison"]
            if comparison["mode"] == "float_tolerance" and not ({"absolute_tolerance", "relative_tolerance"} & comparison.keys()):
                raise ValueError("float_tolerance requires an absolute or relative tolerance")

    return {
        "schema": SCHEMA,
        "capture_id": package["capture_id"],
        "artifacts": len(artifacts),
        "device_objects": len(device_objects),
        "pipeline_snapshots": len(snapshots),
        "events": len(events),
        "target_draws": len(target_draws),
        "checkpoints": len(checkpoints),
        "replay_closure": "complete",
    }
