from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uc.d3d11_capture import validate_capture


def descriptor(size, decoded):
    return {"raw_hex": "00" * size, "decoded": decoded}


def artifact(identity, kind, digest, path, size=16, encoding="raw"):
    return {"id": identity, "kind": kind, "path": path, "sha256": digest,
            "size_bytes": size, "encoding": encoding, "lossless": True}


def stage(shader_id, *, cbs=(), srvs=(), samplers=(), uavs=()):
    def rows(values):
        return [{"slot": slot, "object_id": identity} for slot, identity in values]
    return {"shader_id": shader_id, "class_instance_ids": [], "constant_buffers": rows(cbs), "srvs": rows(srvs),
            "samplers": rows(samplers), "uavs": rows(uavs)}


def fixture():
    hashes = {name: str(index) * 64 for index, name in enumerate(
        ("exe", "vs", "ps", "vb", "cb", "reference"), start=1)}
    resources = [{
        "id": "res.vb", "kind": "buffer",
        "descriptor": descriptor(24, {"byte_width": 256, "usage": 1, "bind_flags": 1,
            "cpu_access_flags": 0, "misc_flags": 0, "structure_byte_stride": 0}),
        "content_policy": "initial_data",
        "initial_data": [{"subresource": 0, "artifact_id": "artifact.vb", "row_pitch": 256, "depth_pitch": 256}],
    }, {
        "id": "res.cb", "kind": "buffer",
        "descriptor": descriptor(24, {"byte_width": 64, "usage": 1, "bind_flags": 4,
            "cpu_access_flags": 0, "misc_flags": 0, "structure_byte_stride": 0}),
        "content_policy": "initial_data",
        "initial_data": [{"subresource": 0, "artifact_id": "artifact.cb", "row_pitch": 64, "depth_pitch": 64}],
    }, {
        "id": "res.gbuffer0", "kind": "texture2d",
        "descriptor": descriptor(44, {"width": 1920, "height": 1080, "mip_levels": 1,
            "array_size": 1, "format": {"value": 28, "name": "DXGI_FORMAT_R8G8B8A8_UNORM"},
            "sample_desc": {"count": 1, "quality": 0}, "usage": 0, "bind_flags": 40,
            "cpu_access_flags": 0, "misc_flags": 0}),
        "content_policy": "undefined", "initial_data": [],
    }]
    view = {
        "id": "view.gbuffer0.rtv", "kind": "rtv", "resource_id": "res.gbuffer0",
        "descriptor": descriptor(20, {"format": {"value": 28, "name": "DXGI_FORMAT_R8G8B8A8_UNORM"},
            "view_dimension": 4, "union": {"texture2d": {"mip_slice": 0}}}),
    }
    shaders = [{
        "id": "shader.vs", "stage": "vs", "artifact_id": "artifact.vs",
        "bytecode_sha256": hashes["vs"], "class_linkage_id": None,
        "required_bindings": {"constant_buffers": [0], "srvs": [], "samplers": [], "uavs": []},
    }, {
        "id": "shader.ps", "stage": "ps", "artifact_id": "artifact.ps",
        "bytecode_sha256": hashes["ps"], "class_linkage_id": None,
        "required_bindings": {"constant_buffers": [], "srvs": [], "samplers": [], "uavs": []},
    }]
    layout = {
        "id": "layout.body", "signature_artifact_id": "artifact.vs", "shader_signature_sha256": hashes["vs"],
        "elements": [{"semantic_name": "POSITION", "semantic_index": 0,
            "format": {"value": 6, "name": "DXGI_FORMAT_R32G32B32_FLOAT"}, "input_slot": 0,
            "aligned_byte_offset": 0, "input_slot_class": "per_vertex", "instance_data_step_rate": 0}],
    }
    rasterizer = {"id": "state.rasterizer", "kind": "rasterizer",
                  "descriptor": descriptor(40, {"fill_mode": 3, "cull_mode": 3})}
    binding_events = list(range(8, 15))
    snapshot = {
        "id": "snapshot.draw15", "event_id": 15, "binding_event_ids": binding_events,
        "input_assembler": {
            "input_layout_id": "layout.body", "primitive_topology": "D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST",
            "vertex_buffers": [{"slot": 0, "resource_id": "res.vb", "stride": 12, "offset": 0}],
            "index_buffer": None,
        },
        "stages": {"vs": stage("shader.vs", cbs=((0, "res.cb"),)), "ps": stage("shader.ps"),
                   "gs": None, "hs": None, "ds": None, "cs": None},
        "stream_output": {"targets": []},
        "rasterizer": {"state_id": "state.rasterizer",
            "viewports": [{"top_left_x": 0.0, "top_left_y": 0.0, "width": 1920.0, "height": 1080.0,
                           "min_depth": 0.0, "max_depth": 1.0}], "scissors": []},
        "output_merger": {"rtvs": [{"slot": 0, "object_id": "view.gbuffer0.rtv"}], "dsv_id": None,
            "uavs": [], "blend_state_id": None, "blend_factor": [1.0, 1.0, 1.0, 1.0],
            "sample_mask": 4294967295, "depth_stencil_state_id": None, "stencil_ref": 0},
        "predication": {"predicate_id": None, "value": False},
    }
    objects = resources + [view] + shaders + [layout, rasterizer]
    create_calls = {
        "res.vb": "CreateBuffer", "res.cb": "CreateBuffer", "res.gbuffer0": "CreateTexture2D",
        "view.gbuffer0.rtv": "CreateRenderTargetView", "shader.vs": "CreateVertexShader",
        "shader.ps": "CreatePixelShader", "layout.body": "CreateInputLayout",
        "state.rasterizer": "CreateRasterizerState",
    }
    events = [{"id": index, "op": "create_object", "object_id": row["id"], "call": create_calls[row["id"]]}
              for index, row in enumerate(objects)]
    events.extend([
        {"id": 8, "op": "set_state", "call": "IASetInputLayout", "arguments": {}, "object_ids": ["layout.body"]},
        {"id": 9, "op": "set_state", "call": "IASetVertexBuffers", "arguments": {"slot": 0}, "object_ids": ["res.vb"]},
        {"id": 10, "op": "set_state", "call": "VSSetShader", "arguments": {}, "object_ids": ["shader.vs"]},
        {"id": 11, "op": "set_state", "call": "VSSetConstantBuffers", "arguments": {"slot": 0}, "object_ids": ["res.cb"]},
        {"id": 12, "op": "set_state", "call": "PSSetShader", "arguments": {}, "object_ids": ["shader.ps"]},
        {"id": 13, "op": "set_state", "call": "RSSetState", "arguments": {}, "object_ids": ["state.rasterizer"]},
        {"id": 14, "op": "set_state", "call": "OMSetRenderTargets", "arguments": {"slots": 1}, "object_ids": ["view.gbuffer0.rtv"]},
        {"id": 15, "op": "draw", "call": "Draw", "arguments": {"vertex_count": 3, "start_vertex": 0},
         "snapshot_id": "snapshot.draw15"},
    ])
    return {
        "schema": "uc.d3d11-capture.v1", "capture_id": "test-body-draw",
        "api": "d3d11", "capture_kind": "golden_replay", "validation_mode": "golden",
        "source": {"capturer": "owned-fixture", "capturer_version": "1",
            "captured_utc": "2026-09-02T00:00:00Z",
            "executable": {"name": "fixture.exe", "sha256": hashes["exe"]}, "modules": [],
            "adapter": {"vendor_id": 4318, "device_id": 1, "luid": "0000000000000001"},
            "feature_level": "D3D_FEATURE_LEVEL_11_0"},
        "frame": {"frame_index": 1, "width": 1920, "height": 1080,
                  "swapchain_format": {"value": 28, "name": "DXGI_FORMAT_R8G8B8A8_UNORM"}},
        "completeness": {"object_creation": "complete", "resource_initial_data": "complete",
            "resource_updates": "complete", "binding_calls": "complete", "event_order": "complete",
            "draw_snapshots": "complete", "lossless_artifacts": True},
        "artifacts": [
            artifact("artifact.vs", "dxbc", hashes["vs"], "artifacts/vs.dxbc"),
            artifact("artifact.ps", "dxbc", hashes["ps"], "artifacts/ps.dxbc"),
            artifact("artifact.vb", "resource_initial_data", hashes["vb"], "artifacts/vb.bin"),
            artifact("artifact.cb", "resource_initial_data", hashes["cb"], "artifacts/cb.bin"),
            artifact("artifact.reference", "reference_attachment", hashes["reference"], "reference/gbuffer0.bin"),
        ],
        "objects": {"resources": resources, "views": [view], "shaders": shaders,
                    "input_layouts": [layout], "states": [rasterizer], "class_linkages": [],
                    "class_instances": [], "asynchronous": [], "pipeline_snapshots": [snapshot]},
        "events": events, "entry_event_id": 0, "target_draw_event_ids": [15],
        "checkpoints": [{"id": "checkpoint.after", "phase": "after_event", "event_id": 15,
            "attachments": [{"resource_id": "res.gbuffer0", "subresource": 0, "view_id": "view.gbuffer0.rtv",
                "aspect": "color", "artifact_id": "artifact.reference", "row_pitch": 7680, "depth_pitch": 8294400,
                "comparison": {"mode": "exact_unorm"}}]}],
    }


class D3D11CaptureTests(unittest.TestCase):
    def test_minimal_body_draw_has_replay_closure(self):
        result = validate_capture(fixture())
        self.assertEqual(result["replay_closure"], "complete")
        self.assertEqual(result["target_draws"], 1)

    def test_resource_and_view_descriptors_are_independent(self):
        value = fixture()
        value["objects"]["views"][0]["resource_id"] = "missing.resource"
        with self.assertRaisesRegex(ValueError, "unknown id"):
            validate_capture(value)

    def test_reflected_shader_slot_must_be_bound(self):
        value = fixture()
        value["objects"]["pipeline_snapshots"][0]["stages"]["vs"]["constant_buffers"] = []
        with self.assertRaisesRegex(ValueError, "misses vs constant_buffers slots"):
            validate_capture(value)

    def test_draw_cannot_read_uninitialized_resource(self):
        value = fixture()
        vb = value["objects"]["resources"][0]
        vb["content_policy"] = "captured_updates"
        vb["initial_data"] = []
        with self.assertRaisesRegex(ValueError, "reads uninitialized resources.*res.vb"):
            validate_capture(value)

    def test_every_device_object_needs_a_create_event(self):
        value = fixture()
        value["events"] = [event for event in value["events"] if event.get("object_id") != "shader.ps"]
        value["events"][4]["id"] = 5
        with self.assertRaisesRegex(ValueError, "event ids must be strictly increasing|objects lack create events|inactive object"):
            validate_capture(value)

    def test_draw_snapshot_needs_binding_provenance(self):
        value = fixture()
        value["objects"]["pipeline_snapshots"][0]["binding_event_ids"].append(99)
        with self.assertRaisesRegex(ValueError, "unavailable Set events"):
            validate_capture(value)

    def test_presentation_png_is_not_a_checkpoint_oracle(self):
        value = fixture()
        value["artifacts"][-1]["encoding"] = "png"
        with self.assertRaisesRegex(ValueError, "native lossless bytes"):
            validate_capture(value)

    def test_golden_replay_cannot_claim_interactive_validation(self):
        value = fixture()
        value["validation_mode"] = "interactive"
        with self.assertRaisesRegex(ValueError, "must use golden"):
            validate_capture(value)

    def test_verify_files_checks_bytes_and_hashes(self):
        value = fixture()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for row in value["artifacts"]:
                path = root / row["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = row["id"].encode("utf-8")
                path.write_bytes(payload)
                row["size_bytes"] = len(payload)
                row["sha256"] = hashlib.sha256(payload).hexdigest()
            for shader in value["objects"]["shaders"]:
                shader["bytecode_sha256"] = next(row["sha256"] for row in value["artifacts"]
                                                   if row["id"] == shader["artifact_id"])
            value["objects"]["input_layouts"][0]["shader_signature_sha256"] = value["objects"]["shaders"][0]["bytecode_sha256"]
            self.assertEqual(validate_capture(value, package_root=root, verify_files=True)["artifacts"], 5)

    def test_owned_native_d3d11_fixture_emits_a_verified_real_draw(self):
        executable = Path(__file__).resolve().parents[1] / "build" / "D3D11CaptureFixture.exe"
        if not executable.is_file():
            self.skipTest("build/D3D11CaptureFixture.exe has not been built")
        with tempfile.TemporaryDirectory() as temp:
            package_root = Path(temp) / "capture"
            completed = subprocess.run([str(executable), str(package_root)], capture_output=True, text=True,
                                       encoding="utf-8", timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with (package_root / "capture.json").open("r", encoding="utf-8") as stream:
                package = json.load(stream)
            result = validate_capture(package, package_root=package_root, verify_files=True)
            self.assertEqual(result["replay_closure"], "complete")
            pixels = (package_root / "reference" / "gbuffer0.bin").read_bytes()
            self.assertEqual(len(pixels), 16 * 16 * 4)
            self.assertEqual(set(bytes(pixels[index:index + 4]) for index in range(0, len(pixels), 4)),
                             {bytes.fromhex("ff4080ff")})


if __name__ == "__main__":
    unittest.main()
