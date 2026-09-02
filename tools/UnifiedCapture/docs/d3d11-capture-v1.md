# `uc.d3d11-capture.v1`

This package is the replay boundary between an authoritative D3D11 capture and a native golden renderer. It is deliberately stricter than a frame-inspection export: a valid package must be sufficient to reconstruct the selected event range without consulting the original process, RenderDoc, Unity, or undocumented local state.

## Evidence contract

A package makes seven explicit completeness claims: D3D object creation, resource initial data, resource updates, binding calls, event order, draw snapshots, and lossless artifacts. The validator accepts only `complete`/`true` for these claims. If the capturer did not observe one category, it must not emit this schema.

Every binary artifact has a relative path, byte size, lowercase SHA-256, encoding, and `lossless: true`. The manifest separates:

- `ResourceDesc` from `ViewDesc`. A resource and each SRV/RTV/DSV/UAV over it are distinct objects with distinct IDs and exact raw descriptor bytes.
- Original DXBC from reflection-derived binding requirements. The replay executes the captured bytecode; reflection only states which slots must be closed.
- D3D device objects from materialized pipeline snapshots. Device objects have `create_object` lifetime events; snapshots are immutable evidence records tied one-to-one to a draw or dispatch event.
- Golden validation from interactive validation. A `golden_replay` package may only use `validation_mode: golden`.

Descriptor `raw_hex` is the byte-exact native D3D11 descriptor. `decoded` is the readable projection. Resource projections use these names:

| Kind | Required decoded fields |
| --- | --- |
| buffer | `byte_width`, `usage`, `bind_flags`, `cpu_access_flags`, `misc_flags`, `structure_byte_stride` |
| texture1d | `width`, `mip_levels`, `array_size`, `format`, `usage`, `bind_flags`, `cpu_access_flags`, `misc_flags` |
| texture2d | `width`, `height`, `mip_levels`, `array_size`, `format`, `sample_desc`, `usage`, `bind_flags`, `cpu_access_flags`, `misc_flags` |
| texture3d | `width`, `height`, `depth`, `mip_levels`, `format`, `usage`, `bind_flags`, `cpu_access_flags`, `misc_flags` |

View projections must include `format`, `view_dimension`, and `union`. The union object retains the active SDK union member and all its fields.

## Draw closure

Every draw/dispatch references one pipeline snapshot whose `event_id` is that event. The snapshot contains IA, all six shader stages, dynamic class instances, SO, RS, OM, and predication state. `binding_event_ids` identifies the complete, ordered `Set*` calls which produced the materialized state; all must precede the draw. Input layouts identify the exact DXBC artifact used as their creation signature. Predication references a captured `ID3D11Predicate`, never an ordinary buffer.

The semantic validator checks:

- global ID uniqueness and every cross-reference;
- exact native descriptor byte sizes;
- original DXBC artifact kind and digest identity;
- object creation before use and destruction after last use;
- slot uniqueness and shader-stage compatibility;
- every reflected CB/SRV/Sampler/UAV requirement against the snapshot;
- initialized contents for vertex, index, constant, sampled, predicate, and indirect-argument resources;
- correct view/state kinds at every binding;
- indexed draw/index-buffer and draw/output-target requirements;
- target draw identity and checkpoint attachment provenance;
- native raw/DDS/UC binary checkpoint data rather than presentation screenshots.

Resource initialization is temporal. Initial artifacts initialize a resource at creation; update/map/clear/copy/resolve and draw/dispatch outputs update initialization state. A resource read before any such producer invalidates the package.

## Event vocabulary

The event stream retains `create_object`, `destroy_object`, `set_state`, buffer/texture/map writes, all draw and dispatch variants, copy/subresource-copy/resolve, clears, mip generation, present, and markers. API-specific arguments which do not reference an object remain in the event `arguments` object. Every referenced D3D object also appears in `object_ids`, typed event fields, or the event's pipeline snapshot, so an object dependency cannot hide inside an opaque string.

## Checkpoints

Checkpoints attach native resource bytes before or after a named event. Each attachment specifies resource, subresource, optional view, aspect, artifact, row/depth pitch, and comparison policy. Floating-point comparisons need an explicit absolute or relative tolerance; integer and normalized targets can demand exact comparison. PNG may exist as auxiliary metadata, but cannot serve as a checkpoint oracle.

## Validation

Run structural and semantic validation:

```powershell
python d3d11_capture_verify.py <package>\capture.json
```

Also verify every artifact path, size, and SHA-256:

```powershell
python d3d11_capture_verify.py <package>\capture.json --verify-files
```

The command exits `0` on success and `2` on malformed, incomplete, or changed evidence. A successful result reports `replay_closure: complete`; it does not claim that replay pixels already match the authoritative checkpoint.

The owned native fixture exercises the producer side with an actual WARP D3D11 device and GPU draw:

```powershell
cmd /c build.cmd
build\D3D11CaptureFixture.exe build\d3d11-fixture-package
python d3d11_capture_verify.py build\d3d11-fixture-package\capture.json --verify-files
```

It creates real DXBC, buffers, descriptors, state calls, a draw snapshot, and a GPU-readback oracle. It proves the package writer and validator agree on real D3D11 objects; it is not game evidence and is never a substitute for the authoritative target capture.

When an RDC is available, first inventory the official lossless XML+ZIP export:

```powershell
python renderdoc_export_inventory.py frame.rdc build\frame-inventory
```

The inventory hashes the RDC/XML/ZIP, checks every numbered binary blob against the XML `byteLength`, classifies Create/Set/Update/Copy/Clear/Draw/Dispatch chunks, and preserves unresolved internal resource IDs. Its terminal status is deliberately `mechanical-export-inventory-not-yet-uc-d3d11-package`: a valid XML export still needs native attachment export, descriptor packing, object mapping, and full `uc.d3d11-capture.v1` validation.

## R1 acceptance boundary

The first native replay package should contain exactly one ordinary opaque body GBuffer draw, not a face pass and not deferred lighting. R1 passes only when the native runner consumes the original DXBC and captured state/data and reproduces every selected GBuffer attachment under its declared comparison policy. Deferred lighting and Unity hosting remain out of scope until that comparison passes.
