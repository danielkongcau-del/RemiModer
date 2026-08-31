from __future__ import annotations

from typing import Any

from .model import sha, uint


SCHEMA = "uc.probe-site-qualification.v1"


def validate_site_qualification(value: Any) -> dict:
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("qualification schema")
    qid = value.get("qualification_id")
    if not isinstance(qid, str) or not qid:
        raise ValueError("qualification id required")
    modules = value.get("modules")
    if not isinstance(modules, dict) or not modules:
        raise ValueError("qualification modules required")
    for alias, module in modules.items():
        if not alias or not isinstance(module, dict) or not module.get("image"):
            raise ValueError("qualification module identity")
        sha(module.get("sha256"))
    sites = value.get("sites")
    if not isinstance(sites, list) or not sites:
        raise ValueError("qualification sites required")
    ids = set()
    ranges = []
    for site in sites:
        sid = site.get("id") if isinstance(site, dict) else None
        if not isinstance(sid, str) or not sid or sid in ids:
            raise ValueError("duplicate/empty qualification site id")
        ids.add(sid)
        if site.get("module") not in modules:
            raise ValueError(f"{sid}: unknown module")
        rva = uint(site.get("rva"), f"{sid}.rva")
        prefix = site.get("verified_source_prefix")
        if not isinstance(prefix, str) or len(prefix) < 64 or len(prefix) % 2 or prefix != prefix.lower():
            raise ValueError(f"{sid}: 32 lower-case hex source bytes required")
        try:
            bytes.fromhex(prefix)
        except ValueError as error:
            raise ValueError(f"{sid}: invalid source prefix") from error
        safe = uint(site.get("semantic_safe_span"), f"{sid}.semantic_safe_span", len(prefix)//2)
        if safe < 5 or safe > len(prefix)//2:
            raise ValueError(f"{sid}: semantic safe span")
        spans = site.get("safe_redirect_spans")
        if (not isinstance(spans, list) or not spans or len(spans) != len(set(spans))
                or any(span not in (5, 16) for span in spans)
                or max(spans) > safe):
            raise ValueError(f"{sid}: safe redirect spans must be a covered subset of [5,16]")
        if site.get("direct_interior_edge_free") is not True:
            raise ValueError(f"{sid}: direct interior edge freedom required")
        for module, begin, end in ranges:
            if module == site["module"] and not (end <= rva or rva + 16 <= begin):
                raise ValueError("qualification site reservations overlap")
        ranges.append((site["module"], rva, rva + 16))
    return {"qualification_id": qid, "sites": len(sites), "activation_published": False}
