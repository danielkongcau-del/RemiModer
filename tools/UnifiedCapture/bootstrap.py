"""Download pinned TOOL dependencies only. Never transmits workspace content."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
DEPENDENCIES = (
    ("frida-gum-17.17.0.tar.xz",
     "https://github.com/frida/frida/releases/download/17.17.0/frida-gum-devkit-17.17.0-windows-x86_64.tar.xz",
     "7c0166afe681395acb523fc3044a8b9434c9166997f6fdba43fd3631abaa6ca0"),
    ("json.hpp",
     "https://raw.githubusercontent.com/nlohmann/json/v3.12.0/single_include/nlohmann/json.hpp",
     "aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63"),
)

def main():
    cache = ROOT / "vendor"
    cache.mkdir(exist_ok=True)
    for name, url, wanted in DEPENDENCIES:
        target = cache / name
        if target.exists():
            data = target.read_bytes()
        else:
            request = urllib.request.Request(url, headers={"User-Agent": "UnifiedCapture-dependency-bootstrap"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            digest = hashlib.sha256(data).hexdigest()
            if digest != wanted:
                raise ValueError(f"download hash mismatch: {name}: expected {wanted}, got {digest}; "
                                 "re-run to retry the download or update the pinned digest deliberately")
            with target.open("xb") as stream:
                stream.write(data)
        digest = hashlib.sha256(data).hexdigest()
        if digest != wanted:
            raise ValueError(f"existing dependency hash mismatch: {target}: expected {wanted}, got {digest}; "
                             "delete the file to re-download or update the pinned digest deliberately")
        print(f"VERIFIED {name} {wanted}", flush=True)
    destination = cache / "gum-17.17.0"
    destination.mkdir(exist_ok=True)
    with tarfile.open(cache / DEPENDENCIES[0][0], "r:xz") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination.resolve()) or member.issym() or member.islnk():
                raise ValueError(f"unsupported archive member: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                data = archive.extractfile(member).read()
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if target.read_bytes() != data:
                        raise ValueError(f"changed extracted dependency: {target}")
                else:
                    with target.open("xb") as stream:
                        stream.write(data)
    manifest = {"schema": "uc.tool-dependencies.v1", "dependencies": [
        {"file": name, "url": url, "sha256": sha} for name, url, sha in DEPENDENCIES]}
    manifest_path = cache / "dependencies.lock.json"
    encoded = json.dumps(manifest, indent=2).encode() + b"\n"
    if manifest_path.exists():
        if manifest_path.read_bytes() != encoded:
            raise ValueError("existing dependency lock differs")
    else:
        with manifest_path.open("xb") as stream:
            stream.write(encoded)
if __name__ == "__main__":
    main()
