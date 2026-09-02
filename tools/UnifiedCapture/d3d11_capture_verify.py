from __future__ import annotations

import argparse
import json
from pathlib import Path

from uc.cli import run_main
from uc.d3d11_capture import validate_capture
from uc.model import canonical


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate a uc.d3d11-capture.v1 replay package")
    parser.add_argument("manifest", type=Path, help="capture manifest JSON")
    parser.add_argument("--verify-files", action="store_true", help="hash and size every package artifact")
    args = parser.parse_args(argv)
    manifest = args.manifest.resolve()
    with manifest.open("r", encoding="utf-8") as stream:
        package = json.load(stream)
    result = validate_capture(package, package_root=manifest.parent, verify_files=args.verify_files)
    print(canonical(result).decode("utf-8"))
    return result


if __name__ == "__main__":
    run_main(main)
