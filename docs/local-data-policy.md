# Local data policy

The following categories must remain on the local machine and must not be committed:

- target executables, launchers, packages, and protection components;
- extracted assets, audio, shaders, metadata, disassembly, and memory snapshots;
- runtime captures, screenshots, frame dumps, logs, indices, and databases;
- target-specific plans, names, addresses, hashes, signatures, and findings;
- external tools or dependencies downloaded for local analysis;
- source assets and prototype projects containing third-party material.

Only generic recorder source, generic tests using owned fixtures, public schemas, and non-target-specific documentation belong in the Git repository.

Before every push, inspect both `git status` and the complete staged-file list. Do not use `git add -f` to bypass these rules.
