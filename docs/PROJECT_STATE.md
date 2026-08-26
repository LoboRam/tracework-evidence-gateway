# Project State Reconstruction 1.0

Project State establishes what a local project workspace contains at one inspection point. It is independent from AI conversation history and GitHub history. An AI may perform the inspection, but the evidence source remains the workspace.

## Identity and claims

- Evidence identity: `source_type: project_state`, `source_system: local_project_workspace`, and a Tracework-scoped source ID.
- Analyst: separately declared provider, surface, optional model, and inspection time.
- Authenticated connection: server-recorded outside the packet.
- Allowed claims: directly observed components, inferred architecture, reachability, present-but-inactive code, experimental/obsolete/generated/dead classifications with a stated basis, capability state, and unknowns.
- Disallowed inference: the presence of files does not establish production deployment, customer use, adoption, or commercial success.

## Privacy boundary

The packet has no file-content field. Findings are bounded single-line generalizations. Provenance may contain safe project-relative paths, safe component IDs, observation type, and SHA-256 content fingerprints. Absolute paths, path traversal, credential-bearing filenames, raw source, file contents, credentials, repository internals, and opaque blobs are rejected. Credential/secret files and version-control internals must be excluded from both inspection and fingerprint input.

## Snapshot fingerprint

`tracework.ps.snapshot.sha256-merkle-v1` is deterministic and scope-bound:

1. The local inspector hashes each authorized, non-sensitive file with SHA-256. Raw bytes remain local.
2. Entries are normalized to safe forward-slash project-relative paths and sorted by path.
3. `scope_fingerprint` hashes the canonical scope policy.
4. `path_set_fingerprint` hashes the ordered normalized path set.
5. `inventory_fingerprint` hashes ordered `path NUL size NUL content_sha256` records.
6. `root_fingerprint` hashes the algorithm identity plus the three preceding fingerprints.

Tracework stores only the submitted aggregate fingerprints, safe bounded referenced-file fingerprints, counts, limitations, and sanitized findings. A new inspection creates a new packet/revision; `previous_root_fingerprint` can link it to the earlier inspection without rewriting history.
