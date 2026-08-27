# Project State Reconstruction Schema 1.0.3

Project State establishes what a local project workspace contains at one inspection point. It is independent from AI conversation history and GitHub history. An AI may perform the inspection, but the evidence source remains the workspace.

## Identity and claims

- Evidence identity: `source_type: project_state`, `source_system: local_project_workspace`, and a Tracework-scoped source ID.
- Analyst: separately declared provider, surface, optional model, and inspection time.
- Authenticated connection: server-recorded outside the packet.
- Allowed claims: directly observed components, inferred architecture, reachability, present-but-inactive code, experimental/obsolete/generated/dead classifications with a stated basis, capability state, and unknowns.
- Disallowed inference: the presence of files does not establish production deployment, customer use, adoption, or commercial success.

## Privacy boundary

The packet has no file-content field. Findings are bounded single-line generalizations. Provenance may contain safe project-relative paths, safe component IDs, observation type, and SHA-256 content fingerprints. Absolute paths, path traversal, credential-bearing filenames, raw source, file contents, credentials, repository internals, and opaque blobs are rejected. Credential/secret files and version-control internals must be excluded from both inspection and fingerprint input.

## Field bounds

Every sanitized single-line field accepts at most 420 characters. That is the same ceiling the privacy scanner applies to any one line, so the published schema bound and the accepted-content boundary are the same number: a packet that satisfies the schema is never rejected for line size afterwards. Over-length prose is a schema error naming the field and the limit, not a privacy rejection.

Length is measured after canonical normalization, which the gateway applies before both schema validation and privacy scanning: NFKC, CRLF and CR to LF, runs of tabs and spaces to one space, and trimmed ends. Analysts should normalize the same way before measuring, or stay clear of the boundary.

A generalization that will not fit is split across findings. Findings are bounded generalizations, not prose containers, and `findings` accepts up to 160 entries.

## Text-field contract

Every string is normalized and then privacy-scanned, but its schema also reflects its role:

- IDs and workspace handles use a bounded identifier alphabet; protocol versions, categories, policies, classifications, and production status use exact literals or enums.
- Timestamps are offset date-times. Fingerprints are lowercase SHA-256 hex values.
- `relative_path` is a single-line safe forward-slash project-relative path. Line breaks, absolute paths, traversal, credential-bearing names, and version-control internals are prohibited.
- `root_label`, analyst `surface`, and analyst `model` are bounded single-line labels, not narrative or payload fields.
- `summary`, finding `statement`, and every inspection, finding, and provenance `limitations` entry are bounded single-line generalized narrative. The same scanner rejects source syntax, fenced code, raw file payloads, transcripts, prompts, diffs, credentials, private URLs, absolute paths, encoded blobs, and other prohibited sensitive shapes in each of these locations.

Limitations may still describe uncertainty, exclusions, or constrained inspection in ordinary prose. Terms such as “function,” “class,” or “export,” and normal punctuation, are not rejected by themselves; source-like syntax and payload structure are.

## Snapshot fingerprint

`tracework.ps.snapshot.sha256-inventory-v1` is deterministic and scope-bound:

1. The local inspector hashes each authorized, non-sensitive file with SHA-256. Raw bytes remain local.
2. Entries are normalized to safe forward-slash project-relative paths and sorted by path.
3. `scope_fingerprint` hashes the canonical scope policy.
4. `path_set_fingerprint` hashes the ordered normalized path set.
5. `inventory_fingerprint` hashes ordered `path NUL size NUL content_sha256` records.
6. `root_fingerprint` hashes the algorithm identity plus the three preceding fingerprints.

Tracework stores only the submitted aggregate fingerprints, safe bounded referenced-file fingerprints, counts, limitations, and sanitized findings. A new inspection creates a new packet/revision; `previous_root_fingerprint` can link it to the earlier inspection without rewriting history.
