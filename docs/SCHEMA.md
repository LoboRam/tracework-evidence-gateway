# Source Reconstruction Packet Schema 2.1.0

The machine-readable snapshot is generated at `schema/reconstruction-packet-2.1.0.schema.json`.

The runtime packet is strict: undocumented top-level and nested properties are rejected. The documentation-only `_enum_reference` object is not accepted.

## Identity

`reconstruction_packet_id`, schema/protocol/provenance versions, project identity, and provider must match trusted server state.

## Coverage perimeter

The packet identifies exactly one accepted reconstruction coverage snapshot and its recovery-pass and manifest IDs. Every pass/manifest must belong to the server-supplied accepted snapshot.

## Provenance index

Each privacy-safe reference includes `ref_id`, pass/manifest identifiers, controlled `source_type` and `source_detail`, generalized date/precision, evidence confidence, and limitations. File paths, arbitrary URLs, raw chat titles, conversation content, private provider identifiers, and credentials are not valid `source_detail` values.

## Evidence collections

The schema contains meaningful moments, human observations, AI observations, decisions, failures/pivots, validation/outcomes, and capability evidence. Every evidence item has a stable ID and one or more references into the packet provenance index.

## Controlled vocabularies

- `source_type`: `direct_retrieval`, `session_history`, `memory_summary`, `artifact_evidence`, `external_unknown`
- provider source `claim_basis`: `owner_reported`, `provider_observed`, `artifact_observed`, `inferred`, `unknown`
- `cross_source_confirmed` is reserved for the Project Compiler and rejected in source packets
- `coverage_confidence`: `strong`, `partial`, `limited`
- `date_precision`: `day`, `month`, `year`, `range`, `unknown`
- `uncertainty`: `none`, `low`, `moderate`, `high`

Arrays and text fields have explicit upper bounds. IDs use a bounded safe character set. Unknown vocabulary values fail closed.
