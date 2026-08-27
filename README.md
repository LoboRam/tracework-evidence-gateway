# Tracework Evidence Gateway

This repository contains the actual security-critical evidence-ingestion implementation consumed by Tracework production. It is not a sample, reference, mock, or documentation-only implementation.

The gateway is the exclusive application-level authority deciding which historical reconstruction content may cross into Tracework evidence storage. The proprietary application authenticates a request, resolves project and recovery state, and supplies a narrow trusted context. This package strictly validates the candidate Source Reconstruction Packet, rejects prohibited data, verifies provenance and coverage references, canonicalizes an accepted packet, and returns a branded accepted result. Persistence receives only that canonical accepted result.

Tracework production is not wholly open source. Authentication, account/project state, deployment, and persistence remain private application concerns. This package does not prove what hosting infrastructure may operationally observe. It makes the application evidence boundary inspectable and reproducible.

## Public contract

- License: [MPL-2.0](LICENSE)
- Reconstruction Packet Schema: `2.1.0`
- Historical Reconstruction Protocol: `historical-0.4`
- Provenance Schema: `1.0.0`
- Project State Reconstruction Schema: `1.0.2`
- Project State Reconstruction Protocol: `project-state-1.0`
- Snapshot fingerprint algorithm: `tracework.ps.snapshot.sha256-inventory-v1`
- Privacy-contract compatibility: `2.0.2`
- Receipt algorithm: Ed25519, with production signing performed through AWS KMS

See [Architecture](docs/ARCHITECTURE.md), [Schema](docs/SCHEMA.md), [Privacy scanner](docs/PRIVACY_SCANNER.md), [Canonical artifact](docs/REPRODUCIBLE_BUILD.md), and [Evidence Receipts](docs/EVIDENCE_RECEIPTS.md).

## Local verification

```sh
npm ci
npm run typecheck
npm run lint
npm test
npm run schema:snapshot
npm run build
npm run verify:reproducible
```

The canonical artifact is `artifact/tracework-evidence-gateway.canonical.json`. `artifact/SHA256SUMS` contains the SHA-256 over those exact bytes.

To compare a clean local artifact with the running service:

```sh
npm run verify:tracework -- --artifact artifact/tracework-evidence-gateway.canonical.json
```

To verify a downloaded owner Evidence Receipt:

```sh
npm run verify:tracework -- --receipt path/to/receipt.json
```

No Tracework credentials are required for public provenance or receipt signature verification.

## Security reporting

Please do not put private project evidence, credentials, or exploit payloads in a public issue. Use GitHub's private vulnerability-reporting channel when enabled, or contact the Tracework owner through the service's published security contact.
