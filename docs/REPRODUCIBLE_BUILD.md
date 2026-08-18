# Reproducible canonical artifact

The canonical artifact is a UTF-8 JSON document followed by exactly one LF byte. It has this shape:

```json
{"format":"tracework-evidence-gateway-canonical-v1","hashing_algorithm":"SHA-256","included_files":[...]}
```

`included_files` contains every TypeScript-produced `.js` and `.d.ts` file in `dist`, except generated `provenance.js` and `provenance.d.ts`, ordered by POSIX-style relative path using an English ordinal comparison. Each entry contains the relative path, SHA-256 of the exact compiled bytes, and those exact bytes encoded as base64.

Generated runtime provenance is excluded to avoid a self-referential digest. It is produced after the canonical digest and reports the checked-out source commit, exact release tag, canonical artifact digest, and protocol versions. The canonical artifact includes the implementation that generates and validates gateway results and receipts; it excludes dependencies and package-manager metadata.

Rebuild from a clean tagged checkout:

```sh
git clone https://github.com/LoboRam/tracework-evidence-gateway.git
cd tracework-evidence-gateway
git checkout evidence-gateway-v1.0.0
npm ci
npm run typecheck
npm test
npm run build
npm run verify:reproducible
```

The SHA-256 printed by the final two commands must equal the release digest and the running Tracework runtime-provenance digest. A mismatch is a failed verification, not an acceptable build variation.
