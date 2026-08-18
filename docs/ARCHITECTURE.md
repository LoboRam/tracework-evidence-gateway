# Architecture

## Sole application-level intake boundary

The production historical-reconstruction path is:

1. Private Tracework authenticates the OAuth bearer request.
2. Private Tracework verifies ownership, provider attachment, active reconstruction state, and the accepted coverage snapshot.
3. Private Tracework constructs `TrustedGatewayContext` from database state. The candidate packet is not persisted, logged by value, analyzed, or sent to the compiler.
4. `acceptHistoricalReconstruction(candidate, trustedContext)` in this package validates the candidate.
5. The gateway strictly parses Schema 2.1.0, validates identity, provider, coverage perimeter, provenance and references, runs the public privacy scanner, and canonicalizes the accepted packet.
6. A rejection returns only a safe category and bounded issue labels. It cannot produce canonical accepted evidence.
7. On acceptance, the private persistence adapter receives only the branded `CanonicalAcceptedPacket` returned by this package.
8. Tracework persists the canonical packet immutably and creates an Evidence Receipt binding its digest to the released gateway provenance.

Private Tracework may authenticate, authorize, rate-limit, look up state, and persist accepted output. It must not contain a parallel reconstruction schema, privacy scanner, canonicalizer, or accepted-packet generator.

## Trust boundary

`TrustedGatewayContext` is server-derived. It binds the authenticated request to a project name/ID, expected provider, accepted Reconstruction Coverage Snapshot, allowed pass/manifest IDs, and protocol versions. Browser fields and source-supplied identity do not establish this context.

The gateway is deliberately database-independent. This prevents validation logic from becoming coupled to private storage and makes synthetic public tests deterministic.

## Failure

Loading failure, exceptions, version mismatch, malformed schema, privacy detection, identity mismatch, invalid provenance, or an unknown validation state rejects the request. There is no availability bypass.
