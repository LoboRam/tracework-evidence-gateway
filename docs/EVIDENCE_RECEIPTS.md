# Evidence Receipts

An Evidence Receipt attests that Tracework accepted a canonical packet digest under a particular gateway release at a particular time. It does not prove that infrastructure could not operationally observe a request, that the source evidence is true, or that Tracework has passed an independent audit.

Receipt claims are strictly parsed, deterministically key-sorted JSON encoded as UTF-8, and signed directly as an Ed25519 message. Claims bind receipt and project-safe IDs, provider, operation, accepted timestamp, coverage snapshot, gateway version/source commit/release/artifact digest, privacy-contract version, canonical packet digest, submission channel, and signing `key_id`.

Production uses an asymmetric Ed25519 key in AWS KMS (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`, `MessageType: RAW`). The private key is generated and retained by KMS and is not exported to Tracework. A restricted runtime AWS credential may authorize `kms:Sign` on the exact active key; that credential is security-sensitive even though it is not private key material.

The public registry supports `active`, `retired`, and `revoked`. Rotation creates a new KMS key. Old receipt signatures remain verifiable with retained public keys. `retired` means the key no longer signs new Tracework receipts. `revoked` means the verifier can still identify the historical signature but must warn that the key is no longer trusted because of a suspected or confirmed security condition.

Receipts are immutable and are never silently re-signed.
