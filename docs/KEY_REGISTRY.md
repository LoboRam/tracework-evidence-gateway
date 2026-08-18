# Public receipt-key registry

Tracework publishes `/.well-known/tracework-receipt-keys.json`. Each entry includes a stable Tracework `key_id`, Ed25519 public key in base64url-encoded SPKI form, activation and optional retirement timestamp, status, and a safe AWS KMS key reference. It contains no AWS credentials or private material.

The verifier selects the public key using the signed receipt's `key_id`. Exactly one registry entry may be active. Retired keys remain present. Revoked keys remain present so affected receipts can be identified and warned on rather than erased.
