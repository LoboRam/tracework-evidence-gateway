# Release and contract versioning

Gateway package releases use semantic versioning and immutable Git tags. A release records source commit, tag, canonical artifact digest, reconstruction schema/protocol versions, provenance version, and privacy-contract compatibility.

Privacy-contract compatibility increments whenever accepted reconstruction fields, privacy-scanner behavior, authorization preconditions, compiler access, or private/public behavior changes materially. Tightening detection with no accepted-data contract change may use a patch gateway release; new/changed accepted fields require a schema and compatible gateway version update.

Production must depend on an exact released package, never a moving branch. A gateway behavior change is made here, reviewed, released, and then imported by Tracework. There is no private behavior fork.
