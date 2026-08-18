# Privacy scanner

The gateway scans all candidate string values before acceptance. It rejects patterns consistent with raw multi-turn transcripts, serialized message arrays, prompt/response dumps, fenced or source-like code, repository diffs, bulk file payloads, service/API credentials, bearer tokens, private keys, JWTs, suspicious encoded blobs, private network URLs, email addresses, possible payment cards, and government identifiers.

The scanner is defense in depth, not a universal data-loss-prevention guarantee. Pattern matching can have false positives and cannot prove that every sensitive value has been detected. Strict structure, bounded fields, controlled `source_detail`, server-derived context, project/provider authorization, and source-side sanitization are independent controls.

Rejected reconstruction content must not be persisted merely to preserve a diagnostic or hash. Safe diagnostics may include request ID, operation, argument-key names, and rejection category; they must not include candidate values.
