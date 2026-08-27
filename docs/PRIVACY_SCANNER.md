# Privacy scanner

The gateway scans all candidate string values before acceptance. It rejects patterns consistent with raw multi-turn transcripts, serialized message arrays, prompt/response dumps, fenced or source-like code, repository diffs, bulk file payloads, service/API credentials, bearer tokens, private keys, JWTs, suspicious encoded blobs, private network URLs, email addresses, possible payment cards, and government identifiers.

The scanner is defense in depth, not a universal data-loss-prevention guarantee. Pattern matching can have false positives and cannot prove that every sensitive value has been detected. Strict structure, bounded fields, controlled `source_detail`, server-derived context, project/provider authorization, and source-side sanitization are independent controls.

The scanner rejects any single line longer than 420 characters as `source_sized_line`. This is a code-shape heuristic, not a volume control: fields whose schema forbids newlines are bounded at the same 420 characters, so in those fields the condition is unreachable and the analyst is told about length by the schema instead.

Rejected reconstruction content must not be persisted merely to preserve a diagnostic or hash. Safe diagnostics may include request ID, operation, argument-key names, and rejection category; they must not include candidate values.

A privacy rejection reports each issue as `field path: rejection category`. The path is built from validated schema keys and array indices on the already-parsed strict object, so it carries argument-key names only and never any part of the candidate value. Reporting it is what lets a conforming analyst find and correct the offending field without being shown what was rejected.
