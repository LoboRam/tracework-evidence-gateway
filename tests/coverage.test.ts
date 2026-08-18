import assert from "node:assert/strict";
import test from "node:test";
import { acceptSourceCoverageManifest } from "../src/gateway.js";

const context = { project_id: "project_test", expected_provider: "claude", active_recovery_pass_id: "pass_1", recovery_profile_version: "2026-08-17T12:00:00.000Z" } as const;
const manifest = { protocol_version: "recovery-0.1", project_id: "project_test", provider: "claude", coverage: "partial", historical_range: { start: "2026-04", end: "2026-04", label: "April 2026", precision: "month" }, candidate_contexts: 15, context_unit: "chats", search_tiers_used: ["exact_identity"], matched_signals: ["Synthetic Project"], coverage_notes: ["Project-scoped history was available."], limitations: ["Regular chats were outside this pass."], remaining_gaps: ["Regular chats remain unsearched."], relevant_history_found: true, history_may_be_missing: true, source_scope_reference: "claude_project_chat_search", searched_at: "2026-08-17T12:00:00.000Z" } as const;

test("coverage manifest acceptance is strict, privacy scanned, and deterministic", async () => {
  const first = await acceptSourceCoverageManifest(manifest, context);
  const second = await acceptSourceCoverageManifest(manifest, context);
  assert.equal(first.status, "accept"); assert.equal(second.status, "accept");
  if (first.status === "accept" && second.status === "accept") assert.equal(first.accepted_manifest_digest, second.accepted_manifest_digest);
});

test("coverage manifest rejects provider mismatch, raw history, and unknown fields", async () => {
  assert.equal((await acceptSourceCoverageManifest({ ...manifest, provider: "chatgpt" }, context)).status, "reject");
  assert.equal((await acceptSourceCoverageManifest({ ...manifest, coverage_notes: ["User: private source request here\nAssistant: private response material here"] }, context)).status, "reject");
  assert.equal((await acceptSourceCoverageManifest({ ...manifest, raw_chat: "not accepted" }, context)).status, "reject");
});
