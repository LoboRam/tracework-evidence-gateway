import assert from "node:assert/strict";
import test from "node:test";
import {
  PROJECT_STATE_FINGERPRINT_ALGORITHM,
  PROJECT_STATE_RECONSTRUCTION_PROTOCOL_VERSION,
  PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION,
} from "../src/constants.js";
import { acceptProjectStateReconstruction } from "../src/gateway.js";
import { computeProjectStateSnapshotFingerprint } from "../src/project-state.js";

const analyst = { provider: "codex", surface: "Local analyst", model: "synthetic-model" } as const;
const context = { project_id: "project_test", evidence_source_id: "evidence_source_workspace", source_system: "local_project_workspace", analyst } as const;
const inspectedAt = "2026-08-25T12:00:00.000Z";

function validPacket() {
  return {
    packet_id: "project_state_packet_1",
    project_state_reconstruction_schema_version: PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION,
    project_state_reconstruction_protocol_version: PROJECT_STATE_RECONSTRUCTION_PROTOCOL_VERSION,
    project_id: "project_test",
    evidence_source: { architecture_version: 1, source_id: "evidence_source_workspace", source_type: "project_state", source_system: "local_project_workspace", analyst_provider: null },
    inspection: {
      inspection_id: "inspection_1", inspected_at: inspectedAt, workspace_handle: "workspace_opaque_1", root_label: "Synthetic workspace", inspection_method: "local_filesystem",
      snapshot: { fingerprint_algorithm: PROJECT_STATE_FINGERPRINT_ALGORITHM, root_fingerprint: "a".repeat(64), scope_fingerprint: "b".repeat(64), path_set_fingerprint: "c".repeat(64), inventory_fingerprint: "d".repeat(64), fingerprinted_file_count: 3, fingerprinted_directory_count: 2, fingerprinted_total_bytes: 840, previous_root_fingerprint: null },
      scope: { basis: "project_root", excluded_categories: ["credentials_and_secrets", "version_control_internals", "dependency_caches", "binary_contents"], symlink_policy: "do_not_follow", hidden_files_policy: "include_except_sensitive", limitations: ["Unreadable entries would be reported as exclusions."] },
    },
    summary: "The inspected workspace has one reachable application entry point and a separate test package.",
    findings: [{ finding_id: "finding_entry", category: "project_entry_point", statement: "The application entry point is reachable through the declared package start command.", directness: "direct_observation", state_classification: "active_reachable", confidence: "high", provenance_refs: ["ref_package", "ref_entry"], limitations: [], production_status: "not_established" }],
    provenance_index: [
      { ref_id: "ref_package", component_id: "package_manifest", component_kind: "package", relative_path: "package.json", content_fingerprint: "e".repeat(64), observation_basis: "manifest_or_configuration", directness: "direct_observation", observed_at: inspectedAt, limitations: [] },
      { ref_id: "ref_entry", component_id: "application_entry", component_kind: "entry_point", relative_path: "src/index.ts", content_fingerprint: "f".repeat(64), observation_basis: "entry_point_reachability", directness: "direct_observation", observed_at: inspectedAt, limitations: [] },
    ],
    analyst: { ...analyst, inspected_at: inspectedAt },
    privacy: { raw_source_code_included: false, file_contents_included: false, credentials_or_secrets_included: false, absolute_paths_included: false, sanitized_findings_only: true, cryptographic_fingerprints_only: true },
  } as const;
}

test("accepts deterministic sanitized Project State evidence with separate source and analyst identity", async () => {
  const first = await acceptProjectStateReconstruction(validPacket(), context);
  const second = await acceptProjectStateReconstruction(validPacket(), context);
  assert.equal(first.status, "accept", JSON.stringify(first)); assert.equal(second.status, "accept", JSON.stringify(second));
  if (first.status === "accept" && second.status === "accept") {
    assert.equal(first.accepted.accepted_packet_digest, second.accepted.accepted_packet_digest);
    assert.equal(first.accepted.packet.evidence_source.analyst_provider, null);
    assert.equal(first.accepted.packet.analyst.provider, "codex");
  }
});

test("rejects identity confusion, absolute or secret paths, file content, and production claims", async () => {
  const cases: Array<(packet: any) => void> = [
    (packet) => { packet.evidence_source.source_type = "ai_history"; },
    (packet) => { packet.evidence_source.source_system = "codex"; },
    (packet) => { packet.analyst.provider = "claude"; },
    (packet) => { packet.provenance_index[0].relative_path = "C:/private/project/package.json"; },
    (packet) => { packet.provenance_index[0].relative_path = ".env.production"; },
    (packet) => { packet.file_contents = "short raw content"; },
    (packet) => { packet.findings[0].production_status = "deployed"; },
    (packet) => { packet.findings[0].statement = "Customer adoption and commercial success are proven."; packet.findings[0].production_status = "production_deployed"; },
  ];
  for (const mutate of cases) { const packet: any = structuredClone(validPacket()); mutate(packet); assert.equal((await acceptProjectStateReconstruction(packet, context)).status, "reject"); }
});

test("requires explicit uncertainty for experimental, obsolete, and dead classifications", async () => {
  const packet: any = structuredClone(validPacket()); packet.findings[0].category = "dead_code"; packet.findings[0].state_classification = "dead";
  assert.equal((await acceptProjectStateReconstruction(packet, context)).status, "reject");
  packet.findings[0].limitations = ["No import or configured entry-point path reached this component within the bounded static analysis."];
  const accepted = await acceptProjectStateReconstruction(packet, context); assert.equal(accepted.status, "accept", JSON.stringify(accepted));
});

test("snapshot fingerprints are order-independent, scope-bound, and content-sensitive", async () => {
  const scope = { basis: "project_root", excluded_categories: ["credentials_and_secrets", "version_control_internals"], symlink_policy: "do_not_follow", hidden_files_policy: "include_except_sensitive" } as const;
  const entries = [{ relative_path: "src/index.ts", size_bytes: 10, content_sha256: "a".repeat(64) }, { relative_path: "package.json", size_bytes: 20, content_sha256: "b".repeat(64) }];
  const first = await computeProjectStateSnapshotFingerprint(scope, entries); const reordered = await computeProjectStateSnapshotFingerprint(scope, [...entries].reverse());
  assert.deepEqual(first, reordered);
  const changed = await computeProjectStateSnapshotFingerprint(scope, [{ ...entries[0]!, content_sha256: "c".repeat(64) }, entries[1]!]);
  assert.notEqual(first.root_fingerprint, changed.root_fingerprint);
  const narrower = await computeProjectStateSnapshotFingerprint({ ...scope, basis: "authorized_subtree" }, entries);
  assert.notEqual(first.root_fingerprint, narrower.root_fingerprint);
});

test("snapshot fingerprints bind directory inventory and mandatory privacy exclusions", async () => {
  const scope = { basis: "project_root", excluded_categories: ["credentials_and_secrets", "version_control_internals"], symlink_policy: "do_not_follow", hidden_files_policy: "include_except_sensitive" } as const;
  const entries = [{ relative_path: "src/index.ts", size_bytes: 12, content_sha256: "a".repeat(64) }];
  const withoutDirectory = await computeProjectStateSnapshotFingerprint(scope, entries);
  const withDirectory = await computeProjectStateSnapshotFingerprint(scope, entries, ["src", "empty"]);
  assert.notEqual(withoutDirectory.root_fingerprint, withDirectory.root_fingerprint);
  assert.equal(withDirectory.fingerprinted_directory_count, 2);
  await assert.rejects(() => computeProjectStateSnapshotFingerprint({ ...scope, excluded_categories: ["version_control_internals"] }, entries), /must exclude credentials/i);
});
