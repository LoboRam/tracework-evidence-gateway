import { PROJECT_STATE_FINGERPRINT_ALGORITHM, PROJECT_STATE_RECONSTRUCTION_PROTOCOL_VERSION, PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION, PROVENANCE_SCHEMA_VERSION, RECONSTRUCTION_PACKET_SCHEMA_VERSION, RECONSTRUCTION_PROTOCOL_VERSION } from "../src/constants.js";

export function validContext() {
  return {
    project_id: "project_test",
    project_name: "Synthetic Project",
    expected_provider: "claude",
    accepted_reconstruction_coverage_snapshot_id: "snapshot_1",
    allowed_recovery_pass_ids: ["pass_1"],
    allowed_manifest_ids: ["manifest_1"],
    reconstruction_packet_schema_version: RECONSTRUCTION_PACKET_SCHEMA_VERSION,
    reconstruction_protocol_version: RECONSTRUCTION_PROTOCOL_VERSION,
    provenance_schema_version: PROVENANCE_SCHEMA_VERSION,
  } as const;
}

export function validPacket() {
  const date = { value: "2026-04", label: "April 2026", precision: "month" } as const;
  return {
    reconstruction_packet_id: "packet_1",
    reconstruction_packet_schema_version: RECONSTRUCTION_PACKET_SCHEMA_VERSION,
    reconstruction_protocol_version: RECONSTRUCTION_PROTOCOL_VERSION,
    provenance_schema_version: PROVENANCE_SCHEMA_VERSION,
    project_id: "project_test",
    project_name: "Synthetic Project",
    provider: "claude",
    coverage_perimeter: {
      accepted_reconstruction_coverage_snapshot_id: "snapshot_1",
      recovery_pass_ids: ["pass_1"],
      manifest_ids: ["manifest_1"],
      earliest_date: date,
      latest_date: date,
      coverage_confidence: "partial",
      limitations: ["Synthetic coverage is intentionally partial."],
    },
    project_summary: { description: "A synthetic project used only for public gateway validation tests.", claim_basis: "provider_observed" },
    provenance_index: [{ ref_id: "ref_1", recovery_pass_id: "pass_1", manifest_id: "manifest_1", source_type: "direct_retrieval", source_detail: "claude_regular_chat_search", date, confidence: "Strong", limitations: [] }],
    evidence: {
      meaningful_moments: [{ evidence_id: "event_1", title: "Constraint identified", description: "The builder identified a boundary that changed the implementation direction.", uncertainty: "low", evidence_refs: ["ref_1"], date, resulting_state: "The implementation followed the documented boundary." }],
      human_observations: [{ evidence_id: "human_1", description: "The builder rejected an approach that violated the project constraint.", uncertainty: "low", evidence_refs: ["ref_1"], observation_type: "rejection" }],
      ai_observations: [{ evidence_id: "ai_1", description: "The AI proposed the initial implementation approach.", uncertainty: "low", evidence_refs: ["ref_1"], observation_type: "proposal" }],
      decisions: [{ evidence_id: "decision_1", description: "A constrained design was selected.", uncertainty: "low", evidence_refs: ["ref_1"], decision_type: "architecture", outcome: "The design respected the project boundary." }],
      failures_and_pivots: [],
      validation_and_outcomes: [{ evidence_id: "validation_1", description: "The boundary was tested with a synthetic fixture.", uncertainty: "low", evidence_refs: ["ref_1"], validation_method: "Synthetic schema and privacy tests.", outcome: "The fixture passed without raw source material." }],
      capability_evidence: [{ evidence_id: "capability_1", description: "The rejection demonstrated observable tradeoff reasoning.", uncertainty: "moderate", evidence_refs: ["ref_1"], capability: "Tradeoff Reasoning", strength: "Moderate", narrative_basis: "A consequential alternative was rejected against a documented constraint." }],
      origin_traces: [{ evidence_id: "origin_1", description: "The design boundary first appears as a builder-supplied constraint.", uncertainty: "low", evidence_refs: ["ref_1"], concept_key: "design_boundary", first_observed_as: "human_input", generalized_basis: "The available provider evidence first observes the constraint in builder input.", confidence: "high" }],
    },
    provider_limitations: ["This is synthetic test evidence, not a real project reconstruction."],
    privacy_profile: { redactions_applied: [], owner_opted_in_disclosures: [] },
    provider_provenance: { provider: "claude", packet_generated_at: "2026-08-17T12:00:00.000Z" },
  } as const;
}

export function clone<T>(value: T): T { return structuredClone(value); }

export type AnalystProvider = "chatgpt" | "claude" | "codex" | "other";

export const PROJECT_STATE_INSPECTED_AT = "2026-08-25T12:00:00.000Z";

export function generalizedProse(length: number): string {
  let output = "the inspected ";
  while (output.length < length) output += "workspace ";
  return `${output.slice(0, length - 1).replace(/ $/, "w")}.`;
}

export function projectStateAnalyst(provider: AnalystProvider) {
  return { provider, surface: "Generic local analyst", model: "generic-analyst-model" } as const;
}

export function projectStateContext(provider: AnalystProvider) {
  return { project_id: "project_test", evidence_source_id: "evidence_source_workspace", source_system: "local_project_workspace", analyst: projectStateAnalyst(provider) } as const;
}

export function projectStatePacket(provider: AnalystProvider) {
  const observedAt = PROJECT_STATE_INSPECTED_AT;
  return {
    packet_id: "project_state_packet_generic",
    project_state_reconstruction_schema_version: PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION,
    project_state_reconstruction_protocol_version: PROJECT_STATE_RECONSTRUCTION_PROTOCOL_VERSION,
    project_id: "project_test",
    evidence_source: { architecture_version: 1, source_id: "evidence_source_workspace", source_type: "project_state", source_system: "local_project_workspace", analyst_provider: null },
    inspection: {
      inspection_id: "inspection_generic",
      inspected_at: observedAt,
      workspace_handle: "workspace_opaque_generic",
      root_label: "Generic workspace",
      inspection_method: "mounted_project_workspace",
      snapshot: { fingerprint_algorithm: PROJECT_STATE_FINGERPRINT_ALGORITHM, root_fingerprint: "1".repeat(64), scope_fingerprint: "2".repeat(64), path_set_fingerprint: "3".repeat(64), inventory_fingerprint: "4".repeat(64), fingerprinted_file_count: 4, fingerprinted_directory_count: 2, fingerprinted_total_bytes: 2048, previous_root_fingerprint: null },
      scope: { basis: "project_root", excluded_categories: ["credentials_and_secrets", "version_control_internals", "dependency_caches"], symlink_policy: "do_not_follow", hidden_files_policy: "include_except_sensitive", limitations: ["Dependency caches were excluded from inspection and fingerprinting."] },
    },
    summary: "The inspected workspace declares one reachable entry point, a configured pipeline, and a separate test package.",
    findings: [
      { finding_id: "finding_entry", category: "project_entry_point", statement: "The declared package start command reaches a single application entry point.", directness: "direct_observation", state_classification: "active_reachable", confidence: "high", provenance_refs: ["ref_manifest", "ref_entry"], limitations: [], production_status: "not_established" },
      { finding_id: "finding_unreferenced", category: "major_module_or_component", statement: "A sibling module is present but no configured profile references it, so its reachability was not established.", directness: "inferred_architecture", state_classification: "present_reachability_unknown", confidence: "medium", provenance_refs: ["ref_module"], limitations: ["Reachability was assessed from manifest and reference signals within the bounded scope."], production_status: "not_established" },
    ],
    provenance_index: [
      { ref_id: "ref_manifest", component_id: "package_manifest", component_kind: "package", relative_path: "package.json", content_fingerprint: "5".repeat(64), observation_basis: "manifest_or_configuration", directness: "direct_observation", observed_at: observedAt, limitations: [] },
      { ref_id: "ref_entry", component_id: "application_entry", component_kind: "entry_point", relative_path: "src/index.ts", content_fingerprint: "6".repeat(64), observation_basis: "entry_point_reachability", directness: "direct_observation", observed_at: observedAt, limitations: [] },
      { ref_id: "ref_module", component_id: "sibling_module", component_kind: "module", relative_path: "src/sibling.ts", content_fingerprint: "7".repeat(64), observation_basis: "import_or_reference_graph", directness: "inferred_relationship", observed_at: observedAt, limitations: [] },
    ],
    analyst: { ...projectStateAnalyst(provider), inspected_at: observedAt },
    privacy: { raw_source_code_included: false, file_contents_included: false, credentials_or_secrets_included: false, absolute_paths_included: false, sanitized_findings_only: true, cryptographic_fingerprints_only: true },
  };
}
