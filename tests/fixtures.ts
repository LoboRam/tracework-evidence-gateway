import { PROVENANCE_SCHEMA_VERSION, RECONSTRUCTION_PACKET_SCHEMA_VERSION, RECONSTRUCTION_PROTOCOL_VERSION } from "../src/constants.js";

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
    },
    provider_limitations: ["This is synthetic test evidence, not a real project reconstruction."],
    privacy_profile: { redactions_applied: [], owner_opted_in_disclosures: [] },
    provider_provenance: { provider: "claude", packet_generated_at: "2026-08-17T12:00:00.000Z" },
  } as const;
}

export function clone<T>(value: T): T { return structuredClone(value); }
