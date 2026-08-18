import { z } from "zod";
import { PROVENANCE_SCHEMA_VERSION, RECONSTRUCTION_PACKET_SCHEMA_VERSION, RECONSTRUCTION_PROTOCOL_VERSION } from "./constants.js";

const safeId = z.string().trim().min(1).max(120).regex(/^[A-Za-z0-9._:-]+$/);
const shortText = z.string().trim().min(1).max(500);
const mediumText = z.string().trim().min(1).max(2_000);
const limitationText = z.string().trim().min(1).max(500);

export const providerSchema = z.enum(["chatgpt", "claude", "codex", "other", "manual"]);
export const sourceTypeSchema = z.enum(["direct_retrieval", "session_history", "memory_summary", "artifact_evidence", "external_unknown"]);
export const claimBasisSchema = z.enum(["owner_reported", "provider_observed", "artifact_observed", "inferred", "unknown"]);
export const coverageConfidenceSchema = z.enum(["strong", "partial", "limited"]);
export const datePrecisionSchema = z.enum(["day", "month", "year", "range", "unknown"]);
export const uncertaintySchema = z.enum(["none", "low", "moderate", "high"]);
export const evidenceStrengthSchema = z.enum(["Strong", "Moderate", "Limited"]);
export const sourceDetailSchema = z.enum(["claude_project_chat_search", "claude_regular_chat_search", "chatgpt_history_search", "chatgpt_project_search", "codex_persisted_thread", "codex_cli_session", "codex_vscode_session", "provider_memory_summary", "owner_supplied_artifact_observation", "external_or_unknown_scope"]);

export const capabilitySchema = z.enum([
  "Problem Definition", "Requirements Definition", "Planning", "Systems Thinking", "Architecture", "Tradeoff Reasoning", "AI Orchestration", "Critical AI Evaluation", "Debugging", "Root-Cause Analysis", "Experiment Design", "Validation", "Quality Control", "Risk Identification", "Integration", "Product Thinking", "User Experience Judgment", "Research / Evidence Evaluation", "Communication / Specification",
]);

export const historicalDateSchema = z.object({ value: z.string().trim().max(80).optional(), label: z.string().trim().min(1).max(120), precision: datePrecisionSchema }).strict().superRefine((date, context) => {
  const value = date.value ?? "";
  if (date.precision === "day" && !/^\d{4}-\d{2}-\d{2}$/.test(value)) context.addIssue({ code: "custom", path: ["value"], message: "Day precision requires YYYY-MM-DD" });
  if (date.precision === "month" && !/^\d{4}-\d{2}$/.test(value)) context.addIssue({ code: "custom", path: ["value"], message: "Month precision requires YYYY-MM" });
  if (date.precision === "year" && !/^\d{4}$/.test(value)) context.addIssue({ code: "custom", path: ["value"], message: "Year precision requires YYYY" });
  if (date.precision === "range" && (value.length < 3 || value.length > 80)) context.addIssue({ code: "custom", path: ["value"], message: "Range precision requires a bounded generalized range" });
  if (date.precision === "unknown" && value) context.addIssue({ code: "custom", path: ["value"], message: "Unknown precision cannot include a value" });
});

export const provenanceReferenceSchema = z.object({ ref_id: safeId, recovery_pass_id: safeId, manifest_id: safeId, source_type: sourceTypeSchema, source_detail: sourceDetailSchema, date: historicalDateSchema, confidence: evidenceStrengthSchema, limitations: z.array(limitationText).max(8) }).strict();
const evidenceBase = { evidence_id: safeId, description: mediumText, uncertainty: uncertaintySchema, evidence_refs: z.array(safeId).min(1).max(24) };
const meaningfulMomentSchema = z.object({ ...evidenceBase, title: z.string().trim().min(1).max(160), date: historicalDateSchema, resulting_state: z.string().trim().min(1).max(1_200) }).strict();
const humanObservationSchema = z.object({ ...evidenceBase, observation_type: z.enum(["objective", "requirement", "constraint", "decision", "challenge", "correction", "rejection", "diagnosis", "redirection", "validation", "integration", "specification", "other_supported_judgment"]) }).strict();
const aiObservationSchema = z.object({ ...evidenceBase, observation_type: z.enum(["proposal", "research", "implementation", "debugging", "testing", "analysis", "autonomous_execution", "other_ai_activity"]) }).strict();
const decisionSchema = z.object({ ...evidenceBase, decision_type: z.enum(["architecture", "tradeoff", "scope", "product", "risk", "quality", "integration", "experiment", "other"]), outcome: mediumText }).strict();
const pivotSchema = z.object({ ...evidenceBase, previous_direction: mediumText, changed_direction: mediumText, trigger: mediumText }).strict();
const validationOutcomeSchema = z.object({ ...evidenceBase, validation_method: mediumText, outcome: mediumText }).strict();
const capabilityEvidenceSchema = z.object({ ...evidenceBase, capability: capabilitySchema, strength: evidenceStrengthSchema, narrative_basis: mediumText }).strict();
const originTraceSchema = z.object({ ...evidenceBase, concept_key: safeId, first_observed_as: z.enum(["human_input", "ai_proposal", "preexisting_context", "uncertain"]), generalized_basis: mediumText, confidence: z.enum(["high", "medium", "low"]) }).strict();

export const sourceReconstructionPacketSchema = z.object({
  reconstruction_packet_id: safeId,
  reconstruction_packet_schema_version: z.literal(RECONSTRUCTION_PACKET_SCHEMA_VERSION),
  reconstruction_protocol_version: z.literal(RECONSTRUCTION_PROTOCOL_VERSION),
  provenance_schema_version: z.literal(PROVENANCE_SCHEMA_VERSION),
  project_id: safeId,
  project_name: z.string().trim().min(1).max(160),
  provider: providerSchema,
  coverage_perimeter: z.object({ accepted_reconstruction_coverage_snapshot_id: safeId, recovery_pass_ids: z.array(safeId).min(1).max(32), manifest_ids: z.array(safeId).min(1).max(32), earliest_date: historicalDateSchema, latest_date: historicalDateSchema, coverage_confidence: coverageConfidenceSchema, limitations: z.array(limitationText).max(16) }).strict(),
  project_summary: z.object({ description: mediumText, claim_basis: claimBasisSchema }).strict(),
  provenance_index: z.array(provenanceReferenceSchema).min(1).max(240),
  evidence: z.object({ meaningful_moments: z.array(meaningfulMomentSchema).min(1).max(80), human_observations: z.array(humanObservationSchema).max(160), ai_observations: z.array(aiObservationSchema).max(160), decisions: z.array(decisionSchema).max(120), failures_and_pivots: z.array(pivotSchema).max(80), validation_and_outcomes: z.array(validationOutcomeSchema).max(120), capability_evidence: z.array(capabilityEvidenceSchema).max(80), origin_traces: z.array(originTraceSchema).max(160) }).strict(),
  provider_limitations: z.array(limitationText).max(20),
  privacy_profile: z.object({ redactions_applied: z.array(z.enum(["raw_conversation", "prompt_content", "source_code", "file_content", "credential", "personal_identifier", "private_url", "provider_identifier", "other"])).max(16), owner_opted_in_disclosures: z.array(z.string().trim().min(1).max(240)).max(8) }).strict(),
  provider_provenance: z.object({ provider: providerSchema, packet_generated_at: z.string().datetime({ offset: true }) }).strict(),
}).strict();

export const trustedGatewayContextSchema = z.object({
  project_id: safeId,
  project_name: z.string().trim().min(1).max(160),
  expected_provider: providerSchema,
  accepted_reconstruction_coverage_snapshot_id: safeId,
  allowed_recovery_pass_ids: z.array(safeId).min(1).max(32),
  allowed_manifest_ids: z.array(safeId).min(1).max(32),
  reconstruction_packet_schema_version: z.literal(RECONSTRUCTION_PACKET_SCHEMA_VERSION),
  reconstruction_protocol_version: z.literal(RECONSTRUCTION_PROTOCOL_VERSION),
  provenance_schema_version: z.literal(PROVENANCE_SCHEMA_VERSION),
}).strict();

export type SourceReconstructionPacket = z.infer<typeof sourceReconstructionPacketSchema>;
export type TrustedGatewayContext = z.infer<typeof trustedGatewayContextSchema>;
