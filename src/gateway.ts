import { GATEWAY_ACCEPTANCE_BRAND, GATEWAY_PACKAGE_VERSION, PRIVACY_CONTRACT_COMPATIBILITY, PROVENANCE_SCHEMA_VERSION, RECONSTRUCTION_PACKET_SCHEMA_VERSION, RECONSTRUCTION_PROTOCOL_VERSION } from "./constants.js";
import { canonicalize, normalizeProtocolPayload, sha256Hex } from "./canonical.js";
import { privacyIssuesFor } from "./privacy.js";
import { sourceCoverageManifestSchema, sourceReconstructionPacketSchema, trustedCoverageContextSchema, trustedGatewayContextSchema, type SourceCoverageManifest, type SourceReconstructionPacket, type TrustedGatewayContext } from "./schema.js";
import { projectStateReconstructionPacketSchema, trustedProjectStateContextSchema, type ProjectStateReconstructionPacket, type TrustedProjectStateContext } from "./project-state.js";
import { PROJECT_STATE_RECONSTRUCTION_PROTOCOL_VERSION, PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION } from "./constants.js";

export type GatewayRejectionCategory =
  | "invalid_trusted_context"
  | "invalid_schema"
  | "identity_mismatch"
  | "coverage_mismatch"
  | "reference_integrity"
  | "privacy_rejection"
  | "gateway_failure";

export type GatewayValidationMetadata = Readonly<{
  gateway_package_version: string;
  reconstruction_packet_schema_version: string;
  reconstruction_protocol_version: string;
  provenance_schema_version: string;
  privacy_contract_compatibility: string;
  normalized: true;
  privacy_scan: "passed";
  provenance_validation: "passed";
  reference_validation: "passed";
}>;
type GatewayRejection = Readonly<{ status: "reject"; category: GatewayRejectionCategory; issues: readonly string[] }>;

export type CanonicalAcceptedPacket = Readonly<{
  readonly __tracework_gateway_acceptance: typeof GATEWAY_ACCEPTANCE_BRAND;
  readonly packet: SourceReconstructionPacket;
  readonly canonical_packet: string;
  readonly accepted_packet_digest: string;
  readonly validation_metadata: GatewayValidationMetadata;
}>;

export type GatewayResult =
  | Readonly<{ status: "accept"; accepted: CanonicalAcceptedPacket }>
  | GatewayRejection;

export type CoverageGatewayResult =
  | Readonly<{ status: "accept"; manifest: SourceCoverageManifest; canonical_manifest: string; accepted_manifest_digest: string }>
  | GatewayRejection;

export type CanonicalAcceptedProjectStatePacket = Readonly<{
  readonly __tracework_gateway_acceptance: typeof GATEWAY_ACCEPTANCE_BRAND;
  readonly packet: ProjectStateReconstructionPacket;
  readonly canonical_packet: string;
  readonly accepted_packet_digest: string;
  readonly validation_metadata: Readonly<{
    gateway_package_version: string;
    project_state_reconstruction_schema_version: string;
    project_state_reconstruction_protocol_version: string;
    privacy_contract_compatibility: string;
    normalized: true;
    privacy_scan: "passed";
    provenance_validation: "passed";
    snapshot_validation: "passed";
  }>;
}>;

export type ProjectStateGatewayResult = Readonly<{ status: "accept"; accepted: CanonicalAcceptedProjectStatePacket }> | GatewayRejection;

function reject(category: GatewayRejectionCategory, issues: readonly string[]): GatewayRejection {
  return { status: "reject", category, issues: [...new Set(issues)].slice(0, 64) };
}

function validateIdentity(packet: SourceReconstructionPacket, context: TrustedGatewayContext): string[] {
  const issues: string[] = [];
  if (packet.project_id !== context.project_id) issues.push("project_id does not match trusted context");
  if (packet.project_name !== context.project_name) issues.push("project_name does not match trusted context");
  if (packet.provider !== context.expected_provider) issues.push("provider does not match authenticated attachment");
  if (packet.provider_provenance.provider !== context.expected_provider) issues.push("provider provenance does not match authenticated attachment");
  if (packet.reconstruction_packet_schema_version !== context.reconstruction_packet_schema_version) issues.push("reconstruction schema version mismatch");
  if (packet.reconstruction_protocol_version !== context.reconstruction_protocol_version) issues.push("reconstruction protocol version mismatch");
  if (packet.provenance_schema_version !== context.provenance_schema_version) issues.push("provenance schema version mismatch");
  return issues;
}

function validateCoverage(packet: SourceReconstructionPacket, context: TrustedGatewayContext): string[] {
  const perimeter = packet.coverage_perimeter;
  const issues: string[] = [];
  if (perimeter.accepted_reconstruction_coverage_snapshot_id !== context.accepted_reconstruction_coverage_snapshot_id) issues.push("coverage snapshot does not match active reconstruction");
  const allowedPasses = new Set(context.allowed_recovery_pass_ids);
  const allowedManifests = new Set(context.allowed_manifest_ids);
  if (new Set(perimeter.recovery_pass_ids).size !== perimeter.recovery_pass_ids.length) issues.push("duplicate recovery pass ID");
  if (new Set(perimeter.manifest_ids).size !== perimeter.manifest_ids.length) issues.push("duplicate manifest ID");
  for (const id of perimeter.recovery_pass_ids) if (!allowedPasses.has(id)) issues.push("recovery pass outside accepted snapshot");
  for (const id of perimeter.manifest_ids) if (!allowedManifests.has(id)) issues.push("manifest outside accepted snapshot");
  return issues;
}

function validateReferences(packet: SourceReconstructionPacket): string[] {
  const issues: string[] = [];
  const refs = new Map<string, SourceReconstructionPacket["provenance_index"][number]>();
  for (const ref of packet.provenance_index) {
    if (refs.has(ref.ref_id)) issues.push("duplicate provenance ref ID");
    refs.set(ref.ref_id, ref);
    if (!packet.coverage_perimeter.recovery_pass_ids.includes(ref.recovery_pass_id)) issues.push("provenance recovery pass is outside packet perimeter");
    if (!packet.coverage_perimeter.manifest_ids.includes(ref.manifest_id)) issues.push("provenance manifest is outside packet perimeter");
  }
  const collections = Object.values(packet.evidence).flat();
  const evidenceIds = new Set<string>();
  for (const item of collections) {
    if (evidenceIds.has(item.evidence_id)) issues.push("duplicate evidence ID");
    evidenceIds.add(item.evidence_id);
    for (const ref of item.evidence_refs) if (!refs.has(ref)) issues.push("dangling evidence reference");
  }
  return issues;
}

export async function acceptHistoricalReconstruction(candidate: unknown, trustedContext: unknown): Promise<GatewayResult> {
  try {
    const contextResult = trustedGatewayContextSchema.safeParse(trustedContext);
    if (!contextResult.success) return reject("invalid_trusted_context", contextResult.error.issues.map((issue) => issue.path.join(".") || "trusted_context"));
    const normalized = normalizeProtocolPayload(candidate);
    const packetResult = sourceReconstructionPacketSchema.safeParse(normalized);
    if (!packetResult.success) return reject("invalid_schema", packetResult.error.issues.map((issue) => `${issue.path.join(".") || "packet"}: ${issue.message}`));
    const identityIssues = validateIdentity(packetResult.data, contextResult.data);
    if (identityIssues.length) return reject("identity_mismatch", identityIssues);
    const coverageIssues = validateCoverage(packetResult.data, contextResult.data);
    if (coverageIssues.length) return reject("coverage_mismatch", coverageIssues);
    const referenceIssues = validateReferences(packetResult.data);
    if (referenceIssues.length) return reject("reference_integrity", referenceIssues);
    const privacyIssues = privacyIssuesFor(packetResult.data);
    if (privacyIssues.length) return reject("privacy_rejection", privacyIssues);
    const canonicalPacket = canonicalize(packetResult.data);
    return {
      status: "accept",
      accepted: Object.freeze({
        __tracework_gateway_acceptance: GATEWAY_ACCEPTANCE_BRAND,
        packet: packetResult.data,
        canonical_packet: canonicalPacket,
        accepted_packet_digest: await sha256Hex(canonicalPacket),
        validation_metadata: Object.freeze({
          gateway_package_version: GATEWAY_PACKAGE_VERSION,
          reconstruction_packet_schema_version: RECONSTRUCTION_PACKET_SCHEMA_VERSION,
          reconstruction_protocol_version: RECONSTRUCTION_PROTOCOL_VERSION,
          provenance_schema_version: PROVENANCE_SCHEMA_VERSION,
          privacy_contract_compatibility: PRIVACY_CONTRACT_COMPATIBILITY,
          normalized: true,
          privacy_scan: "passed",
          provenance_validation: "passed",
          reference_validation: "passed",
        }),
      }),
    };
  } catch {
    return reject("gateway_failure", ["Evidence Gateway failed closed"]);
  }
}

export async function acceptSourceCoverageManifest(candidate: unknown, trustedContext: unknown): Promise<CoverageGatewayResult> {
  try {
    const contextResult = trustedCoverageContextSchema.safeParse(trustedContext);
    if (!contextResult.success) return reject("invalid_trusted_context", contextResult.error.issues.map((issue) => issue.path.join(".") || "trusted_context"));
    const normalized = normalizeProtocolPayload(candidate);
    const manifestResult = sourceCoverageManifestSchema.safeParse(normalized);
    if (!manifestResult.success) return reject("invalid_schema", manifestResult.error.issues.map((issue) => `${issue.path.join(".") || "manifest"}: ${issue.message}`));
    if (manifestResult.data.project_id !== contextResult.data.project_id || manifestResult.data.provider !== contextResult.data.expected_provider) return reject("identity_mismatch", ["Coverage manifest does not match trusted project/provider context"]);
    const privacyIssues = privacyIssuesFor(manifestResult.data);
    if (privacyIssues.length) return reject("privacy_rejection", privacyIssues);
    const canonicalManifest = canonicalize(manifestResult.data);
    return { status: "accept", manifest: manifestResult.data, canonical_manifest: canonicalManifest, accepted_manifest_digest: await sha256Hex(canonicalManifest) };
  } catch {
    return reject("gateway_failure", ["Evidence Gateway failed closed"]);
  }
}

export async function acceptProjectStateReconstruction(candidate: unknown, trustedContext: unknown): Promise<ProjectStateGatewayResult> {
  try {
    const contextResult = trustedProjectStateContextSchema.safeParse(trustedContext);
    if (!contextResult.success) return reject("invalid_trusted_context", contextResult.error.issues.map((issue) => issue.path.join(".") || "trusted_context"));
    const normalized = normalizeProtocolPayload(candidate);
    const packetResult = projectStateReconstructionPacketSchema.safeParse(normalized);
    if (!packetResult.success) return reject("invalid_schema", packetResult.error.issues.map((issue) => `${issue.path.join(".") || "packet"}: ${issue.message}`));
    const packet = packetResult.data; const context: TrustedProjectStateContext = contextResult.data; const issues: string[] = [];
    if (packet.project_id !== context.project_id) issues.push("project_id does not match trusted context");
    if (packet.evidence_source.source_id !== context.evidence_source_id) issues.push("evidence source does not match trusted context");
    if (packet.evidence_source.source_system !== context.source_system) issues.push("source system does not match the inspected workspace attachment");
    if (packet.analyst.provider !== context.analyst.provider || packet.analyst.surface !== context.analyst.surface || (packet.analyst.model ?? null) !== (context.analyst.model ?? null)) issues.push("analyst attestation does not match trusted request context");
    if (issues.length) return reject("identity_mismatch", issues);
    const privacyIssues = privacyIssuesFor(packet, "project_state_packet");
    if (privacyIssues.length) return reject("privacy_rejection", privacyIssues);
    const canonicalPacket = canonicalize(packet);
    return { status: "accept", accepted: Object.freeze({
      __tracework_gateway_acceptance: GATEWAY_ACCEPTANCE_BRAND,
      packet,
      canonical_packet: canonicalPacket,
      accepted_packet_digest: await sha256Hex(canonicalPacket),
      validation_metadata: Object.freeze({ gateway_package_version: GATEWAY_PACKAGE_VERSION, project_state_reconstruction_schema_version: PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION, project_state_reconstruction_protocol_version: PROJECT_STATE_RECONSTRUCTION_PROTOCOL_VERSION, privacy_contract_compatibility: PRIVACY_CONTRACT_COMPATIBILITY, normalized: true, privacy_scan: "passed", provenance_validation: "passed", snapshot_validation: "passed" }),
    }) };
  } catch {
    return reject("gateway_failure", ["Evidence Gateway failed closed"]);
  }
}

export function isCanonicalAcceptedPacket(value: unknown): value is CanonicalAcceptedPacket {
  return Boolean(value && typeof value === "object" && (value as Record<string, unknown>).__tracework_gateway_acceptance === GATEWAY_ACCEPTANCE_BRAND);
}
