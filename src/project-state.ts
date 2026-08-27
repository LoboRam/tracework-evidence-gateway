import { z } from "zod";
import {
  PROJECT_STATE_FINGERPRINT_ALGORITHM,
  PROTOCOL_MAX_LINE_LENGTH,
  PROJECT_STATE_RECONSTRUCTION_PROTOCOL_VERSION,
  PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION,
} from "./constants.js";
import { canonicalize, sha256Hex } from "./canonical.js";

const safeId = z.string().trim().min(1).max(120).regex(/^[A-Za-z0-9._:-]+$/);
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const singleLine = (max: number = PROTOCOL_MAX_LINE_LENGTH) => z.string().trim().min(1).max(Math.min(max, PROTOCOL_MAX_LINE_LENGTH)).refine((value) => !/[\r\n]/.test(value), "must be a single sanitized line");
const safeFindingText = singleLine().refine((value) => !/[{};]|=>|```/.test(value), "must be a generalized finding, not source code");
const sensitivePathPart = /^(?:\.env(?:\..*)?|\.git-credentials|\.npmrc|\.pypirc|id_(?:rsa|dsa|ecdsa|ed25519)|credentials?|secrets?|tokens?|private[_-]?key)(?:\.[^/]*)?$/i;

export const projectStateRelativePathSchema = z.string().trim().min(1).max(300).refine((value) => {
  if (value.includes("\\") || value.startsWith("/") || /^[A-Za-z]:/.test(value)) return false;
  const parts = value.split("/");
  return parts.every((part) => part && part !== "." && part !== ".." && !sensitivePathPart.test(part));
}, "must be a safe project-relative path and must not identify a credential-bearing file");

export const projectStateAnalystSchema = z.object({
  provider: z.enum(["chatgpt", "claude", "codex", "other"]),
  surface: singleLine(120),
  model: singleLine(120).nullable().optional(),
  inspected_at: z.string().datetime({ offset: true }),
}).strict();

export const projectStateEvidenceSourceIdentitySchema = z.object({
  architecture_version: z.literal(1),
  source_id: safeId,
  source_type: z.literal("project_state"),
  source_system: z.literal("local_project_workspace"),
  analyst_provider: z.null(),
}).strict();

export const projectStateObservationBasisSchema = z.enum([
  "filesystem_metadata", "manifest_or_configuration", "import_or_reference_graph", "entry_point_reachability",
  "build_or_test_definition", "generated_marker", "naming_and_location_signal", "bounded_static_analysis", "other_bounded_observation",
]);
export const projectStateFindingCategorySchema = z.enum([
  "project_entry_point", "active_execution_path", "major_module_or_component", "referenced_dependency",
  "configuration_or_provider_wiring", "active_model_or_asset", "test_build_or_package_structure",
  "inactive_code", "experimental_code", "obsolete_code", "generated_or_build_artifact", "dead_code",
  "architecture_state", "capability_state", "unknown_state",
]);
export const projectStateStateClassificationSchema = z.enum([
  "active_reachable", "present_inactive", "experimental", "obsolete", "generated_artifact", "dead", "present_reachability_unknown", "unknown",
]);

export const projectStateReconstructionPacketSchema = z.object({
  packet_id: safeId,
  project_state_reconstruction_schema_version: z.literal(PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION),
  project_state_reconstruction_protocol_version: z.literal(PROJECT_STATE_RECONSTRUCTION_PROTOCOL_VERSION),
  project_id: safeId,
  evidence_source: projectStateEvidenceSourceIdentitySchema,
  inspection: z.object({
    inspection_id: safeId,
    inspected_at: z.string().datetime({ offset: true }),
    workspace_handle: safeId,
    root_label: singleLine(160).refine((value) => !/[\\/]/.test(value) && !/^[A-Za-z]:/.test(value), "must be a safe label, not a filesystem path"),
    inspection_method: z.enum(["local_filesystem", "mounted_project_workspace"]),
    snapshot: z.object({
      fingerprint_algorithm: z.literal(PROJECT_STATE_FINGERPRINT_ALGORITHM),
      root_fingerprint: sha256,
      scope_fingerprint: sha256,
      path_set_fingerprint: sha256,
      inventory_fingerprint: sha256,
      fingerprinted_file_count: z.number().int().nonnegative().max(1_000_000),
      fingerprinted_directory_count: z.number().int().nonnegative().max(1_000_000),
      fingerprinted_total_bytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
      previous_root_fingerprint: sha256.nullable(),
    }).strict(),
    scope: z.object({
      basis: z.enum(["project_root", "authorized_subtree"]),
      excluded_categories: z.array(z.enum(["credentials_and_secrets", "version_control_internals", "dependency_caches", "unreadable_entries", "outside_authorized_scope", "binary_contents"])).min(1).max(6),
      symlink_policy: z.enum(["do_not_follow", "follow_within_authorized_root"]),
      hidden_files_policy: z.enum(["include_except_sensitive", "exclude_all"]),
      limitations: z.array(singleLine()).max(16),
    }).strict(),
  }).strict(),
  summary: safeFindingText,
  findings: z.array(z.object({
    finding_id: safeId,
    category: projectStateFindingCategorySchema,
    statement: safeFindingText,
    directness: z.enum(["direct_observation", "inferred_architecture", "unknown"]),
    state_classification: projectStateStateClassificationSchema,
    confidence: z.enum(["high", "medium", "low"]),
    provenance_refs: z.array(safeId).min(1).max(32),
    limitations: z.array(singleLine()).max(8),
    production_status: z.literal("not_established"),
  }).strict()).min(1).max(160),
  provenance_index: z.array(z.object({
    ref_id: safeId,
    component_id: safeId,
    component_kind: z.enum(["file", "directory", "entry_point", "module", "package", "configuration", "provider", "model", "asset", "test", "build", "generated_artifact", "other"]),
    relative_path: projectStateRelativePathSchema.optional(),
    content_fingerprint: sha256.optional(),
    observation_basis: projectStateObservationBasisSchema,
    directness: z.enum(["direct_observation", "inferred_relationship"]),
    observed_at: z.string().datetime({ offset: true }),
    limitations: z.array(singleLine()).max(8),
  }).strict()).min(1).max(320),
  analyst: projectStateAnalystSchema,
  privacy: z.object({
    raw_source_code_included: z.literal(false),
    file_contents_included: z.literal(false),
    credentials_or_secrets_included: z.literal(false),
    absolute_paths_included: z.literal(false),
    sanitized_findings_only: z.literal(true),
    cryptographic_fingerprints_only: z.literal(true),
  }).strict(),
}).strict().superRefine((packet, context) => {
  if (packet.inspection.inspected_at !== packet.analyst.inspected_at) context.addIssue({ code: "custom", path: ["analyst", "inspected_at"], message: "Analyst and inspection timestamps must identify the same inspection point" });
  if (!packet.inspection.scope.excluded_categories.includes("credentials_and_secrets")) context.addIssue({ code: "custom", path: ["inspection", "scope", "excluded_categories"], message: "Credential and secret files must be excluded from inspection and fingerprinting" });
  if (!packet.inspection.scope.excluded_categories.includes("version_control_internals")) context.addIssue({ code: "custom", path: ["inspection", "scope", "excluded_categories"], message: "Version-control internals must be excluded so Project State remains independent from repository history" });
  const refs = new Set<string>();
  for (const [index, ref] of packet.provenance_index.entries()) {
    if (refs.has(ref.ref_id)) context.addIssue({ code: "custom", path: ["provenance_index", index, "ref_id"], message: "Duplicate provenance reference" });
    refs.add(ref.ref_id);
    if (ref.component_kind === "file" && !ref.relative_path) context.addIssue({ code: "custom", path: ["provenance_index", index, "relative_path"], message: "File provenance requires a safe relative path" });
  }
  const findings = new Set<string>();
  for (const [index, finding] of packet.findings.entries()) {
    if (findings.has(finding.finding_id)) context.addIssue({ code: "custom", path: ["findings", index, "finding_id"], message: "Duplicate finding ID" });
    findings.add(finding.finding_id);
    for (const ref of finding.provenance_refs) if (!refs.has(ref)) context.addIssue({ code: "custom", path: ["findings", index, "provenance_refs"], message: `Unknown provenance reference ${ref}` });
    const inferredState = ["experimental", "obsolete", "dead"] as const;
    if (inferredState.includes(finding.state_classification as typeof inferredState[number]) && finding.directness === "direct_observation" && !finding.limitations.length) context.addIssue({ code: "custom", path: ["findings", index, "limitations"], message: "Experimental, obsolete, and dead classifications must state the folder-supported basis or uncertainty" });
  }
}).describe("Sanitized Project State reconstruction. It identifies the inspected local project snapshot without storing the project or claiming deployment, usage, adoption, or commercial success.");

export const trustedProjectStateContextSchema = z.object({
  project_id: safeId,
  evidence_source_id: safeId,
  source_system: z.literal("local_project_workspace"),
  analyst: projectStateAnalystSchema.omit({ inspected_at: true }),
}).strict();

export type ProjectStateReconstructionPacket = z.infer<typeof projectStateReconstructionPacketSchema>;
export type TrustedProjectStateContext = z.infer<typeof trustedProjectStateContextSchema>;

export type ProjectStateFingerprintEntry = { relative_path: string; size_bytes: number; content_sha256: string };
export type ProjectStateFingerprintScope = { basis: "project_root" | "authorized_subtree"; excluded_categories: readonly string[]; symlink_policy: "do_not_follow" | "follow_within_authorized_root"; hidden_files_policy: "include_except_sensitive" | "exclude_all" };

export async function computeProjectStateSnapshotFingerprint(scope: ProjectStateFingerprintScope, entries: ProjectStateFingerprintEntry[], directoryPaths: string[] = []) {
  if (!scope.excluded_categories.includes("credentials_and_secrets") || !scope.excluded_categories.includes("version_control_internals")) throw new Error("Project State fingerprint scope must exclude credentials, secrets, and version-control internals");
  const normalized = entries.map((entry) => ({ relative_path: projectStateRelativePathSchema.parse(entry.relative_path), size_bytes: z.number().int().nonnegative().parse(entry.size_bytes), content_sha256: sha256.parse(entry.content_sha256) })).sort((a, b) => a.relative_path.localeCompare(b.relative_path));
  if (new Set(normalized.map((entry) => entry.relative_path)).size !== normalized.length) throw new Error("Project State fingerprint entries must have unique relative paths");
  const directories = directoryPaths.map((path) => projectStateRelativePathSchema.parse(path)).sort((a, b) => a.localeCompare(b));
  if (new Set(directories).size !== directories.length) throw new Error("Project State fingerprint directory paths must be unique");
  if (directories.some((path) => normalized.some((entry) => entry.relative_path === path))) throw new Error("Project State fingerprint paths must identify either a file or a directory, not both");
  const scope_fingerprint = await sha256Hex(canonicalize({ ...scope, excluded_categories: [...scope.excluded_categories].sort() }));
  const path_set_fingerprint = await sha256Hex([...normalized.map((entry) => `file\0${entry.relative_path}`), ...directories.map((path) => `directory\0${path}`)].sort().join("\n"));
  const inventory_fingerprint = await sha256Hex([...normalized.map((entry) => `file\0${entry.relative_path}\0${entry.size_bytes}\0${entry.content_sha256}`), ...directories.map((path) => `directory\0${path}`)].sort().join("\n"));
  const root_fingerprint = await sha256Hex(`${PROJECT_STATE_FINGERPRINT_ALGORITHM}\0${scope_fingerprint}\0${path_set_fingerprint}\0${inventory_fingerprint}`);
  return { fingerprint_algorithm: PROJECT_STATE_FINGERPRINT_ALGORITHM, root_fingerprint, scope_fingerprint, path_set_fingerprint, inventory_fingerprint, fingerprinted_file_count: normalized.length, fingerprinted_directory_count: directories.length, fingerprinted_total_bytes: normalized.reduce((sum, entry) => sum + entry.size_bytes, 0) } as const;
}
