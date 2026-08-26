import { z } from "zod";
import { KEY_REGISTRY_FORMAT_VERSION, RECEIPT_FORMAT_VERSION } from "./constants.js";
import { canonicalize, fromBase64Url, sha256Hex, utf8 } from "./canonical.js";

const receiptClaimsSchema = z.object({
  receipt_format_version: z.literal(RECEIPT_FORMAT_VERSION),
  receipt_id: z.string().min(1).max(120),
  project_safe_identifier: z.string().min(1).max(120),
  provider: z.string().min(1).max(60),
  operation: z.enum(["source_coverage", "source_reconstruction", "project_state_reconstruction", "unified_reconstruction"]),
  accepted_at: z.string().datetime({ offset: true }),
  coverage_snapshot_reference: z.string().min(1).max(120).nullable(),
  gateway_package_version: z.string().min(1).max(40),
  gateway_source_commit: z.string().regex(/^[a-f0-9]{40}$/),
  gateway_release_tag: z.string().min(1).max(80),
  gateway_artifact_digest: z.string().regex(/^[a-f0-9]{64}$/),
  privacy_contract_version: z.string().min(1).max(40),
  canonical_packet_digest: z.string().regex(/^[a-f0-9]{64}$/),
  submission_channel: z.enum(["mcp", "authenticated_web", "system_compiler"]),
  key_id: z.string().min(1).max(120),
}).strict();

export type EvidenceReceiptClaims = z.infer<typeof receiptClaimsSchema>;
export type EvidenceReceipt = Readonly<{
  claims: EvidenceReceiptClaims;
  claims_digest: string;
  algorithm: "Ed25519";
  signature: string;
}>;

export type ReceiptSigningKey = Readonly<{
  key_id: string;
  algorithm: "Ed25519";
  public_key_spki: string;
  activated_at: string;
  retired_at: string | null;
  status: "active" | "retired" | "revoked";
  kms_key_reference?: string | undefined;
}>;

export type ReceiptKeyRegistry = Readonly<{
  format_version: typeof KEY_REGISTRY_FORMAT_VERSION;
  keys: readonly ReceiptSigningKey[];
}>;

export interface ReceiptSigner {
  readonly keyId: string;
  readonly algorithm: "Ed25519";
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export function canonicalReceiptClaims(claims: EvidenceReceiptClaims): string {
  return canonicalize(receiptClaimsSchema.parse(claims));
}

export async function createEvidenceReceipt(claims: EvidenceReceiptClaims, signer: ReceiptSigner): Promise<EvidenceReceipt> {
  const parsed = receiptClaimsSchema.parse(claims);
  if (parsed.key_id !== signer.keyId) throw new Error("Receipt key ID does not match active signer");
  if (signer.algorithm !== "Ed25519") throw new Error("Unsupported receipt signing algorithm");
  const canonical = canonicalReceiptClaims(parsed);
  const signature = await signer.sign(utf8(canonical));
  return Object.freeze({ claims: parsed, claims_digest: await sha256Hex(canonical), algorithm: "Ed25519", signature: Buffer.from(signature).toString("base64url") });
}

export async function verifyEvidenceReceipt(receipt: EvidenceReceipt, registry: ReceiptKeyRegistry): Promise<{ valid: boolean; key_status?: ReceiptSigningKey["status"]; warning?: string }> {
  if (registry.format_version !== KEY_REGISTRY_FORMAT_VERSION) return { valid: false, warning: "Unsupported key registry format" };
  const claimsResult = receiptClaimsSchema.safeParse(receipt.claims);
  if (!claimsResult.success || receipt.algorithm !== "Ed25519") return { valid: false, warning: "Invalid receipt shape" };
  const key = registry.keys.find((item) => item.key_id === receipt.claims.key_id);
  if (!key) return { valid: false, warning: "Signing key not found" };
  const canonical = canonicalReceiptClaims(claimsResult.data);
  if ((await sha256Hex(canonical)) !== receipt.claims_digest) return { valid: false, key_status: key.status, warning: "Receipt claims digest mismatch" };
  const publicKey = await crypto.subtle.importKey("spki", fromBase64Url(key.public_key_spki) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, fromBase64Url(receipt.signature) as BufferSource, utf8(canonical) as BufferSource);
  if (key.status === "revoked") return { valid, key_status: key.status, warning: "The signing key is revoked; the historical signature remains identifiable but must not be treated as currently trusted." };
  return { valid, key_status: key.status };
}

export function validateReceiptKeyRegistry(value: unknown): ReceiptKeyRegistry {
  const schema = z.object({
    format_version: z.literal(KEY_REGISTRY_FORMAT_VERSION),
    keys: z.array(z.object({
      key_id: z.string().min(1).max(120), algorithm: z.literal("Ed25519"), public_key_spki: z.string().min(40).max(500), activated_at: z.string().datetime({ offset: true }), retired_at: z.string().datetime({ offset: true }).nullable(), status: z.enum(["active", "retired", "revoked"]), kms_key_reference: z.string().min(1).max(300).optional(),
    }).strict()).min(1),
  }).strict();
  const registry = schema.parse(value);
  if (registry.keys.filter((key) => key.status === "active").length !== 1) throw new Error("Registry must contain exactly one active signing key");
  if (new Set(registry.keys.map((key) => key.key_id)).size !== registry.keys.length) throw new Error("Registry key IDs must be unique");
  return registry;
}
