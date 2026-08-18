import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { KEY_REGISTRY_FORMAT_VERSION, RECEIPT_FORMAT_VERSION } from "../src/constants.js";
import { createEvidenceReceipt, verifyEvidenceReceipt, type EvidenceReceiptClaims, type ReceiptSigner } from "../src/receipts.js";

function testSigner(keyId: string): { signer: ReceiptSigner; publicKey: string } {
  const pair = generateKeyPairSync("ed25519");
  return {
    signer: { keyId, algorithm: "Ed25519", async sign(message) { return sign(null, Buffer.from(message), pair.privateKey); } },
    publicKey: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
  };
}

function claims(keyId: string, receiptId: string): EvidenceReceiptClaims {
  return {
    receipt_format_version: RECEIPT_FORMAT_VERSION, receipt_id: receiptId, project_safe_identifier: "project_test", provider: "claude", operation: "source_reconstruction", accepted_at: "2026-08-17T12:00:00.000Z", coverage_snapshot_reference: "snapshot_1", gateway_package_version: "1.0.0", gateway_source_commit: "a".repeat(40), gateway_release_tag: "evidence-gateway-v1.0.0", gateway_artifact_digest: "b".repeat(64), privacy_contract_version: "1.0.0", canonical_packet_digest: "c".repeat(64), submission_channel: "mcp", key_id: keyId,
  };
}

test("rotation keeps an old receipt verifiable and routes by key_id", async () => {
  const a = testSigner("receipt-key-a");
  const receiptA = await createEvidenceReceipt(claims(a.signer.keyId, "receipt_a"), a.signer);
  const registryA = { format_version: KEY_REGISTRY_FORMAT_VERSION, keys: [{ key_id: "receipt-key-a", algorithm: "Ed25519", public_key_spki: a.publicKey, activated_at: "2026-08-17T10:00:00.000Z", retired_at: null, status: "active" }] } as const;
  assert.deepEqual(await verifyEvidenceReceipt(receiptA, registryA), { valid: true, key_status: "active" });

  const b = testSigner("receipt-key-b");
  const receiptB = await createEvidenceReceipt(claims(b.signer.keyId, "receipt_b"), b.signer);
  const registryB = { format_version: KEY_REGISTRY_FORMAT_VERSION, keys: [
    { ...registryA.keys[0], retired_at: "2026-08-17T11:00:00.000Z", status: "retired" },
    { key_id: "receipt-key-b", algorithm: "Ed25519", public_key_spki: b.publicKey, activated_at: "2026-08-17T11:00:00.000Z", retired_at: null, status: "active" },
  ] } as const;
  assert.deepEqual(await verifyEvidenceReceipt(receiptA, registryB), { valid: true, key_status: "retired" });
  assert.deepEqual(await verifyEvidenceReceipt(receiptB, registryB), { valid: true, key_status: "active" });
});

test("revoked keys remain identifiable and produce a warning", async () => {
  const key = testSigner("receipt-key-revoked");
  const receipt = await createEvidenceReceipt(claims(key.signer.keyId, "receipt_revoked"), key.signer);
  const result = await verifyEvidenceReceipt(receipt, { format_version: KEY_REGISTRY_FORMAT_VERSION, keys: [{ key_id: key.signer.keyId, algorithm: "Ed25519", public_key_spki: key.publicKey, activated_at: "2026-08-17T10:00:00.000Z", retired_at: "2026-08-17T11:00:00.000Z", status: "revoked" }] });
  assert.equal(result.valid, true); assert.equal(result.key_status, "revoked"); assert.match(result.warning ?? "", /revoked/i);
});
