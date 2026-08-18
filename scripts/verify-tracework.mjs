#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const site = (process.env.TRACEWORK_SITE_URL || "https://tracework-progress.icy-acorn-6036.chatgpt.site").replace(/\/$/, "");
const args = new Map(process.argv.slice(2).map((value, index, all) => value.startsWith("--") ? [value, all[index + 1]?.startsWith("--") ? undefined : all[index + 1]] : ["", undefined]));
const getJson = async (path) => { const response = await fetch(`${site}${path}`); if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`); return response.json(); };

const runtime = await getJson("/.well-known/tracework-runtime.json");
const mcp = await getJson("/.well-known/tracework-mcp.json");
const keys = await getJson("/.well-known/tracework-receipt-keys.json");
const result = { site, gateway: runtime.evidence_gateway, signing: runtime.receipt_signing, mcp_manifest_digest: mcp.tool_contract_digest, receipt_key_count: keys.keys?.length ?? 0 };

if (args.has("--artifact")) {
  const bytes = await readFile(resolve(args.get("--artifact")));
  const localDigest = createHash("sha256").update(bytes).digest("hex");
  result.local_artifact_digest = localDigest;
  result.artifact_matches_runtime = localDigest === runtime.evidence_gateway?.canonical_artifact_sha256;
  if (!result.artifact_matches_runtime) process.exitCode = 2;
}

if (args.has("--receipt")) {
  const [{ verifyEvidenceReceipt }, receiptText] = await Promise.all([import("../dist/receipts.js"), readFile(resolve(args.get("--receipt")), "utf8")]);
  result.receipt_verification = await verifyEvidenceReceipt(JSON.parse(receiptText), keys);
  if (!result.receipt_verification.valid || result.receipt_verification.key_status === "revoked") process.exitCode = 3;
}

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
