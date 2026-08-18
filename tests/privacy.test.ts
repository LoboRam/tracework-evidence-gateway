import assert from "node:assert/strict";
import test from "node:test";
import { acceptHistoricalReconstruction } from "../src/gateway.js";
import { clone, validContext, validPacket } from "./fixtures.js";

const unsafeCases: Array<[string, string]> = [
  ["raw transcript", "User: Please write this implementation in full.\nAssistant: Here is the complete implementation with every private detail."],
  ["serialized message array", '[{"role":"user","content":"full private prompt content that should never be accepted"}]'],
  ["prompt dump", `prompt: ${"private prompt material ".repeat(12)}`],
  ["source code", `\`\`\`ts\n${"const secretValue = function () { return { private: true }; };\n".repeat(5)}\`\`\``],
  ["repository diff", "diff --git a/private.ts b/private.ts\nindex abc123..def456\n@@ -1,3 +1,3 @@\n-private\n+secret"],
  ["bulk file payload", `FILE: one.ts\n${"private file content ".repeat(20)}\nFILE: two.ts\nmore`],
  ["credential", "api_key = sk-live-abcdefghijklmnopqrstuvwxyz123456"],
  ["private key", "-----BEGIN PRIVATE KEY-----\nnot-real-but-forbidden\n-----END PRIVATE KEY-----"],
  ["private URL", "Internal context came from https://private.internal/secret/path"],
  ["encoded blob", Buffer.from("synthetic content that must not be accepted as an opaque blob".repeat(8)).toString("base64")],
];

for (const [name, value] of unsafeCases) test(`${name} is rejected and cannot produce accepted evidence`, async () => {
  const packet: any = clone(validPacket()); packet.project_summary.description = value;
  const result = await acceptHistoricalReconstruction(packet, validContext());
  assert.equal(result.status, "reject");
  if (result.status === "reject") assert.notEqual(result.category, "gateway_failure");
});
