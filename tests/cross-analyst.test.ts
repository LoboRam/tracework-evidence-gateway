import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION, PROTOCOL_MAX_LINE_LENGTH } from "../src/constants.js";
import { acceptHistoricalReconstruction, acceptProjectStateReconstruction } from "../src/gateway.js";
import { clone, generalizedProse, projectStateContext, projectStatePacket, validContext, validPacket, type AnalystProvider } from "./fixtures.js";

const analysts: readonly AnalystProvider[] = ["chatgpt", "claude", "codex"];

function withStatement(provider: AnalystProvider, statement: string) {
  const packet: any = clone(projectStatePacket(provider));
  packet.findings[0].statement = statement;
  return packet;
}

test("chatgpt, claude, and codex analysts produce equivalent accepted Project State evidence", async () => {
  const accepted = [];
  for (const provider of analysts) {
    const result = await acceptProjectStateReconstruction(projectStatePacket(provider), projectStateContext(provider));
    assert.equal(result.status, "accept", `${provider}: ${JSON.stringify(result)}`);
    if (result.status === "accept") accepted.push(result.accepted);
  }
  for (const one of accepted) {
    assert.equal(one.packet.evidence_source.analyst_provider, null);
    assert.equal(one.packet.evidence_source.source_system, "local_project_workspace");
    assert.equal(one.validation_metadata.privacy_scan, "passed");
  }
  const withoutAnalyst = accepted.map((one) => { const packet: any = structuredClone(one.packet); delete packet.analyst; return JSON.stringify(packet); });
  assert.equal(new Set(withoutAnalyst).size, 1, "analyst identity must be the only difference between equivalent packets");
  assert.equal(new Set(accepted.map((one) => one.accepted_packet_digest)).size, analysts.length);
});

test("an analyst cannot attest as a provider the trusted context did not authorize", async () => {
  for (const provider of analysts) {
    const other = analysts.find((candidate) => candidate !== provider)!;
    const result = await acceptProjectStateReconstruction(projectStatePacket(provider), projectStateContext(other));
    assert.equal(result.status, "reject");
    if (result.status === "reject") assert.equal(result.category, "identity_mismatch");
  }
});

test("the published single-line bound is exactly the bound the gateway accepts", async () => {
  for (const provider of analysts) {
    const atLimit = await acceptProjectStateReconstruction(withStatement(provider, generalizedProse(PROTOCOL_MAX_LINE_LENGTH)), projectStateContext(provider));
    assert.equal(atLimit.status, "accept", `${provider}: ${JSON.stringify(atLimit)}`);
    const overLimit = await acceptProjectStateReconstruction(withStatement(provider, generalizedProse(PROTOCOL_MAX_LINE_LENGTH + 1)), projectStateContext(provider));
    assert.equal(overLimit.status, "reject");
    if (overLimit.status === "reject") {
      assert.equal(overLimit.category, "invalid_schema", JSON.stringify(overLimit.issues));
      assert.ok(overLimit.issues.some((issue) => issue.startsWith("findings.0.statement:")), JSON.stringify(overLimit.issues));
      assert.ok(overLimit.issues.some((issue) => issue.includes(String(PROTOCOL_MAX_LINE_LENGTH))), JSON.stringify(overLimit.issues));
    }
  }
});

test("the versioned public JSON Schema publishes the corrected bound", async () => {
  const schema = JSON.parse(await readFile(new URL(`../schema/project-state-reconstruction-${PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION}.schema.json`, import.meta.url), "utf8"));
  assert.equal(schema.properties.project_state_reconstruction_schema_version.const, PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION);
  assert.equal(schema.properties.summary.maxLength, PROTOCOL_MAX_LINE_LENGTH);
  assert.equal(schema.properties.findings.items.properties.statement.maxLength, PROTOCOL_MAX_LINE_LENGTH);
  assert.equal(schema.properties.findings.items.properties.limitations.items.maxLength, PROTOCOL_MAX_LINE_LENGTH);
  assert.equal(schema.properties.inspection.properties.scope.properties.limitations.items.maxLength, PROTOCOL_MAX_LINE_LENGTH);
  assert.equal(schema.properties.provenance_index.items.properties.limitations.items.maxLength, PROTOCOL_MAX_LINE_LENGTH);
});

test("normalization precedes the shared length boundary", async () => {
  const atLimit: any = clone(projectStatePacket("codex"));
  atLimit.summary = `${"ﬃ ".repeat(104)}ﬃx`;
  assert.equal((await acceptProjectStateReconstruction(atLimit, projectStateContext("codex"))).status, "accept");

  const overLimit: any = clone(atLimit);
  overLimit.summary += "ﬃ";
  const rejected = await acceptProjectStateReconstruction(overLimit, projectStateContext("codex"));
  assert.equal(rejected.status, "reject");
  if (rejected.status === "reject") assert.equal(rejected.category, "invalid_schema");
});

test("no generalized prose length is schema-legal yet privacy-rejected for line size", async () => {
  for (let length = 1; length <= 1_200; length += 7) {
    const statement = await acceptProjectStateReconstruction(withStatement("claude", generalizedProse(length)), projectStateContext("claude"));
    if (statement.status === "reject") assert.equal(statement.category, "invalid_schema", `statement length ${length}: ${JSON.stringify(statement.issues)}`);
    const packet: any = clone(projectStatePacket("claude"));
    packet.findings[0].limitations = [generalizedProse(length)];
    const limitation = await acceptProjectStateReconstruction(packet, projectStateContext("claude"));
    if (limitation.status === "reject") assert.equal(limitation.category, "invalid_schema", `limitation length ${length}: ${JSON.stringify(limitation.issues)}`);
  }
});

test("a privacy rejection names the offending field and never echoes the rejected value", async () => {
  const marker = "distinctivemarkertoken";
  const packet: any = clone(validPacket());
  packet.evidence.decisions[0].outcome = `${marker} ${generalizedProse(600)}`;
  const result = await acceptHistoricalReconstruction(packet, validContext());
  assert.equal(result.status, "reject");
  if (result.status === "reject") {
    assert.equal(result.category, "privacy_rejection");
    assert.ok(result.issues.includes("payload.evidence.decisions[0].outcome: source_sized_line"), JSON.stringify(result.issues));
    for (const issue of result.issues) {
      assert.ok(!issue.includes(marker), issue);
      assert.ok(!issue.includes("workspace"), issue);
    }
  }
});

test("Project State privacy rejections are addressed to a Project State field path", async () => {
  const packet: any = clone(projectStatePacket("codex"));
  packet.findings[0].limitations = ["function stage(input){return input.map(function(item){return item.value})}".repeat(5).slice(0, 400)];
  const result = await acceptProjectStateReconstruction(packet, projectStateContext("codex"));
  assert.equal(result.status, "reject");
  if (result.status === "reject") {
    assert.equal(result.category, "privacy_rejection");
    assert.ok(result.issues.includes("project_state_packet.findings[0].limitations[0]: likely_source_code"), JSON.stringify(result.issues));
    for (const issue of result.issues) assert.ok(!issue.includes("return"), issue);
  }
});

const unsafeMutations: Array<[string, (packet: any) => void]> = [
  ["minified source in a limitation", (packet) => { packet.findings[0].limitations = ["function stage(input){return input.map(function(item){return item.value})}".repeat(5).slice(0, 400)]; }],
  ["source code in a statement", (packet) => { packet.findings[0].statement = "const pipeline = { stage: 1 }; runPipeline(pipeline);"; }],
  ["fenced code block in a limitation", (packet) => { packet.findings[0].limitations = [`\`\`\`ts ${"const configured = 1 ".repeat(6)}\`\`\``]; }],
  ["bulk file payload in a limitation", (packet) => { packet.findings[0].limitations = [`FILE: one.ts\n${"generic file content ".repeat(12)}\nFILE: two.ts`]; }],
  ["repository diff in a limitation", (packet) => { packet.findings[0].limitations = ["diff --git a/one.ts b/one.ts index abc123..def456 @@ -1,3 +1,3 @@ removed added"]; }],
  ["raw transcript in a summary", (packet) => { packet.summary = "User: describe the module.\nAssistant: here is the full module implementation."; }],
  ["service credential in a limitation", (packet) => { packet.findings[0].limitations = ["Excluded a key resembling AKIAIOSFODNN7EXAMPLE from scope."]; }],
  ["bearer token in a limitation", (packet) => { packet.findings[0].limitations = ["Observed Bearer abcdefghijklmnopqrstuvwxyz012345 during inspection."]; }],
  ["email address in a summary", (packet) => { packet.summary = "The maintainer contact is owner@example.com for this workspace."; }],
  ["private url in a limitation", (packet) => { packet.findings[0].limitations = ["Configuration referenced https://service.internal/private/path here."]; }],
  ["encoded blob in a limitation", (packet) => { packet.findings[0].limitations = [Buffer.from("generic content that must never be accepted as an opaque blob".repeat(6)).toString("base64")]; }],
  ["absolute path in provenance", (packet) => { packet.provenance_index[0].relative_path = "C:/workspace/package.json"; }],
  ["path traversal in provenance", (packet) => { packet.provenance_index[0].relative_path = "../outside/package.json"; }],
  ["credential-bearing filename in provenance", (packet) => { packet.provenance_index[0].relative_path = ".env.production"; }],
  ["filesystem path as root label", (packet) => { packet.inspection.root_label = "C:/workspace/project"; }],
  ["file contents smuggled as an extra field", (packet) => { packet.file_contents = "generic raw content"; }],
  ["credential-bearing scope exclusion removed", (packet) => { packet.inspection.scope.excluded_categories = ["dependency_caches"]; }],
  ["production deployment claim", (packet) => { packet.findings[0].production_status = "production_deployed"; }],
  ["privacy attestation flipped", (packet) => { packet.privacy.file_contents_included = true; }],
];

for (const [name, mutate] of unsafeMutations) test(`fails closed for every analyst: ${name}`, async () => {
  for (const provider of analysts) {
    const packet: any = clone(projectStatePacket(provider));
    mutate(packet);
    const result = await acceptProjectStateReconstruction(packet, projectStateContext(provider));
    assert.equal(result.status, "reject", `${provider}: ${name} was accepted`);
    if (result.status === "reject") assert.notEqual(result.category, "gateway_failure");
  }
});
