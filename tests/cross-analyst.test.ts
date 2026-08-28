import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION } from "../src/constants.js";
import { acceptHistoricalReconstruction, acceptProjectStateReconstruction } from "../src/gateway.js";
import { clone, generalizedProse, projectStateContext, projectStatePacket, validContext, validPacket, type AnalystProvider } from "./fixtures.js";

const analysts: readonly AnalystProvider[] = ["chatgpt", "claude", "codex"];

function withStatement(provider: AnalystProvider, statement: string) {
  const packet: any = clone(projectStatePacket(provider));
  packet.findings[0].statement = statement;
  return packet;
}

const projectStateNarrativeTargets = [
  { name: "summary", path: "summary", set: (packet: any, value: string) => { packet.summary = value; } },
  { name: "finding statement", path: "findings[0].statement", set: (packet: any, value: string) => { packet.findings[0].statement = value; } },
  { name: "finding limitation", path: "findings[0].limitations[0]", set: (packet: any, value: string) => { packet.findings[0].limitations = [value]; } },
  { name: "inspection-scope limitation", path: "inspection.scope.limitations[0]", set: (packet: any, value: string) => { packet.inspection.scope.limitations = [value]; } },
  { name: "provenance limitation", path: "provenance_index[0].limitations[0]", set: (packet: any, value: string) => { packet.provenance_index[0].limitations = [value]; } },
] as const;

const prohibitedNarrativeSamples = [
  ["source code", "function stage(input){ return input.map(item => item.value); }", "likely_source_code"],
  ["raw file content", `FILE: config.ts ${"export const endpoint = buildEndpoint(); ".repeat(3)}export default endpoint;`, "raw_file_payload"],
  ["credential", "Observed password=distinctivesecretvalue during inspection.", "credential_assignment"],
  ["absolute path", "Observed configuration at C:/Users/private/workspace/config.ts.", "absolute_filesystem_path"],
  ["repository diff", "diff --git a/one.ts b/one.ts index abc123..def456 @@ -1,3 +1,3 @@ removed added", "repository_diff"],
  ["raw transcript", "User: describe the private module. Assistant: here is the full module implementation.", "raw_transcript"],
  ["fenced code", "```ts const configured = 1; ```", "source_code_block"],
  ["private URL", "Configuration referenced https://service.internal/private/path during inspection.", "private_url"],
  ["serialized source object", "{\"scripts\":{\"build\":\"tsc\"},\"privateConfig\":{\"mode\":\"local\"}}", "likely_source_code"],
  ["encoded blob", Buffer.from("generic opaque file content ".repeat(8)).toString("base64"), "suspicious_encoded_blob"],
] as const;

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

test("Project State narrative capacity is length-independent for every analyst", async () => {
  for (const provider of analysts) {
    const result = await acceptProjectStateReconstruction(withStatement(provider, generalizedProse(1_200_000)), projectStateContext(provider));
    assert.equal(result.status, "accept", provider);
    if (result.status === "accept") assert.ok(result.accepted.canonical_segments.length > 5);
  }
});

test("the versioned public JSON Schema publishes unbounded narrative and collection capacity", async () => {
  const schema = JSON.parse(await readFile(new URL(`../schema/project-state-reconstruction-${PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION}.schema.json`, import.meta.url), "utf8"));
  assert.equal(schema.properties.project_state_reconstruction_schema_version.const, PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION);
  assert.equal(schema.properties.summary.maxLength, undefined);
  assert.equal(schema.properties.findings.maxItems, undefined);
  assert.equal(schema.properties.findings.items.properties.statement.maxLength, undefined);
  assert.equal(schema.properties.provenance_index.maxItems, undefined);
});

test("normalization introduces no hidden Project State capacity boundary", async () => {
  const packet: any = clone(projectStatePacket("codex"));
  packet.summary = `${"ﬃ ".repeat(100_000)}ﬃx`;
  assert.equal((await acceptProjectStateReconstruction(packet, projectStateContext("codex"))).status, "accept");
});

test("no generalized Project State prose is rejected merely for size", async () => {
  for (const length of [1, 420, 421, 1_200, 100_000]) {
    const statement = await acceptProjectStateReconstruction(withStatement("claude", generalizedProse(length)), projectStateContext("claude"));
    assert.equal(statement.status, "accept", `statement length ${length}`);
    const packet: any = clone(projectStatePacket("claude")); packet.findings[0].limitations = [generalizedProse(length)];
    assert.equal((await acceptProjectStateReconstruction(packet, projectStateContext("claude"))).status, "accept", `limitation length ${length}`);
  }
});

test("a privacy rejection names the offending field and never echoes the rejected value", async () => {
  const marker = "distinctivemarkertoken";
  const packet: any = clone(validPacket());
  packet.evidence.decisions[0].outcome = `function ${marker}(input){ return input.map(item => item.value); }`;
  const result = await acceptHistoricalReconstruction(packet, validContext());
  assert.equal(result.status, "reject");
  if (result.status === "reject") {
    assert.equal(result.category, "privacy_rejection");
    assert.ok(result.issues.includes("payload.evidence.decisions[0].outcome: likely_source_code"), JSON.stringify(result.issues));
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

test("prohibited narrative material fails closed in every Project State narrative field for every analyst", async () => {
  for (const provider of analysts) for (const [sampleName, value, category] of prohibitedNarrativeSamples) for (const target of projectStateNarrativeTargets) {
    const packet: any = clone(projectStatePacket(provider));
    target.set(packet, value);
    const result = await acceptProjectStateReconstruction(packet, projectStateContext(provider));
    assert.equal(result.status, "reject", `${provider}: ${sampleName} was accepted in ${target.name}`);
    if (result.status === "reject") {
      assert.equal(result.category, "privacy_rejection", `${provider}: ${sampleName} in ${target.name}: ${JSON.stringify(result.issues)}`);
      assert.ok(result.issues.includes(`project_state_packet.${target.path}: ${category}`), `${provider}: ${sampleName} in ${target.name}: ${JSON.stringify(result.issues)}`);
      for (const issue of result.issues) {
        assert.ok(!issue.includes("distinctivesecretvalue"), issue);
        assert.ok(!issue.includes("buildEndpoint"), issue);
        assert.ok(!issue.includes("private/workspace"), issue);
      }
    }
  }
});

test("source-like content cannot hide in Project State labels", async () => {
  const samples = [
    ["function stage(input){ return input.map(item => item.value); }", "likely_source_code"],
    ["User: provide the private module. Assistant: here is its implementation.", "raw_transcript"],
    ["Observed password=distinctivesecretvalue during inspection.", "credential_assignment"],
  ] as const;
  for (const provider of analysts) for (const [value, category] of samples) {
    for (const target of ["root_label", "surface", "model"] as const) {
      const packet: any = clone(projectStatePacket(provider));
      const context: any = clone(projectStateContext(provider));
      if (target === "root_label") packet.inspection.root_label = value;
      else { packet.analyst[target] = value; context.analyst[target] = value; }
      const result = await acceptProjectStateReconstruction(packet, context);
      assert.equal(result.status, "reject", `${provider}: ${target} accepted prohibited content`);
      if (result.status === "reject") {
        assert.equal(result.category, "privacy_rejection", JSON.stringify(result.issues));
        const path = target === "root_label" ? "inspection.root_label" : `analyst.${target}`;
        assert.ok(result.issues.includes(`project_state_packet.${path}: ${category}`), JSON.stringify(result.issues));
        for (const issue of result.issues) assert.ok(!issue.includes("distinctivesecretvalue"), issue);
      }
    }
  }
});

test("ordinary generalized limitations remain usable across fields and analysts", async () => {
  const legitimate = [
    "A generated configuration was excluded; only its presence and role were generalized.",
    "One function-named component was present, but its implementation was not inspected.",
    "Build metadata described an export target; the underlying file contents were excluded.",
  ];
  for (const provider of analysts) for (const value of legitimate) for (const target of projectStateNarrativeTargets) {
    const packet: any = clone(projectStatePacket(provider));
    target.set(packet, value);
    const result = await acceptProjectStateReconstruction(packet, projectStateContext(provider));
    assert.equal(result.status, "accept", `${provider}: legitimate prose rejected in ${target.name}: ${JSON.stringify(result)}`);
  }
});

test("sanitized technical reconstruction narrative is not mistaken for source code", async () => {
  const legitimate = [
    "The import and export layers remained compatible; the interface returned version 2.1; release metadata described class boundaries without exposing implementation text.",
    "The parser, API adapter, and worker components changed together; commit metadata named the function-oriented subsystem and the return path, but no file content or diff was retained.",
    "Tags v1.8.0 and v1.8.1 identify repository checkpoints; the configuration terminology includes const, class, and interface names only as generalized component labels.",
  ];
  for (const provider of analysts) for (const value of legitimate) {
    const packet: any = clone(validPacket()); const context: any = clone(validContext());
    packet.provider = provider; packet.provider_provenance.provider = provider; context.expected_provider = provider;
    packet.project_summary.description = value;
    const result = await acceptHistoricalReconstruction(packet, context);
    assert.equal(result.status, "accept", `${provider}: ${JSON.stringify(result)}`);
  }
});

test("Project State relative paths reject absolute, traversal, credential, and version-control paths", async () => {
  for (const provider of analysts) for (const value of ["C:/workspace/package.json", "/workspace/package.json", "../outside/package.json", ".env.production", ".git/config", ".hg/store", ".svn/entries"]) {
    const packet: any = clone(projectStatePacket(provider));
    packet.provenance_index[0].relative_path = value;
    const result = await acceptProjectStateReconstruction(packet, projectStateContext(provider));
    assert.equal(result.status, "reject", `${provider}: unsafe path accepted: ${value}`);
    if (result.status === "reject") {
      assert.equal(result.category, "invalid_schema");
      assert.ok(result.issues.some((issue) => issue.startsWith("provenance_index.0.relative_path:")), JSON.stringify(result.issues));
      for (const issue of result.issues) assert.ok(!issue.includes(value), issue);
    }
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
