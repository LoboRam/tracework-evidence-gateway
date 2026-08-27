import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION,
  PROTOCOL_MAX_LINE_LENGTH,
  RECONSTRUCTION_PACKET_SCHEMA_VERSION,
} from "../src/constants.js";
import { acceptHistoricalReconstruction } from "../src/gateway.js";
import { privacyIssuesFor } from "../src/privacy.js";
import { clone, generalizedProse, validContext, validPacket } from "./fixtures.js";

async function schema(name: string) {
  return JSON.parse(await readFile(new URL(`../schema/${name}.schema.json`, import.meta.url), "utf8"));
}

function stringsWithOversizedPublishedBounds(value: any, path = "schema", found: string[] = []): string[] {
  if (!value || typeof value !== "object") return found;
  if (value.type === "string" && typeof value.maxLength === "number" && value.maxLength > PROTOCOL_MAX_LINE_LENGTH) found.push(`${path} (${value.maxLength})`);
  for (const [key, child] of Object.entries(value.properties ?? {})) stringsWithOversizedPublishedBounds(child, `${path}.${key}`, found);
  if (value.items) stringsWithOversizedPublishedBounds(value.items, `${path}[]`, found);
  for (const [index, child] of (value.anyOf ?? []).entries()) stringsWithOversizedPublishedBounds(child, `${path}.anyOf[${index}]`, found);
  return found;
}

test("no current public schema publishes a string bound above the scanner line boundary", async () => {
  for (const name of [`reconstruction-packet-${RECONSTRUCTION_PACKET_SCHEMA_VERSION}`, `project-state-reconstruction-${PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION}`]) {
    assert.deepEqual(stringsWithOversizedPublishedBounds(await schema(name)), [], name);
  }
});

test("the Project State public relative-path contract excludes embedded line breaks", async () => {
  const published = await schema(`project-state-reconstruction-${PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION}`);
  const node = published.properties.provenance_index.items.properties.relative_path;
  const relativePath = node.type === "string" ? node : node.anyOf.find((variant: any) => variant.type === "string");
  assert.equal(relativePath.maxLength, 300);
  assert.match(relativePath.pattern, /\\r/);
  assert.match(relativePath.pattern, /\\n/);
  assert.match(relativePath.pattern, /2028/);
  assert.match(relativePath.pattern, /2029/);
});

const providers = ["chatgpt", "claude", "codex"] as const;

function historical(provider: typeof providers[number]) {
  const packet: any = clone(validPacket());
  const context: any = clone(validContext());
  packet.provider = provider;
  packet.provider_provenance.provider = provider;
  context.expected_provider = provider;
  return { packet, context };
}

const narrativeTargets = [
  { name: "project summary", path: "project_summary.description", set: (packet: any, value: string) => { packet.project_summary.description = value; } },
  { name: "coverage limitation", path: "coverage_perimeter.limitations.0", set: (packet: any, value: string) => { packet.coverage_perimeter.limitations = [value]; } },
  { name: "provenance limitation", path: "provenance_index.0.limitations.0", set: (packet: any, value: string) => { packet.provenance_index[0].limitations = [value]; } },
  { name: "evidence description", path: "evidence.meaningful_moments.0.description", set: (packet: any, value: string) => { packet.evidence.meaningful_moments[0].description = value; } },
  { name: "resulting state", path: "evidence.meaningful_moments.0.resulting_state", set: (packet: any, value: string) => { packet.evidence.meaningful_moments[0].resulting_state = value; } },
  { name: "decision outcome", path: "evidence.decisions.0.outcome", set: (packet: any, value: string) => { packet.evidence.decisions[0].outcome = value; } },
  { name: "validation method", path: "evidence.validation_and_outcomes.0.validation_method", set: (packet: any, value: string) => { packet.evidence.validation_and_outcomes[0].validation_method = value; } },
  { name: "validation outcome", path: "evidence.validation_and_outcomes.0.outcome", set: (packet: any, value: string) => { packet.evidence.validation_and_outcomes[0].outcome = value; } },
  { name: "capability narrative", path: "evidence.capability_evidence.0.narrative_basis", set: (packet: any, value: string) => { packet.evidence.capability_evidence[0].narrative_basis = value; } },
  { name: "origin basis", path: "evidence.origin_traces.0.generalized_basis", set: (packet: any, value: string) => { packet.evidence.origin_traces[0].generalized_basis = value; } },
  { name: "provider limitation", path: "provider_limitations.0", set: (packet: any, value: string) => { packet.provider_limitations = [value]; } },
] as const;

test("Reconstruction narrative fields expose the same reachable 420-character boundary for every provider", async () => {
  for (const provider of providers) for (const target of narrativeTargets) {
    const atLimit = historical(provider);
    target.set(atLimit.packet, generalizedProse(PROTOCOL_MAX_LINE_LENGTH));
    assert.equal((await acceptHistoricalReconstruction(atLimit.packet, atLimit.context)).status, "accept", `${provider}: ${target.name} at limit`);

    const overLimit = historical(provider);
    target.set(overLimit.packet, generalizedProse(PROTOCOL_MAX_LINE_LENGTH + 1));
    const result = await acceptHistoricalReconstruction(overLimit.packet, overLimit.context);
    assert.equal(result.status, "reject", `${provider}: ${target.name} over limit`);
    if (result.status === "reject") {
      assert.equal(result.category, "invalid_schema", `${provider}: ${target.name}: ${JSON.stringify(result.issues)}`);
      assert.ok(result.issues.some((issue) => issue.startsWith(`${target.path}:`) && issue.includes(String(PROTOCOL_MAX_LINE_LENGTH))), `${provider}: ${target.name}: ${JSON.stringify(result.issues)}`);
      assert.ok(result.issues.every((issue) => !issue.includes("source_sized_line")), JSON.stringify(result.issues));
    }
  }
});

test("Reconstruction narrative fields reject line breaks with field-specific content-free diagnostics", async () => {
  for (const provider of providers) for (const target of narrativeTargets) {
    const { packet, context } = historical(provider);
    target.set(packet, "generalized first line\ngeneralized second line");
    const result = await acceptHistoricalReconstruction(packet, context);
    assert.equal(result.status, "reject");
    if (result.status === "reject") {
      assert.equal(result.category, "invalid_schema");
      assert.ok(result.issues.some((issue) => issue.startsWith(`${target.path}:`)), JSON.stringify(result.issues));
      assert.ok(result.issues.every((issue) => !issue.includes("generalized first")), JSON.stringify(result.issues));
    }
  }
});

test("normalization precedes the Reconstruction narrative boundary", async () => {
  const atLimit = historical("claude");
  atLimit.packet.project_summary.description = `${"ﬃ ".repeat(104)}ﬃx`;
  assert.equal((await acceptHistoricalReconstruction(atLimit.packet, atLimit.context)).status, "accept");
  atLimit.packet.project_summary.description += "ﬃ";
  const result = await acceptHistoricalReconstruction(atLimit.packet, atLimit.context);
  assert.equal(result.status, "reject");
  if (result.status === "reject") assert.equal(result.category, "invalid_schema");
});

test("the scanner's direct line rule remains fail-closed at 421 characters", () => {
  assert.deepEqual(privacyIssuesFor({ narrative: generalizedProse(PROTOCOL_MAX_LINE_LENGTH) }, "probe"), []);
  assert.deepEqual(privacyIssuesFor({ narrative: generalizedProse(PROTOCOL_MAX_LINE_LENGTH + 1) }, "probe"), ["probe.narrative: source_sized_line"]);
  assert.deepEqual(privacyIssuesFor({ narrative: `${generalizedProse(PROTOCOL_MAX_LINE_LENGTH)}\u2028x` }, "probe"), []);
  assert.deepEqual(privacyIssuesFor({ narrative: `${generalizedProse(PROTOCOL_MAX_LINE_LENGTH + 1)}\u2028x` }, "probe"), ["probe.narrative: source_sized_line"]);
});
