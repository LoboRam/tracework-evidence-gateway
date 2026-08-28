import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION, RECONSTRUCTION_PACKET_SCHEMA_VERSION } from "../src/constants.js";
import { acceptHistoricalReconstruction } from "../src/gateway.js";
import { privacyIssuesFor } from "../src/privacy.js";
import { reassembleLogicalContent } from "../src/segments.js";
import { clone, generalizedProse, validContext, validPacket } from "./fixtures.js";

async function schema(name: string) { return JSON.parse(await readFile(new URL(`../schema/${name}.schema.json`, import.meta.url), "utf8")); }

function artificialCapacityLimits(value: any, path = "schema", found: string[] = []): string[] {
  if (!value || typeof value !== "object") return found;
  if (typeof value.maxLength === "number" || typeof value.maxItems === "number") found.push(path);
  for (const [key, child] of Object.entries(value.properties ?? {})) artificialCapacityLimits(child, `${path}.${key}`, found);
  if (value.items) artificialCapacityLimits(value.items, `${path}[]`, found);
  for (const [index, child] of (value.anyOf ?? []).entries()) artificialCapacityLimits(child, `${path}.anyOf[${index}]`, found);
  return found;
}

test("public reconstruction schemas contain no artificial narrative or collection ceilings", async () => {
  for (const name of [`reconstruction-packet-${RECONSTRUCTION_PACKET_SCHEMA_VERSION}`, `project-state-reconstruction-${PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION}`]) {
    const limits = artificialCapacityLimits(await schema(name)).filter((path) => !/(?:^|[._])(?:[a-z_]*id|[a-z_]*ids)(?:$|\[|\.)|ref|handle|fingerprint|analyst|concept_key/.test(path));
    assert.deepEqual(limits, [], `${name}: ${limits.join(", ")}`);
  }
});

test("Project State relative paths remain privacy-safe without a size ceiling", async () => {
  const published = await schema(`project-state-reconstruction-${PROJECT_STATE_RECONSTRUCTION_SCHEMA_VERSION}`);
  const node = published.properties.provenance_index.items.properties.relative_path;
  const relativePath = node.type === "string" ? node : node.anyOf.find((variant: any) => variant.type === "string");
  assert.equal(relativePath.maxLength, undefined);
  assert.match(relativePath.pattern, /\\r/); assert.match(relativePath.pattern, /\\n/); assert.match(relativePath.pattern, /2028/); assert.match(relativePath.pattern, /2029/);
});

const providers = ["chatgpt", "claude", "codex"] as const;
test("multi-megabyte legitimate historical narrative is accepted and deterministically segmented for every analyst", async () => {
  const narrative = generalizedProse(2_400_000);
  for (const provider of providers) {
    const packet: any = clone(validPacket()); const context: any = clone(validContext());
    packet.provider = provider; packet.provider_provenance.provider = provider; context.expected_provider = provider;
    packet.project_summary.description = narrative;
    const result = await acceptHistoricalReconstruction(packet, context);
    assert.equal(result.status, "accept", provider);
    if (result.status === "accept") {
      assert.ok(result.accepted.canonical_segments.length > 10);
      assert.equal(await reassembleLogicalContent(result.accepted.canonical_segment_manifest, result.accepted.canonical_segments), result.accepted.canonical_packet);
      assert.equal(result.accepted.canonical_segment_manifest.logical_content_sha256, result.accepted.accepted_packet_digest);
    }
  }
});

test("large legitimate prose is never a privacy finding merely because of length or line count", () => {
  assert.deepEqual(privacyIssuesFor({ narrative: generalizedProse(2_400_000) }, "probe"), []);
  assert.deepEqual(privacyIssuesFor({ narrative: `${generalizedProse(600_000)}\n${generalizedProse(600_000)}` }, "probe"), []);
});

test("actual prohibited content still fails independently of size", async () => {
  const packet: any = clone(validPacket());
  packet.project_summary.description = `${generalizedProse(800_000)}\npassword=distinctivesecretvalue`;
  const result = await acceptHistoricalReconstruction(packet, validContext());
  assert.equal(result.status, "reject");
  if (result.status === "reject") { assert.equal(result.category, "privacy_rejection"); assert.ok(result.issues.some((issue) => issue.includes("credential_assignment"))); }
});
