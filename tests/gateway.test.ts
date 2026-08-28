import assert from "node:assert/strict";
import test from "node:test";
import { acceptHistoricalReconstruction } from "../src/gateway.js";
import { clone, validContext, validPacket } from "./fixtures.js";

test("valid sanitized packet is accepted deterministically", async () => {
  const first = await acceptHistoricalReconstruction(validPacket(), validContext());
  const second = await acceptHistoricalReconstruction(validPacket(), validContext());
  assert.equal(first.status, "accept");
  assert.equal(second.status, "accept");
  if (first.status === "accept" && second.status === "accept") {
    assert.equal(first.accepted.canonical_packet, second.accepted.canonical_packet);
    assert.equal(first.accepted.accepted_packet_digest, second.accepted.accepted_packet_digest);
  }
});

const schemaMutations: Array<[string, (packet: any) => void]> = [
  ["unknown top-level field", (packet) => { packet._enum_reference = {}; }],
  ["unknown nested field", (packet) => { packet.project_summary.unexpected = true; }],
  ["invalid enum", (packet) => { packet.coverage_perimeter.coverage_confidence = "complete"; }],
  ["source assigns cross_source_confirmed", (packet) => { packet.project_summary.claim_basis = "cross_source_confirmed"; }],
  ["invalid packet identity", (packet) => { packet.reconstruction_packet_schema_version = "2.0.0"; }],
  ["private source detail", (packet) => { packet.provenance_index[0].source_detail = "C:/private/repository"; }],
];

for (const [name, mutate] of schemaMutations) test(`${name} is rejected`, async () => {
  const packet: any = clone(validPacket()); mutate(packet);
  const result = await acceptHistoricalReconstruction(packet, validContext());
  assert.equal(result.status, "reject");
});

test("duplicate IDs and dangling references are rejected", async () => {
  const duplicate: any = clone(validPacket());
  duplicate.evidence.ai_observations[0].evidence_id = "human_1";
  assert.equal((await acceptHistoricalReconstruction(duplicate, validContext())).status, "reject");
  const dangling: any = clone(validPacket());
  dangling.evidence.meaningful_moments[0].evidence_refs = ["missing"];
  assert.equal((await acceptHistoricalReconstruction(dangling, validContext())).status, "reject");
});

test("identity, provider, coverage pass and manifest mismatches are rejected", async () => {
  for (const mutate of [
    (packet: any) => { packet.project_id = "other_project"; },
    (packet: any) => { packet.provider = "chatgpt"; packet.provider_provenance.provider = "chatgpt"; },
    (packet: any) => { packet.coverage_perimeter.recovery_pass_ids = ["pass_other"]; packet.provenance_index[0].recovery_pass_id = "pass_other"; },
    (packet: any) => { packet.coverage_perimeter.manifest_ids = ["manifest_other"]; packet.provenance_index[0].manifest_id = "manifest_other"; },
  ]) {
    const packet: any = clone(validPacket()); mutate(packet);
    assert.equal((await acceptHistoricalReconstruction(packet, validContext())).status, "reject");
  }
});
