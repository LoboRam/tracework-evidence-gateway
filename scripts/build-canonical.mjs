import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { basename, join, relative } from "node:path";

const root = new URL("..", import.meta.url).pathname.replace(/^\/(.:)/, "$1");
const dist = join(root, "dist");
const artifactDirectory = join(root, "artifact");
const hash = (value) => createHash("sha256").update(value).digest("hex");
const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const output = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path)); else output.push(path);
  }
  return output;
}

const coreFiles = (await walk(dist))
  .filter((path) => !["provenance.js", "provenance.d.ts"].includes(basename(path)))
  .sort((left, right) => relative(dist, left) < relative(dist, right) ? -1 : relative(dist, left) > relative(dist, right) ? 1 : 0);
const includedFiles = [];
for (const path of coreFiles) {
  const bytes = await readFile(path);
  includedFiles.push({ path: relative(dist, path).replaceAll("\\", "/"), sha256: hash(bytes), content_base64: bytes.toString("base64") });
}
const canonical = `${JSON.stringify({ format: "tracework-evidence-gateway-canonical-v1", hashing_algorithm: "SHA-256", included_files: includedFiles })}\n`;
const artifactDigest = hash(Buffer.from(canonical, "utf8"));
await mkdir(artifactDirectory, { recursive: true });
await writeFile(join(artifactDirectory, "tracework-evidence-gateway.canonical.json"), canonical, "utf8");

let sourceCommit = "0000000000000000000000000000000000000000";
let releaseTag = "unreleased";
let sourceTimestamp = "1970-01-01T00:00:00.000Z";
try {
  sourceCommit = git("rev-parse", "HEAD");
  releaseTag = process.env.TRACEWORK_GATEWAY_RELEASE_TAG || git("describe", "--tags", "--exact-match", "HEAD");
  sourceTimestamp = new Date(Number(git("show", "-s", "--format=%ct", "HEAD")) * 1000).toISOString();
} catch {
  releaseTag = process.env.TRACEWORK_GATEWAY_RELEASE_TAG || "unreleased";
}
const provenance = {
  gateway_package_version: "1.0.3",
  public_repository_url: "https://github.com/LoboRam/tracework-evidence-gateway",
  source_commit: sourceCommit,
  release_tag: releaseTag,
  canonical_artifact_format: "tracework-evidence-gateway-canonical-v1",
  canonical_artifact_sha256: artifactDigest,
  reconstruction_packet_schema_version: "2.1.0",
  reconstruction_protocol_version: "historical-0.4",
  provenance_schema_version: "1.0.0",
  privacy_contract_compatibility: "1.0.0",
  source_timestamp: sourceTimestamp,
};
await writeFile(join(dist, "provenance.js"), `export const GATEWAY_RUNTIME_PROVENANCE = Object.freeze(${JSON.stringify(provenance)});\n`, "utf8");
await writeFile(join(dist, "provenance.d.ts"), `export declare const GATEWAY_RUNTIME_PROVENANCE: Readonly<${JSON.stringify(Object.fromEntries(Object.keys(provenance).map((key) => [key, "string"]))).replaceAll('"string"', "string")}>;\n`, "utf8");
await writeFile(join(artifactDirectory, "release-provenance.json"), `${JSON.stringify(provenance, null, 2)}\n`, "utf8");
await writeFile(join(artifactDirectory, "SHA256SUMS"), `${artifactDigest}  tracework-evidence-gateway.canonical.json\n`, "utf8");
process.stdout.write(`${artifactDigest}\n`);
