import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const path = new URL("../artifact/tracework-evidence-gateway.canonical.json", import.meta.url);
const bytes = await readFile(path);
const actual = createHash("sha256").update(bytes).digest("hex");
const sums = await readFile(new URL("../artifact/SHA256SUMS", import.meta.url), "utf8");
const expected = sums.trim().split(/\s+/)[0];
if (actual !== expected) throw new Error(`Canonical artifact mismatch: expected ${expected}, got ${actual}`);
const parsed = JSON.parse(bytes.toString("utf8"));
if (parsed.format !== "tracework-evidence-gateway-canonical-v1") throw new Error("Unexpected canonical artifact format");
process.stdout.write(`${actual}\n`);
