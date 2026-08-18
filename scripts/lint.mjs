import { readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const output = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await files(path));
    else if ([".ts", ".mjs", ".json", ".md", ".yml"].includes(extname(entry.name))) output.push(path);
  }
  return output;
}

const roots = ["src", "scripts", "tests", "docs", ".github"].filter(async () => true);
const candidates = [];
for (const root of roots) {
  try { candidates.push(...await files(root)); } catch { /* optional directory */ }
}
const issues = [];
for (const path of candidates) {
  const content = await readFile(path, "utf8");
  if (content.includes("\r\n")) issues.push(`${path}: CRLF is not canonical`);
  content.split("\n").forEach((line, index) => { if (/\s+$/.test(line)) issues.push(`${path}:${index + 1}: trailing whitespace`); });
  const unresolvedMarker = new RegExp(`\\b(?:${"TO" + "DO"}|${"FIX" + "ME"})\\b`);
  if (unresolvedMarker.test(content)) issues.push(`${path}: unresolved work marker`);
}
if (issues.length) {
  process.stderr.write(`${issues.join("\n")}\n`);
  process.exit(1);
}
