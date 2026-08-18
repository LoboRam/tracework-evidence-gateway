export function normalizeProtocolPayload(value: unknown): unknown {
  if (typeof value === "string") return value.normalize("NFKC").replace(/\r\n?/g, "\n").replace(/[\t ]+/g, " ").trim();
  if (Array.isArray(value)) return value.map(normalizeProtocolPayload);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalizeProtocolPayload(item)]));
  return value;
}
export function sortProtocolObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortProtocolObject);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map((key) => [key, sortProtocolObject((value as Record<string, unknown>)[key])]));
  return value;
}
export function canonicalize(value: unknown): string { return JSON.stringify(sortProtocolObject(value)); }
export async function sha256Hex(value: string | Uint8Array): Promise<string> { const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value; const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource); return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""); }
export function utf8(value: string): Uint8Array { return new TextEncoder().encode(value); }
export function fromBase64Url(value: string): Uint8Array { return new Uint8Array(Buffer.from(value, "base64url")); }
