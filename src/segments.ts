import { canonicalize, sha256Hex } from "./canonical.js";

export const LOGICAL_CONTENT_SEGMENT_FORMAT = "tracework.logical-content-segments/v1" as const;
export const LOGICAL_CONTENT_SEGMENT_TARGET_BYTES = 128 * 1024;

export type LogicalContentSegment = {
  ordinal: number;
  utf8_bytes: number;
  content_sha256: string;
  content: string;
};

export type LogicalContentSegmentManifest = {
  format: typeof LOGICAL_CONTENT_SEGMENT_FORMAT;
  encoding: "utf-8";
  logical_content_sha256: string;
  logical_utf8_bytes: number;
  segment_count: number;
  segment_target_bytes: number;
  segment_sha256: string[];
};

const encoder = new TextEncoder();

export async function segmentLogicalContent(content: string, targetBytes = LOGICAL_CONTENT_SEGMENT_TARGET_BYTES) {
  if (!Number.isSafeInteger(targetBytes) || targetBytes < 1024) throw new Error("Logical-content segment target must be at least 1024 bytes");
  const values: string[] = [];
  let current = "";
  let currentBytes = 0;
  for (const character of content) {
    const bytes = encoder.encode(character).byteLength;
    if (current && currentBytes + bytes > targetBytes) { values.push(current); current = ""; currentBytes = 0; }
    current += character; currentBytes += bytes;
  }
  if (current || !values.length) values.push(current);
  const segments: LogicalContentSegment[] = [];
  for (const [ordinal, value] of values.entries()) segments.push({ ordinal, utf8_bytes: encoder.encode(value).byteLength, content_sha256: await sha256Hex(value), content: value });
  const logicalBytes = encoder.encode(content).byteLength;
  const manifest: LogicalContentSegmentManifest = {
    format: LOGICAL_CONTENT_SEGMENT_FORMAT,
    encoding: "utf-8",
    logical_content_sha256: await sha256Hex(content),
    logical_utf8_bytes: logicalBytes,
    segment_count: segments.length,
    segment_target_bytes: targetBytes,
    segment_sha256: segments.map((segment) => segment.content_sha256),
  };
  return { manifest, segments, storage_manifest: canonicalize(manifest) } as const;
}

export async function reassembleLogicalContent(manifest: LogicalContentSegmentManifest, segments: readonly LogicalContentSegment[]) {
  if (manifest.format !== LOGICAL_CONTENT_SEGMENT_FORMAT || manifest.encoding !== "utf-8") throw new Error("Unsupported logical-content segment manifest");
  const ordered = [...segments].sort((left, right) => left.ordinal - right.ordinal);
  if (ordered.length !== manifest.segment_count) throw new Error("Logical-content segment count mismatch");
  for (const [ordinal, segment] of ordered.entries()) {
    if (segment.ordinal !== ordinal || manifest.segment_sha256[ordinal] !== segment.content_sha256) throw new Error("Logical-content segment ordering or manifest mismatch");
    if (encoder.encode(segment.content).byteLength !== segment.utf8_bytes || await sha256Hex(segment.content) !== segment.content_sha256) throw new Error("Logical-content segment integrity mismatch");
  }
  const content = ordered.map((segment) => segment.content).join("");
  if (encoder.encode(content).byteLength !== manifest.logical_utf8_bytes || await sha256Hex(content) !== manifest.logical_content_sha256) throw new Error("Logical-content reconstruction digest mismatch");
  return content;
}

export function isLogicalContentSegmentManifest(value: unknown): value is LogicalContentSegmentManifest {
  return Boolean(value && typeof value === "object" && (value as { format?: unknown }).format === LOGICAL_CONTENT_SEGMENT_FORMAT);
}
