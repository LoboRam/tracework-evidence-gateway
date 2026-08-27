import { PROTOCOL_MAX_LINE_LENGTH } from "./constants.js";
const forbiddenPatterns: ReadonlyArray<readonly [RegExp, string]> = [
  [/(?:^|\n)(?:User|Assistant|Human|Claude|ChatGPT|System):\s.*\n(?:User|Assistant|Human|Claude|ChatGPT|System):\s/im, "raw_transcript"],
  [/(?:sk|rk|pk)-(?:live|test|proj)?[_-]?[A-Za-z0-9_-]{16,}/i, "possible_api_credential"], [/(?:ghp|github_pat|xox[baprs]|AKIA)[A-Za-z0-9_-]{12,}/i, "possible_service_credential"], [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i, "private_key"], [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i, "bearer_token"], [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/, "json_web_token"], [/(?:api[_ -]?key|password|secret|access[_ -]?token)\s*[:=]\s*["']?[A-Za-z0-9_./+\-=]{8,}/i, "credential_assignment"], [/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, "email_address"], [/\b(?:\d[ -]*?){13,19}\b/, "possible_payment_card"], [/\b\d{3}-\d{2}-\d{4}\b/, "possible_government_identifier"], [/(?:https?:\/\/)(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])|[^/\s]+\.(?:internal|local))[^\s]*/i, "private_url"], [/```(?:[A-Za-z0-9_-]+)?\s*[\s\S]*?```/, "source_code_block"], [/\b(?:User|Assistant|Human|Claude|ChatGPT|System):\s.{8,}?\b(?:User|Assistant|Human|Claude|ChatGPT|System):\s/i, "raw_transcript"], [/(?:^|\n)(?:prompt|response|completion)\s*:\s*.{80,}(?:\n|$)/i, "raw_prompt_dump"], [/\[\s*\{[^{}\n]{0,120}["']role["']\s*:\s*["'](?:user|assistant|system)["'][\s\S]{0,240}["']content["']\s*:/i, "serialized_message_array"], [/\bdiff --git\s+a\/[^\s]+\s+b\/[^\s]+[\s\S]{40,}(?:@@|index\s+[a-f0-9]+)/i, "repository_diff"], [/(?:^|\n)(?:FILE|PATH):\s*[^\n]+\n[\s\S]{160,}(?:^|\n)(?:FILE|PATH):\s*[^\n]+/im, "bulk_file_payload"], [/\b[A-Za-z]:[\\/](?:[^<>:"|?*\r\n]+[\\/])*[^<>:"|?*\r\n]*/i, "absolute_filesystem_path"], [/(?:^|[\s("'=])\/(?:Users|home|root|etc|var|opt|srv|tmp|private|mnt|Volumes|workspace|workspaces)(?:\/[^\s"'<>|]+)+/i, "absolute_filesystem_path"],
];

const explicitSourceSyntax = [
  /\b(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\([^)]{0,160}\)\s*\{/,
  /\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?(?:\([^)]{0,160}\)|[A-Za-z_$][\w$]*)\s*=>/,
  /\b(?:import|export)\s+.{1,160}\s+from\s+["'][^"']+["']/,
  /\b(?:class|interface|type)\s+[A-Za-z_$][\w$]*[^\n]{0,80}(?:\{|=)/,
  /\bdef\s+[A-Za-z_][\w]*\s*\([^)]{0,160}\)\s*:/,
  /\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|CREATE\s+TABLE|UPDATE\s+\w+\s+SET)\b/i,
  /\b(?:console\.log|print|printf|System\.out\.println)\s*\(/,
];

function looksLikeSourceCode(value: string): boolean {
  if (explicitSourceSyntax.some((pattern) => pattern.test(value))) return true;
  const structuralSignals = (value.match(/[{};]|=>/g) ?? []).length;
  const keywordSignals = (value.match(/\b(?:const|let|var|function|class|interface|import|export|return|def|lambda|SELECT|INSERT|UPDATE|CREATE TABLE)\b/gi) ?? []).length;
  const quotedObjectKeys = (value.match(/["'][^"'\r\n]{1,80}["']\s*:/g) ?? []).length;
  return (structuralSignals >= 2 && keywordSignals >= 2) || (structuralSignals >= 4 && keywordSignals >= 1) || (value.trimStart().startsWith("{") && quotedObjectKeys >= 2);
}

function looksLikeSingleLineFilePayload(value: string): boolean {
  return /^(?:FILE|PATH):\s*\S+\s+.{80,}$/i.test(value) && /\b(?:const|let|var|function|class|import|export|return|password|secret|api[_ -]?key)\b/i.test(value);
}

export function collectProtocolStrings(value: unknown, path = "payload", output: Array<{ path: string; value: string }> = []) {
  if (typeof value === "string") output.push({ path, value });
  else if (Array.isArray(value)) value.forEach((item, index) => collectProtocolStrings(item, `${path}[${index}]`, output));
  else if (value && typeof value === "object") Object.entries(value).forEach(([key, item]) => collectProtocolStrings(item, `${path}.${key}`, output));
  return output;
}

export function privacyIssuesFor(value: unknown, root = "payload"): string[] {
  const issues: string[] = [];
  for (const item of collectProtocolStrings(value, root)) {
    if (item.value.length > 180 && /^[A-Za-z0-9+/=_-]+$/.test(item.value) && item.value.length % 4 === 0) issues.push(`${item.path}: suspicious_encoded_blob`);
    if (item.value.split(/[\r\n\u2028\u2029]/).some((line) => line.length > PROTOCOL_MAX_LINE_LENGTH)) issues.push(`${item.path}: source_sized_line`);
    if (looksLikeSourceCode(item.value)) issues.push(`${item.path}: likely_source_code`);
    if (looksLikeSingleLineFilePayload(item.value)) issues.push(`${item.path}: raw_file_payload`);
    for (const [pattern, category] of forbiddenPatterns) if (pattern.test(item.value)) issues.push(`${item.path}: ${category}`);
  }
  return [...new Set(issues)];
}
