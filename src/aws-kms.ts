import type { ReceiptSigner } from "./receipts.js";

export type AwsKmsCredentials = Readonly<{
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}>;

export type AwsKmsReceiptSignerOptions = Readonly<{
  keyId: string;
  kmsKeyId: string;
  region: string;
  credentials: AwsKmsCredentials;
  fetch?: typeof globalThis.fetch;
  now?: () => Date;
}>;

const encoder = new TextEncoder();

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string | Uint8Array): Promise<ArrayBuffer> {
  const bytes = typeof value === "string" ? encoder.encode(value) : Uint8Array.from(value);
  return crypto.subtle.digest("SHA-256", bytes as BufferSource);
}

async function hmac(key: Uint8Array | ArrayBuffer, value: string): Promise<ArrayBuffer> {
  const keyBytes = key instanceof Uint8Array ? Uint8Array.from(key) : key;
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(value));
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function awsTimestamp(date: Date): { date: string; dateTime: string } {
  const iso = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return { date: iso.slice(0, 8), dateTime: iso };
}

/**
 * Signs canonical Tracework receipt claims through the AWS KMS JSON API.
 *
 * The adapter deliberately uses Web Crypto + fetch instead of the AWS SDK so
 * the same reviewed implementation runs in Node and standards-based edge
 * runtimes. Credentials authorize only the remote KMS Sign call; asymmetric
 * private key material remains non-exportable inside AWS KMS.
 */
export class AwsKmsReceiptSigner implements ReceiptSigner {
  readonly algorithm = "Ed25519" as const;
  readonly keyId: string;
  readonly #kmsKeyId: string;
  readonly #region: string;
  readonly #credentials: AwsKmsCredentials;
  readonly #fetch: typeof globalThis.fetch;
  readonly #now: () => Date;

  constructor(options: AwsKmsReceiptSignerOptions) {
    this.keyId = options.keyId;
    this.#kmsKeyId = options.kmsKeyId;
    this.#region = options.region;
    this.#credentials = options.credentials;
    this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.#now = options.now ?? (() => new Date());
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    const host = `kms.${this.#region}.amazonaws.com`;
    const endpoint = `https://${host}/`;
    const body = JSON.stringify({
      KeyId: this.#kmsKeyId,
      Message: base64(message),
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    });
    const { date, dateTime } = awsTimestamp(this.#now());
    const payloadHash = hex(await sha256(body));
    const headers: Record<string, string> = {
      "content-type": "application/x-amz-json-1.1",
      host,
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": dateTime,
      "x-amz-target": "TrentService.Sign",
    };
    if (this.#credentials.sessionToken) headers["x-amz-security-token"] = this.#credentials.sessionToken;
    const signedHeaderNames = Object.keys(headers).sort();
    const canonicalHeaders = signedHeaderNames.map((name) => `${name}:${headers[name]!.trim()}\n`).join("");
    const signedHeaders = signedHeaderNames.join(";");
    const canonicalRequest = ["POST", "/", "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
    const scope = `${date}/${this.#region}/kms/aws4_request`;
    const stringToSign = ["AWS4-HMAC-SHA256", dateTime, scope, hex(await sha256(canonicalRequest))].join("\n");
    const dateKey = await hmac(encoder.encode(`AWS4${this.#credentials.secretAccessKey}`), date);
    const regionKey = await hmac(dateKey, this.#region);
    const serviceKey = await hmac(regionKey, "kms");
    const signingKey = await hmac(serviceKey, "aws4_request");
    const signature = hex(await hmac(signingKey, stringToSign));
    const authorization = `AWS4-HMAC-SHA256 Credential=${this.#credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const response = await this.#fetch(endpoint, { method: "POST", headers: { ...headers, authorization }, body });
    const result = await response.json() as { Signature?: string; __type?: string; message?: string; Message?: string };
    if (!response.ok) {
      const category = (result.__type ?? "AwsKmsSignError").split("#").at(-1);
      throw new Error(`AWS KMS receipt signing failed: ${category}`);
    }
    if (!result.Signature) throw new Error("AWS KMS returned no receipt signature");
    return fromBase64(result.Signature);
  }
}
