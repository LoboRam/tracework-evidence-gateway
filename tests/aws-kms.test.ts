import assert from "node:assert/strict";
import test from "node:test";
import { AwsKmsReceiptSigner } from "../src/aws-kms.js";

test("AWS KMS adapter signs only a structured Sign request with deterministic SigV4 metadata", async () => {
  let capturedUrl = "";
  let capturedInit: RequestInit | undefined;
  const expected = Uint8Array.from([1, 2, 3, 4]);
  const signer = new AwsKmsReceiptSigner({
    keyId: "receipt-key-test",
    kmsKeyId: "arn:aws:kms:us-west-2:123456789012:key/test",
    region: "us-west-2",
    credentials: { accessKeyId: "AKIATEST", secretAccessKey: "test-secret", sessionToken: "test-session" },
    now: () => new Date("2026-08-17T12:34:56.000Z"),
    fetch: async (url, init) => {
      capturedUrl = String(url); capturedInit = init;
      return new Response(JSON.stringify({ Signature: Buffer.from(expected).toString("base64") }), { status: 200 });
    },
  });
  assert.deepEqual(await signer.sign(new TextEncoder().encode("canonical receipt claims")), expected);
  assert.equal(capturedUrl, "https://kms.us-west-2.amazonaws.com/");
  assert.equal(capturedInit?.method, "POST");
  const headers = capturedInit?.headers as Record<string, string>;
  assert.equal(headers["x-amz-target"], "TrentService.Sign");
  assert.equal(headers["x-amz-date"], "20260817T123456Z");
  assert.equal(headers["x-amz-security-token"], "test-session");
  assert.match(headers.authorization ?? "", /^AWS4-HMAC-SHA256 Credential=AKIATEST\/20260817\/us-west-2\/kms\/aws4_request,/);
  assert.deepEqual(JSON.parse(String(capturedInit?.body)), {
    KeyId: "arn:aws:kms:us-west-2:123456789012:key/test",
    Message: "Y2Fub25pY2FsIHJlY2VpcHQgY2xhaW1z",
    MessageType: "RAW",
    SigningAlgorithm: "ED25519_SHA_512",
  });
});

test("AWS KMS adapter reports only a safe failure category", async () => {
  const signer = new AwsKmsReceiptSigner({
    keyId: "receipt-key-test", kmsKeyId: "key", region: "us-west-2",
    credentials: { accessKeyId: "AKIATEST", secretAccessKey: "test-secret" },
    fetch: async () => new Response(JSON.stringify({ __type: "AccessDeniedException", message: "sensitive provider detail" }), { status: 400 }),
  });
  await assert.rejects(signer.sign(new Uint8Array([1])), /^Error: AWS KMS receipt signing failed: AccessDeniedException$/);
});
