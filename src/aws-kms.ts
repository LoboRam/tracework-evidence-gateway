import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import type { ReceiptSigner } from "./receipts.js";

export type AwsKmsReceiptSignerOptions = Readonly<{
  keyId: string;
  kmsKeyId: string;
  client?: KMSClient;
  region?: string;
}>;

export class AwsKmsReceiptSigner implements ReceiptSigner {
  readonly algorithm = "Ed25519" as const;
  readonly keyId: string;
  readonly #kmsKeyId: string;
  readonly #client: KMSClient;

  constructor(options: AwsKmsReceiptSignerOptions) {
    this.keyId = options.keyId;
    this.#kmsKeyId = options.kmsKeyId;
    this.#client = options.client ?? new KMSClient(options.region ? { region: options.region } : {});
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    const result = await this.#client.send(new SignCommand({
      KeyId: this.#kmsKeyId,
      Message: message,
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    }));
    if (!result.Signature) throw new Error("AWS KMS returned no receipt signature");
    return result.Signature;
  }
}
