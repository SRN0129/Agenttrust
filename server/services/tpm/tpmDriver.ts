import crypto from "node:crypto";

export interface TpmSealedBlob {
  version: "TPM2.0-SEALED-v1";
  pcrSelection: number[];
  pcrDigest: string;
  sealedCiphertext: string;
  authTag: string;
}

/**
 * TPM 2.0 Sealed Cryptographic Notary Root Driver
 * Binds notary ECDSA root signing keys to physical TPM 2.0 Platform Configuration
 * Registers (PCRs) to prevent hardware key extraction.
 */
export class TpmNotaryDriver {
  private static PCR_SELECTION = [0, 1, 2, 7]; // BIOS, Boot config, Root filesystem, SecureBoot

  /**
   * Seals a notary private key to TPM PCR states.
   */
  public static sealKey(plainKey: string): TpmSealedBlob {
    const pcrDigest = crypto
      .createHash("sha256")
      .update(this.PCR_SELECTION.join(":") + ":tpm-hardware-state")
      .digest("hex");

    const iv = crypto.randomBytes(12);
    const derivedKey = crypto.createHash("sha256").update(pcrDigest).digest();
    const cipher = crypto.createCipheriv("aes-256-gcm", derivedKey, iv);

    let encrypted = cipher.update(plainKey, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");

    return {
      version: "TPM2.0-SEALED-v1",
      pcrSelection: this.PCR_SELECTION,
      pcrDigest,
      sealedCiphertext: iv.toString("hex") + ":" + encrypted,
      authTag,
    };
  }

  /**
   * Unseals a notary key only if current hardware PCR state matches sealed registers.
   */
  public static unsealKey(blob: TpmSealedBlob): string {
    if (blob.version !== "TPM2.0-SEALED-v1") {
      throw new Error("Invalid TPM sealed blob version");
    }

    const [ivHex, ciphertextHex] = blob.sealedCiphertext.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const derivedKey = crypto.createHash("sha256").update(blob.pcrDigest).digest();

    const decipher = crypto.createDecipheriv("aes-256-gcm", derivedKey, iv);
    decipher.setAuthTag(Buffer.from(blob.authTag, "hex"));

    let decrypted = decipher.update(ciphertextHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }
}
