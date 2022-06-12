import { randomBytes, secretbox, sign, SignKeyPair } from "tweetnacl";
import { convertKeyPair } from "ed2curve-esm";
import type { SignWallet } from "./wallet";
import * as crypto from "crypto";
import * as base64 from "@stablelib/base64";

const PUBLIC_STRING_LENGTH = 32;
export const newNonce = () => randomBytes(secretbox.nonceLength);

// Generate a string that will seed the "lexi magic". This is assumed to be public knowledge.
export const singleUsePublicString = () =>
  base64.encode(randomBytes(PUBLIC_STRING_LENGTH));

export const DEFAULT_FRIENDLY_MESSAGE = "";

export const SHA256D = async (input: Uint8Array): Promise<Uint8Array> => {
  const first = crypto.createHash("sha256");
  const second = crypto.createHash("sha256");
  first.update(input);
  second.update(first.digest());
  return second.digest();
};

export class SignWalletWithKey implements SignWallet {
  private signKey: SignKeyPair;

  constructor(signKey: SignKeyPair) {
    this.signKey = signKey;
  }

  async signMessage(message: Uint8Array): Promise<Uint8Array> {
    return sign.detached(message, this.signKey.secretKey);
  }
}

/**
 * The "lexi magic":
 * Sign and hash a non-secret public string with an asymmetric secret key, creating the secret for the encryption key
 * @param signer
 */
export const generateKeyFromSignature = async (
  signer: SignWallet,
  signatureInput: string
): Promise<Uint8Array> => {
  const signature = await signer.signMessage(
    new TextEncoder().encode(signatureInput)
  );

  // Hash the signature to standardise it to 32 bytes
  // using tweetnacl for hashing creates a 64 byte hash, so we use the native crypto lib here instead
  // return hash(secret);
  return SHA256D(signature);
};

export const generateX25519KeyPairFromSignature = async (
  signer: SignWallet,
  signatureInput: string
): Promise<nacl.BoxKeyPair> => {
  const key = await generateKeyFromSignature(signer, signatureInput);
  const ed25519Keypair = sign.keyPair.fromSeed(key);
  return convertKeyPair(ed25519Keypair);
};
