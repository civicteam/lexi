import { randomBytes, secretbox, sign, SignKeyPair } from "tweetnacl";
import { convertKeyPair } from "ed2curve-esm";
import type { SignWallet } from "./wallet";
import * as crypto from "crypto";
import * as base64 from "@stablelib/base64";
import * as utf8 from "@stablelib/utf8";

const PUBLIC_STRING_LENGTH = 32;
export const newNonce = () => randomBytes(secretbox.nonceLength);

// Generate a string that will seed the "lexi magic". This is assumed to be public knowledge.
export const singleUsePublicString = base64.encode(
  randomBytes(PUBLIC_STRING_LENGTH)
);

/**
 * The "normal" way to generate a symmetric key pair
 */
export const generateKey = () =>
  base64.encode(randomBytes(secretbox.keyLength));

const SHA256D = async (input: Uint8Array): Promise<Uint8Array> => {
  const first = crypto.createHash("sha256");
  const second = crypto.createHash("sha256");
  first.update(input);
  second.update(await first.digest());
  return await second.digest();
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
 * @param publicString
 */
export const generateKeyFromSignature = async (
  signer: SignWallet,
  publicString: string
): Promise<Uint8Array> => {
  // first we blind the 'publicString' by hashing to ensure we're not
  // signing arbitrary attacker-provided data:
  const signatureInput = await SHA256D(utf8.encode(publicString));
  const signature = await signer.signMessage(signatureInput);
  // Hash the signature to standardise it to 32 bytes
  // using tweetnacl for hashing creates a 64 byte hash, so we use the native crypto lib here instead
  // return hash(secret);
  return SHA256D(signature);
};

export const generateX25519KeyPairFromSignature = async (
  signer: SignWallet,
  publicString: string
): Promise<nacl.BoxKeyPair> => {
  const key = await generateKeyFromSignature(signer, publicString);
  const ed25519Keypair = sign.keyPair.fromSeed(key);
  return convertKeyPair(ed25519Keypair);
};
