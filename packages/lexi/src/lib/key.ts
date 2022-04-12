import {BoxKeyPair, randomBytes, secretbox, sign, SignKeyPair} from "tweetnacl";
import {convertKeyPair} from "ed2curve-esm";
import type {SignWallet} from "./wallet";
import * as crypto from "crypto";
import * as base64 from "@stablelib/base64";

const PUBLIC_STRING_LENGTH = 32;
export const newNonce = () => randomBytes(secretbox.nonceLength);

// Generate a string that will seed the "lexi magic". This is assumed to be public knowledge.
export const publicString = base64.encode(randomBytes(PUBLIC_STRING_LENGTH));
console.log("THE PUBLIC STRING IS: " + publicString);

/**
 * The "normal" way to generate a symmetric key pair
 */
export const generateKey = () => base64.encode(randomBytes(secretbox.keyLength));

export class SignWalletWithKey implements SignWallet {
  private signKey: SignKeyPair;

  constructor(signKey: SignKeyPair) {
    this.signKey = signKey;
  }

  async signMessage(message: Uint8Array): Promise<Uint8Array> {
    return sign.detached(
      message,
      this.signKey.secretKey
    );
  }
}

/**
 * The "lexi magic":
 * Sign and hash a non-secret public string with an asymmetric secret key, creating the secret for the encryption key
 * @param publicString
 * @param signer
 */
export const generateKeyFromSignature = async (publicString: string, signer: SignWallet): Promise<Uint8Array> => {
  // Hash and sign the non-secret public string
  const publicHash = crypto.createHash("sha256").update(publicString).digest();
  const secret = await signer.signMessage(publicHash);

  // Hash the signature to standardise it to 32 bytes
  // using tweetnacl for hashing creates a 64 byte hash, so we use the native crypto lib here instead
  // return hash(secret);
  return crypto.createHash('sha256').update(secret).digest();
};

export const generateX25519KeyPairFromSignature = async (publicString: string, signer: SignWallet): Promise<BoxKeyPair> => {
  const key = await generateKeyFromSignature(publicString, signer);
  const ed25519Keypair = sign.keyPair.fromSeed(key);
  return convertKeyPair(ed25519Keypair)
};
