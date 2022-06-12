import * as base64 from "@stablelib/base64";
import * as utf8 from "@stablelib/utf8";
import {
  createJWE,
  decryptJWE,
  JWE,
  resolveX25519Encrypters,
  x25519Decrypter,
} from "did-jwt";
import { LexiOptions, lexiResolver, resolveDID } from "./did";
import {
  generateX25519KeyPairFromSignature,
  SHA256D,
  singleUsePublicString,
} from "./key";
import type { SignWallet } from "./wallet";

export type EncryptedPayload = {
  encryptedData: JWE;
  signString: string;
};

/**
 * Encrypt the payload for the DID
 * @param plainText
 * @param recipient
 * @param resolve
 */
export const encryptForDid = async (
  plainText: string,
  recipient: string,
  resolve = resolveDID
): Promise<JWE> => {
  const didJwtResolver = { resolve };
  const encoded = utf8.encode(plainText);
  const encrypters = await resolveX25519Encrypters([recipient], didJwtResolver);
  return createJWE(encoded, encrypters);
};

/**
 * Encrypt the payload for my DID, using a DID resolver that knows about Lexi, i.e.
 * will artificially add to the DID my encryption key based on my signing key.
 * @param plainText
 * @param me
 * @param signer
 * @param options
 */
export const encryptForMe = async (
  plainText: string,
  me: string,
  signer: SignWallet,
  options: LexiOptions
): Promise<EncryptedPayload> => {
  const resolve = options.resolve || resolveDID;

  const friendlyString = options.friendlyString || "";

  // first we blind the 'publicString' by hashing to ensure we're not
  // signing arbitrary attacker-provided data:
  // base64 encode the message because the raw bytes look a bit weird to users of Civic.me
  const nonce = base64.encode(
    await SHA256D(utf8.encode(singleUsePublicString()))
  );

  const finalSignatureInput = friendlyString + nonce;

  const lexiResolve = lexiResolver(resolve, signer, finalSignatureInput);
  const jwe = await encryptForDid(plainText, me, lexiResolve);

  return {
    signString: friendlyString + nonce,
    encryptedData: jwe,
  };
};

export const decryptJWEWithLexi = async (
  encryptedPayload: EncryptedPayload,
  signer: SignWallet
): Promise<string> => {
  const keyPair = await generateX25519KeyPairFromSignature(
    signer,
    encryptedPayload.signString
  );

  const decrypter = x25519Decrypter(keyPair.secretKey);
  const decrypted = await decryptJWE(encryptedPayload.encryptedData, decrypter);
  return utf8.decode(decrypted);
};
