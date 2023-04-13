import * as utf8 from "@stablelib/utf8";
import {
  createJWE,
  decryptJWE,
  JWE,
  resolveX25519Encrypters,
  x25519Decrypter,
} from "did-jwt";
import { lexiResolver, resolveDID, Resolver } from "./did";
import type EncryptionKeyBox from "./encryption_key_box";
import { generateX25519KeyPairFromSignature } from "./key";
import type { SignWallet } from "./wallet";

export type EncryptionPackage = {
  signingString: string;
  schema: string;
  algorithm: string;
  payload: JWE;
};

/**
 * Encrypt the payload for the DID
 * @param json
 * @param recipient
 * @param resolve
 */
export const encryptForDid = async (
  json: Record<string, unknown>,
  recipient: string,
  resolve = resolveDID
): Promise<JWE> => {
  const didJwtResolver = { resolve };
  const encoded = utf8.encode(JSON.stringify(json));
  const encrypters = await resolveX25519Encrypters([recipient], didJwtResolver);
  return createJWE(encoded, encrypters);
};

/**
 * Encrypt the payload for my DID, using a DID resolver that knows about Lexi, i.e.
 * will artificially add to the DID my encryption key based on my signing key.
 * @param json
 * @param me
 * @param signer
 * @param options
 * @param encryptionKey
 */
export const encryptForMe = async (
  json: Record<string, unknown>,
  me: string,
  signer: SignWallet,
  publicSigningString: string,
  encryptionKey: EncryptionKeyBox,
  resolve?: Resolver
): Promise<EncryptionPackage> => {
  const lexiResolve = lexiResolver(
    resolve || resolveDID,
    signer,
    encryptionKey,
    publicSigningString
  );
  return {
    signingString: publicSigningString,
    algorithm: "ED25519",
    schema: "lexi-encryption-v1",
    payload: await encryptForDid(json, me, lexiResolve),
  };
};

export const decryptJWEWithLexi = async (
  encryptionPackage: EncryptionPackage,
  signer: SignWallet,
  encryptionKeyBox: EncryptionKeyBox
): Promise<Record<string, unknown>> => {
  const publicSigningString = encryptionPackage.signingString;

  const keyPair = await generateX25519KeyPairFromSignature(
    signer,
    publicSigningString,
    encryptionKeyBox
  );

  const decrypter = x25519Decrypter(keyPair.secretKey);
  const decrypted = await decryptJWE(encryptionPackage.payload, decrypter);
  return JSON.parse(utf8.decode(decrypted));
};
