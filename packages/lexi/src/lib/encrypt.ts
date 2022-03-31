import {secretbox} from "tweetnacl";
import {createJWE, decryptJWE, JWE, resolveX25519Encrypters, x25519Decrypter} from "did-jwt";
import {lexiResolver, resolveDID} from "./did";
import {generateX25519KeyPairFromSignature, newNonce, publicString} from "./key";
import type {SignWallet} from './wallet';
import * as base64 from "@stablelib/base64";
import * as utf8 from "@stablelib/utf8";

/**
 * Symmetric key encryption code taken from https://github.com/dchest/tweetnacl-js/wiki/Examples#secretbox
 * Uses x25519-xsalsa20-poly1305
 * @param json
 * @param key
 */
export const encrypt = (json: Record<string, unknown>, key: Uint8Array): string => {
  const nonce = newNonce();
  const messageUint8 = utf8.encode(JSON.stringify(json));
  const box = secretbox(messageUint8, nonce, key);

  const fullMessage = new Uint8Array(nonce.length + box.length);
  fullMessage.set(nonce);
  fullMessage.set(box, nonce.length);

  return base64.encode(fullMessage);
};

/**
 * Encrypt the payload for the DID
 * @param json
 * @param recipient
 * @param resolve
 */
export const encryptForDid = async (json: Record<string, unknown>, recipient: string, resolve = resolveDID): Promise<JWE> => {
  const didJwtResolver = {resolve};
  const encoded = utf8.encode(JSON.stringify(json));
  const encrypters = await resolveX25519Encrypters(
    [recipient],
    didJwtResolver
  );
  return createJWE(encoded, encrypters);
}

/**
 * Encrypt the payload for my DID, using a DID resolver that knows about Lexi, i.e.
 * will artificially add to the DID my encryption key based on my signing key.
 * @param json
 * @param me
 * @param signer
 */
export const encryptForMe = async (json: Record<string, unknown>, me: string, signer: SignWallet): Promise<JWE> => {
  const resolve = lexiResolver(resolveDID, signer);
  return encryptForDid(json, me, resolve);
}

export const decryptJWEWithLexi = async (jwe: JWE, signer: SignWallet): Promise<Record<string, unknown>> => {
  const lexiKeypair = await generateX25519KeyPairFromSignature(publicString, signer);
  const decrypter = x25519Decrypter(lexiKeypair.secretKey)
  const decrypted = await decryptJWE(jwe,decrypter)
  return JSON.parse(utf8.decode(decrypted));
}

/**
 * Symmetric key decryption code taken from https://github.com/dchest/tweetnacl-js/wiki/Examples#secretbox
 * @param messageWithNonce
 * @param key
 */
export const decrypt = (messageWithNonce: string, key: Uint8Array): Record<string, unknown> => {
  const messageWithNonceAsUint8Array = base64.decode(messageWithNonce);
  const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
  const message = messageWithNonceAsUint8Array.slice(
    secretbox.nonceLength,
    messageWithNonce.length
  );

  const decrypted = secretbox.open(message, nonce, key);

  if (!decrypted) {
    throw new Error("Could not decrypt message");
  }

  const base64DecryptedMessage = utf8.decode(decrypted);
  return JSON.parse(base64DecryptedMessage);
};