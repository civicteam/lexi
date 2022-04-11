import {secretbox} from "tweetnacl";
import {decodeBase64, decodeUTF8, encodeBase64, encodeUTF8} from "tweetnacl-util";
import type {JWE} from "did-jwt";
import * as didJWT from "did-jwt";
import {lexiResolver, resolveDID} from "./did";
import {TextDecoder, TextEncoder} from "util";
import {generateX25519KeyPairFromSignature, newNonce, publicString} from "./key";
import type {SignWallet} from './wallet';

/**
 * Symmetric key encryption code taken from https://github.com/dchest/tweetnacl-js/wiki/Examples#secretbox
 * Uses x25519-xsalsa20-poly1305
 * @param json
 * @param key
 */
export const encrypt = (json: Record<string, unknown>, key: Uint8Array): string => {
  const nonce = newNonce();
  const messageUint8 = decodeUTF8(JSON.stringify(json));
  const box = secretbox(messageUint8, nonce, key);

  const fullMessage = new Uint8Array(nonce.length + box.length);
  fullMessage.set(nonce);
  fullMessage.set(box, nonce.length);

  return encodeBase64(fullMessage);
};

/**
 * Encrypt the payload for the DID
 * @param json
 * @param recipient
 * @param resolve
 */
export const encryptForDid = async (json: Record<string, unknown>, recipient: string, resolve = resolveDID): Promise<JWE> => {
  const didJwtResolver = {resolve};
  const encoder = new TextEncoder(); // always utf-8
  const encoded = encoder.encode(JSON.stringify(json));
  const encrypters = await didJWT.resolveX25519Encrypters(
    [recipient],
    didJwtResolver
  );
  return didJWT.createJWE(encoded, encrypters);
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
  const decrypter = didJWT.x25519Decrypter(lexiKeypair.secretKey)
  const decrypted = await didJWT.decryptJWE(jwe,decrypter)
  const decoder = new TextDecoder('utf-8');
  return JSON.parse(decoder.decode(decrypted));
}

/**
 * Symmetric key decryption code taken from https://github.com/dchest/tweetnacl-js/wiki/Examples#secretbox
 * @param messageWithNonce
 * @param key
 */
export const decrypt = (messageWithNonce: string, key: Uint8Array): Record<string, unknown> => {
  const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
  const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
  const message = messageWithNonceAsUint8Array.slice(
    secretbox.nonceLength,
    messageWithNonce.length
  );

  const decrypted = secretbox.open(message, nonce, key);

  if (!decrypted) {
    throw new Error("Could not decrypt message");
  }

  const base64DecryptedMessage = encodeUTF8(decrypted);
  return JSON.parse(base64DecryptedMessage);
};
