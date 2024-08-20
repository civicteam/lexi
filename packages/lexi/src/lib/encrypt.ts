import { concat } from 'uint8arrays';
import {
  computeX25519EcdhEsKek,
  createJWE,
  decryptJWE,
  JWE,
  Recipient,
  resolveX25519Encrypters,
  x25519Decrypter,
  xc20pDirDecrypter,
  base64ToBytes,
} from "did-jwt";
import { lexiResolver, resolveDID, Resolver } from "./did";
import type EncryptionKeyBox from "./encryption_key_box";
import { generateX25519KeyPairFromSignature } from "./key";
import type { SignWallet } from "./wallet";

const toSealed = (ciphertext: string, tag?: string): Uint8Array => {
  return concat([base64ToBytes(ciphertext), tag ? base64ToBytes(tag) : new Uint8Array(0)])
}

export type EncryptionPackage = {
  signingString: string;
  schema: string;
  payload: JWE;
};

/**
 * Encrypt the payload for the DID
 * @param input
 * @param recipient
 * @param resolve
 */
export const encryptForDid = async (
  input: Uint8Array,
  recipient: string,
  resolve: Resolver = resolveDID
): Promise<JWE> => {
  const didJwtResolver = { resolve };
  const encrypters = await resolveX25519Encrypters([recipient], didJwtResolver);
  return createJWE(input, encrypters);
};

/**
 * Encrypt the payload for my DID, using a DID resolver that knows about Lexi, i.e.
 * will artificially add to the DID my encryption key based on my signing key.
 * @param input
 * @param me
 * @param signer
 * @param publicSigningString
 * @param encryptionKey
 * @param resolve
 */
export const encryptForMe = async (
  input: Uint8Array,
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
    schema: "lexi-encryption-v1",
    payload: await encryptForDid(input, me, lexiResolve),
  };
};

export const decryptJWEWithLexi = async (
  encryptionPackage: EncryptionPackage,
  signer: SignWallet,
  encryptionKeyBox: EncryptionKeyBox
): Promise<Uint8Array> => {
  const publicSigningString = encryptionPackage.signingString;

  const keyPair = await generateX25519KeyPairFromSignature(
    signer,
    publicSigningString,
    encryptionKeyBox
  );

  // basically an x25519 decrypter
  const decrypter = x25519Decrypter(keyPair.secretKey);
  return decryptJWE(encryptionPackage.payload, decrypter);
};

const doDecryptCEK = async (
  recipient: Recipient,
  recipientSecret: Uint8Array,
): Promise<Uint8Array | null> => {
  if (!recipient.header.iv) {
    throw new Error('IV is required to decrypt CEK')
  }
  const kek = await computeX25519EcdhEsKek(recipient, recipientSecret, 'ECDH-ES+XC20PKW');
  if (!kek) return null
  // Content Encryption Key
  const sealedCek = toSealed(recipient.encrypted_key, recipient.header.tag)
  const cek = await xc20pDirDecrypter(kek).decrypt(sealedCek, base64ToBytes(recipient.header.iv))
  
  return cek;
}

export const decryptCEK = async (encryptionPackage: EncryptionPackage, signer: SignWallet, encryptionKeyBox: EncryptionKeyBox
): Promise<Uint8Array | null> => {
  const publicSigningString = encryptionPackage.signingString;
  const keyPair = await generateX25519KeyPairFromSignature(
    signer,
    publicSigningString,
    encryptionKeyBox
  );
  if (!encryptionPackage.payload.aad) {
    throw new Error('AAD is required to decrypt CEK')
  }
  if (!encryptionPackage.payload.recipients || encryptionPackage.payload.recipients.length === 0) {
    throw new Error('Bad encryption package: missing recipients')
  }
  return doDecryptCEK(encryptionPackage.payload.recipients[0] as Recipient, keyPair.secretKey);
};

