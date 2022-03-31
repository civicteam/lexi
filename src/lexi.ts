import {randomBytes, secretbox, sign, SignKeyPair} from "tweetnacl";
import {decodeBase64, decodeUTF8, encodeBase64, encodeUTF8} from "tweetnacl-util";
import * as crypto from "crypto";

const PUBLIC_STRING_LENGTH = 32;

const newNonce = () => randomBytes(secretbox.nonceLength);

/**
 * The "normal2 way to generate a symmetric key pair
 */
export const generateKey = () => encodeBase64(randomBytes(secretbox.keyLength));

/**
 * The "lexi magic":
 * Sign and hash a non-secret public string with an asymmetric secret key, creating the secret for the encryption key
 * @param publicString
 * @param signKey
 */
export const generateKeyFromSignature = (publicString: string, signKey: SignKeyPair):string => {
  // Sign the non-secret public string
  const secret = sign.detached(
    decodeBase64(publicString),
    signKey.secretKey
  );

  // Hash the signature to standardise it to 32 bytes
  // using tweetnacl for hashing creates a 64 byte hash, so we use the native crypto lib here instead
  // const hashed = hash(secret);
  const hashed = crypto.createHash('sha256').update(secret).digest();

  return encodeBase64(hashed);
};

/**
 * Symmetric key encryption code taken from https://github.com/dchest/tweetnacl-js/wiki/Examples#secretbox
 * @param json
 * @param key
 */
export const encrypt = (json: Record<string, unknown>, key: string): string => {
  const keyUint8Array = decodeBase64(key);
  const nonce = newNonce();
  const messageUint8 = decodeUTF8(JSON.stringify(json));
  const box = secretbox(messageUint8, nonce, keyUint8Array);

  const fullMessage = new Uint8Array(nonce.length + box.length);
  fullMessage.set(nonce);
  fullMessage.set(box, nonce.length);

  return encodeBase64(fullMessage);
};

/**
 * Symmetric key decryption code taken from https://github.com/dchest/tweetnacl-js/wiki/Examples#secretbox
 * @param messageWithNonce
 * @param key
 */
export const decrypt = (messageWithNonce: string, key: string):Record<string, unknown> => {
  const keyUint8Array = decodeBase64(key);
  const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
  const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
  const message = messageWithNonceAsUint8Array.slice(
    secretbox.nonceLength,
    messageWithNonce.length
  );

  const decrypted = secretbox.open(message, nonce, keyUint8Array);

  if (!decrypted) {
    throw new Error("Could not decrypt message");
  }

  const base64DecryptedMessage = encodeUTF8(decrypted);
  return JSON.parse(base64DecryptedMessage);
};

// Generate a string that will seed the "lexi magic". This is assumed to be public knowledge.
const publicString = encodeBase64(randomBytes(PUBLIC_STRING_LENGTH));

// Create an asymmetric signing key pair. This mimics the user's crypto wallet
const signingKey = sign.keyPair()

// If we weren't using lexi magic, we would generate an encryption key like this
// const encryptionKey = generateKey();
// Instead we are generating one from the signature of the public string
const encryptionKey = generateKeyFromSignature(publicString, signingKey);

// The data we want to encrypt
const obj = { "hello": "world" };

// Encrypt the data
const encrypted = encrypt(obj, encryptionKey);

// Decrypt it with the same key
const decrypted = decrypt(encrypted, encryptionKey);

console.log(decrypted, obj); // should be shallow equal

// Ensure we can rederive the key from the public string and signing key.
const rederivedEncryptionKey = generateKeyFromSignature(publicString, signingKey);

// and that it can decrypt the data
const decrypted2 = decrypt(encrypted, rederivedEncryptionKey);
console.log(decrypted2, obj); // should be shallow equal
