import type EncryptionKeyBox from "./encryption_key_box";
import { generateX25519KeyPairFromSignature } from "./key";
import type { SignWallet } from "./wallet";

// convert a js object to and from a byte stream by stringifying and encoding it as an utf8 byte array
export const objToBytes = (obj: any): Uint8Array => new TextEncoder().encode(JSON.stringify(obj));
export const bytesToObj = (bytes: Uint8Array): any => JSON.parse(new TextDecoder().decode(bytes));

export const hydrateEncryptionKeyBox = async(keyBox: EncryptionKeyBox, signingString: string, signer: SignWallet) => {
    await generateX25519KeyPairFromSignature(
        signer,
        signingString,
        keyBox
    );
}