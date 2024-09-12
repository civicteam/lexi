export { LexiWallet } from "./service/lexi";
export { SignWallet } from "./lib/wallet";
export { Resolver, LexiOptions } from "./lib/did";
export { DIDDocument } from "did-resolver";
export { generateRandomString } from "./lib/key";
export { objToBytes, bytesToObj, hydrateEncryptionKeyBox } from "./lib/util";
export * as EncryptionKeyBox from './lib/encryption_key_box';