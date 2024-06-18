import type { EncryptionPackage } from "./encrypt";
import type {JWE} from "did-jwt";

export interface SignWallet {
  signMessage(message: Uint8Array): Promise<Uint8Array>;
}

interface EncryptionWallet {
  decrypt(
    cyphertext: EncryptionPackage,
    publicSigningString?: string
  ): Promise<Uint8Array>;
  encrypt(plaintext: Uint8Array, did: string): Promise<JWE>;
}

export interface PersonalEncryptionWallet extends EncryptionWallet {
  encryptForMe(plaintext: Uint8Array): Promise<EncryptionPackage>;
}
