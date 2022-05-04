export interface SignWallet {
  signMessage(message: Uint8Array): Promise<Uint8Array>;
}

interface EncryptionWallet {
  decrypt(cyphertext: string): Promise<Record<string, unknown>>;
  encrypt(plaintext: Record<string, unknown>, did: string): Promise<string>;
}

export interface PersonalEncryptionWallet extends EncryptionWallet {
  encryptForMe(plaintext: Record<string, unknown>): Promise<string>;
}
