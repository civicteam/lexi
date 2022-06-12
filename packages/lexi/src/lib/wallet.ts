export interface SignWallet {
  signMessage(message: Uint8Array): Promise<Uint8Array>;
}

interface EncryptionWallet {
  decrypt(cyphertext: string): Promise<string>;
  encrypt(plainText: string, did: string): Promise<string>;
}

export interface PersonalEncryptionWallet extends EncryptionWallet {
  encryptForMe(plainText: string): Promise<string>;
}
