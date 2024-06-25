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

// A wallet that caches signd messages to avoid multiple calls to the wallet
export class CachedSignWallet implements SignWallet {
  private readonly wallet: SignWallet;
  private readonly cache: Record<string, Uint8Array>;

  constructor(wallet: SignWallet) {
    this.wallet = wallet;
    this.cache = {};
  }

  async signMessage(message: Uint8Array): Promise<Uint8Array> {
    const key = message.toString();
    if (!this.cache[key]) {
      this.cache[key] = await this.wallet.signMessage(message);
    }
    return this.cache[key] as Uint8Array;
  }
}