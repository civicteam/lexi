import type { LexiOptions } from "../lib/did";
import {
  decryptJWEWithLexi,
  encryptForDid,
  encryptForMe,
} from "../lib/encrypt";
import type { PersonalEncryptionWallet, SignWallet } from "../lib/wallet";

export class LexiWallet implements PersonalEncryptionWallet {
  private readonly wallet: SignWallet;
  private readonly myDID: string;
  private readonly options: LexiOptions;

  constructor(wallet: SignWallet, myDID: string, options: LexiOptions = {}) {
    this.wallet = wallet;
    this.myDID = myDID;
    this.options = options;
  }

  decrypt(encrypted: string): Promise<string> {
    return decryptJWEWithLexi(JSON.parse(encrypted), this.wallet);
  }

  async encrypt(plainText: string, did: string): Promise<string> {
    return JSON.stringify(
      await encryptForDid(plainText, did, this.options.resolve)
    );
  }

  async encryptForMe(plainText: string): Promise<string> {
    return JSON.stringify(
      await encryptForMe(plainText, this.myDID, this.wallet, this.options)
    );
  }
}
