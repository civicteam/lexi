import type {PersonalEncryptionWallet, SignWallet} from "../lib/wallet";
import {decryptJWEWithLexi, encryptForDid, encryptForMe} from "../lib/encrypt";
import type {LexiOptions} from "../lib/did";

export class LexiWallet implements PersonalEncryptionWallet, SignWallet {
  private wallet: SignWallet;
  private myDID: string;
  private options: LexiOptions;

  constructor(wallet: SignWallet, myDID: string, options: LexiOptions = {}) {
    this.wallet = wallet;
    this.myDID = myDID;
    this.options = options;
  }

  decrypt(cyphertext: string): Promise<Record<string, unknown>> {
    return decryptJWEWithLexi(JSON.parse(cyphertext), this.wallet, this.options);
  }

  encrypt(plaintext: Record<string, unknown>, did: string): Promise<string> {
    return encryptForDid(plaintext, did, this.options.resolve).then(JSON.stringify);
  }

  encryptForMe(plaintext: Record<string, unknown>): Promise<string> {
    return encryptForMe(plaintext, this.myDID, this.wallet, this.options).then(JSON.stringify);
  }

  signMessage(message: Uint8Array): Promise<Uint8Array> {
    return this.wallet.signMessage(message);
  }
}
