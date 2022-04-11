import type {PersonalEncryptionWallet, SignWallet} from "../lib/wallet";
import {decryptJWEWithLexi, encryptForDid, encryptForMe} from "../lib/crypto";

export class LexiWallet implements PersonalEncryptionWallet, SignWallet {
  private wallet: SignWallet;
  private myDID: string;

  constructor(wallet: SignWallet, myDID: string) {
    this.wallet = wallet;
    this.myDID = myDID;
  }

  decrypt(cyphertext: string): Promise<Record<string, unknown>> {
    return decryptJWEWithLexi(JSON.parse(cyphertext), this.wallet);
  }

  encrypt(plaintext: Record<string, unknown>, did: string): Promise<string> {
    return encryptForDid(plaintext, did).then(JSON.stringify);
  }

  encryptForMe(plaintext: Record<string, unknown>): Promise<string> {
    return encryptForMe(plaintext, this.myDID, this.wallet).then(JSON.stringify);
  }

  signMessage(message: Uint8Array): Promise<Uint8Array> {
    return this.wallet.signMessage(message);
  }
}
