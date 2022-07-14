import type { LexiOptions } from "../lib/did";
import {
  decryptJWEWithLexi,
  encryptForDid,
  encryptForMe,
} from "../lib/encrypt";
import EncryptionKeyBox from "../lib/encryption_key_box";
import {
  generateX25519KeyPairFromSignature,
  singleUsePublicString,
} from "../lib/key";
import type { PersonalEncryptionWallet, SignWallet } from "../lib/wallet";

export class LexiWallet implements PersonalEncryptionWallet, SignWallet {
  private readonly wallet: SignWallet;
  private myDID: string;
  private readonly options: LexiOptions;
  private readonly encryptionKeyBox: EncryptionKeyBox;

  constructor(wallet: SignWallet, myDID: string, options: LexiOptions = {}) {
    this.wallet = wallet;
    this.myDID = myDID;
    this.options = options;
    this.encryptionKeyBox = new EncryptionKeyBox();
  }

  async generateKeyForSigning() {
    await generateX25519KeyPairFromSignature(
      this.wallet,
      this.options.publicSigningString || singleUsePublicString,
      this.encryptionKeyBox
    );
  }

  decrypt(cyphertext: string): Promise<Record<string, unknown>> {
    return decryptJWEWithLexi(
      JSON.parse(cyphertext),
      this.wallet,
      this.options,
      this.encryptionKeyBox
    );
  }

  encrypt(plaintext: Record<string, unknown>, did: string): Promise<string> {
    return encryptForDid(plaintext, did, this.options.resolve).then(
      JSON.stringify
    );
  }

  encryptForMe(plaintext: Record<string, unknown>): Promise<string> {
    return encryptForMe(
      plaintext,
      this.myDID,
      this.wallet,
      this.options,
      this.encryptionKeyBox
    ).then(JSON.stringify);
  }

  signMessage(message: Uint8Array): Promise<Uint8Array> {
    return this.wallet.signMessage(message);
  }
}
