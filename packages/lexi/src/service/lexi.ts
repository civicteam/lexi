import EncryptionKeyBox from "src/lib/encryption_key_box";
import type { LexiOptions } from "../lib/did";
import {
  decryptJWEWithLexi,
  encryptForDid,
  encryptForMe,
  EncryptionPackage,
} from "../lib/encrypt";
import {
  generateX25519KeyPairFromSignature,
  singleUsePublicString,
} from "../lib/key";
import type { PersonalEncryptionWallet, SignWallet } from "../lib/wallet";

export class LexiWallet implements PersonalEncryptionWallet, SignWallet {
  private readonly wallet: SignWallet;
  private myDID: string;
  private readonly options: LexiOptions;
  // a list of keyboxes indexed by the signingString
  // this is necessary because each message can have a different string so it's cached to avoid multiple sign calls
  private readonly encryptionKeyBoxes: Record<string, EncryptionKeyBox>;

  constructor(wallet: SignWallet, myDID: string, options: LexiOptions = {}) {
    this.wallet = wallet;
    this.myDID = myDID;
    this.options = options;
    this.encryptionKeyBoxes = {};
  }

  getEncryptionKeyBox(signingString?: string): EncryptionKeyBox {
    const key =
      signingString ||
      this.options.publicSigningString ||
      singleUsePublicString;
    const value = this.encryptionKeyBoxes[key] || new EncryptionKeyBox();
    this.encryptionKeyBoxes[key] = value;
    return value;
  }

  async generateKeyForSigning() {
    await generateX25519KeyPairFromSignature(
      this.wallet,
      this.options.publicSigningString || singleUsePublicString,
      this.getEncryptionKeyBox()
    );
  }

  decrypt(cyphertext: string): Promise<Record<string, unknown>> {
    const parsedText = JSON.parse(cyphertext) as EncryptionPackage;
    return decryptJWEWithLexi(
      parsedText,
      this.wallet,
      this.options.publicSigningString || singleUsePublicString,
      this.getEncryptionKeyBox(parsedText.signingString)
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
      this.getEncryptionKeyBox()
    ).then(JSON.stringify);
  }

  signMessage(message: Uint8Array): Promise<Uint8Array> {
    return this.wallet.signMessage(message);
  }
}
