import EncryptionKeyBox from "../lib/encryption_key_box";
import type { LexiOptions } from "../lib/did";
import {
  decryptJWEWithLexi,
  encryptForDid,
  encryptForMe,
  EncryptionPackage,
} from "../lib/encrypt";
import {
  generateRandomString,
  generateX25519KeyPairFromSignature,
} from "../lib/key";
import type { PersonalEncryptionWallet, SignWallet } from "../lib/wallet";

export class LexiWallet implements PersonalEncryptionWallet, SignWallet {
  private readonly wallet: SignWallet;
  private myDID: string;
  private readonly options: LexiOptions;
  private singleUsePublicString: string;
  // a list of keyboxes indexed by the signingString
  // this is necessary because each message can have a different string so it's cached to avoid multiple sign calls
  private readonly encryptionKeyBoxes: Record<string, EncryptionKeyBox>;

  constructor(wallet: SignWallet, myDID: string, options: LexiOptions = {}) {
    this.wallet = wallet;
    this.myDID = myDID;
    this.options = options;
    this.singleUsePublicString =
      options.publicSigningString || generateRandomString();
    this.encryptionKeyBoxes = {};
  }

  getEncryptionKeyBox(signingString?: string): EncryptionKeyBox {
    const key = signingString || this.singleUsePublicString;
    const value = this.encryptionKeyBoxes[key] || new EncryptionKeyBox();
    this.encryptionKeyBoxes[key] = value;
    return value;
  }

  async generateKeyForSigning() {
    await generateX25519KeyPairFromSignature(
      this.wallet,
      this.singleUsePublicString,
      this.getEncryptionKeyBox()
    );
  }

  decrypt(cyphertext: string): Promise<Record<string, unknown>> {
    const parsedText = JSON.parse(cyphertext) as EncryptionPackage;
    return decryptJWEWithLexi(
      parsedText,
      this.wallet,
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
      this.singleUsePublicString,
      this.getEncryptionKeyBox(),
      this.options.resolve
    ).then(JSON.stringify);
  }

  signMessage(message: Uint8Array): Promise<Uint8Array> {
    return this.wallet.signMessage(message);
  }
}
