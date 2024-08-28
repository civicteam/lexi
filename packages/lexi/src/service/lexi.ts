import EncryptionKeyBox from "../lib/encryption_key_box";
import type { LexiOptions } from "../lib/did";
import {
  decryptCEK,
  decryptJWEWithLexi,
  encryptForDid,
  encryptForMe,
  EncryptionPackage,
} from "../lib/encrypt";
import {
  generateRandomString,
  generateX25519KeyPairFromSignature,
} from "../lib/key";
import {CachedSignWallet, type PersonalEncryptionWallet, type SignWallet} from "../lib/wallet";
import { hydrateEncryptionKeyBox } from "../lib/util";
import type {JWE} from "did-jwt";

export class LexiWallet implements PersonalEncryptionWallet, SignWallet {
  private readonly wallet: SignWallet;
  private myDID: string;
  private readonly options: LexiOptions;
  private singleUsePublicString: string;
  // a list of keyboxes indexed by the signingString
  // this is necessary because each message can have a different string so it's cached to avoid multiple sign calls
  private readonly encryptionKeyBoxes: Record<string, EncryptionKeyBox>;

  constructor(wallet: SignWallet, myDID: string, options: LexiOptions = {}) {
    this.wallet = new CachedSignWallet(wallet);
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

  // get the key box for our own signer but also make sure it contains a hydrated key pair
  async getHydratedEncryptionKeyBox(signingString: string): Promise<EncryptionKeyBox> {
    const keyBox = this.getEncryptionKeyBox(signingString);

    await hydrateEncryptionKeyBox(
      keyBox,
      signingString,
      this.wallet
    );

    return keyBox;
  }

  async generateKeyForSigning() {
    return generateX25519KeyPairFromSignature(
      this.wallet,
      this.singleUsePublicString,
      this.getEncryptionKeyBox()
    );
  }

  decrypt(cyphertext: EncryptionPackage): Promise<Uint8Array> {
    return decryptJWEWithLexi(
      cyphertext,
      this.wallet,
      this.getEncryptionKeyBox(cyphertext.signingString)
    );
  }

  encrypt(plaintext: Uint8Array, did: string): Promise<JWE> {
    return encryptForDid(plaintext, did, this.options.resolve);
  }

  encryptForMe(plaintext: Uint8Array): Promise<EncryptionPackage> {
    return encryptForMe(
      plaintext,
      this.myDID,
      this.wallet,
      this.singleUsePublicString,
      this.getEncryptionKeyBox(),
      this.options.resolve
    );
  }

  async decryptCEK(encryptionPackage: EncryptionPackage, signer?: SignWallet): Promise<Uint8Array | null> {
    let encryptionKeyBox;
    if(signer) {
      encryptionKeyBox = new EncryptionKeyBox();
      await hydrateEncryptionKeyBox(encryptionKeyBox, encryptionPackage.signingString, signer);
    } else {
      encryptionKeyBox = await this.getHydratedEncryptionKeyBox(encryptionPackage.signingString);
    }
    
    return decryptCEK(encryptionPackage, encryptionKeyBox);
  }

  signMessage(message: Uint8Array): Promise<Uint8Array> {
    return this.wallet.signMessage(message);
  }
}
