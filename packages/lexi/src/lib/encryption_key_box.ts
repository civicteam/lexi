import type nacl from "tweetnacl";

// we use this to try and enforce pass-by-reference so that references to the
// encryption key inside the encrytion key box is updatable by functions, trying to
// use the encryptionKey directly causes the private variable in LexiWallet not to
// update by other functions
class EncryptionKeyBox {
  public encryptionKey: nacl.BoxKeyPair | null;

  constructor() {
    this.encryptionKey = null;
  }
}

export default EncryptionKeyBox;
