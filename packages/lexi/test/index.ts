import { sign } from "tweetnacl";
import { encode } from "bs58";
import { SignWalletWithKey } from "../src/lib/key";
import { LexiWallet } from "../src";

describe("LexiWallet", () => {
  it("We create a LexiWallet that generates a key when initiated", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);
    console.log("My DID: " + me);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {}, true);
    const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    console.log(decrypted, obj); // should be shallow equal
  });
});
