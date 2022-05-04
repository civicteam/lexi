import { sign } from "tweetnacl";
import { encode } from "bs58";
import { SignWalletWithKey } from "../src/lib/key";
import { LexiWallet } from "../src";

async function networkTests() {
  // Create an asymmetric signing key pair. This mimics the user's crypto wallet
  const signKey = sign.keyPair();
  const signer = new SignWalletWithKey(signKey);

  // derive my did from this signing key
  const me = "did:sol:" + encode(signKey.publicKey);
  console.log("My DID: " + me);

  // The data we want to encrypt
  const obj = { hello: "world" };

  // encrypt and decrypt using lexi-aware wallet
  const lexiWallet = new LexiWallet(signer, me);
  const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
  const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

  console.log(decrypted, obj); // should be shallow equal
}

async function test() {
  // FIXME(sneak): the test suite should work without requiring network
  // see https://github.com/civicteam/lexi/issues/1
  networkTests();
}

test().catch(console.error);
