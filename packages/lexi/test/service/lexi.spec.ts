import { sign } from "tweetnacl";

import { encode } from "bs58";
import { SignWalletWithKey } from "../../src/lib/key";
import { LexiWallet } from "../../src/service/lexi";
import chai, { expect } from "chai";
import axios from "axios";
import type { DIDResolutionResult } from "did-resolver";
import sinon from "sinon";
import chaiAsPromised from "chai-as-promised";
import "mocha";

chai.use(chaiAsPromised);

describe("LexiWallet", () => {
  let sandbox: sinon.SinonSandbox;
  beforeEach(() => {
    sandbox = sinon.createSandbox();

    sandbox.stub(axios, "get").returns(
      Promise.resolve({
        data: {
          didDocument: {
            "@context": [
              "https://w3id.org/did/v1.0",
              "https://w3id.org/sol/v1",
            ],
            id: "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
            controller: [],
            verificationMethod: [[Object]],
            authentication: [],
            assertionMethod: [],
            keyAgreement: [],
            capabilityInvocation: [
              "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa#default",
            ],
            capabilityDelegation: [],
            service: [],
            publicKey: [[Object]],
          },
          content: null,
          contentType: null,
          didResolutionMetadata: {
            duration: 3077,
            identifier: "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
            pattern: "^(did:sol:.+)$",
            driverUrl: "http://driver-did-sol:8080/1.0/identifiers/",
            didUrl: {
              didUrlString:
                "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
              did: [Object],
              path: "",
              query: null,
              fragment: null,
              parameters: {},
              parseTree: null,
              parseRuleCount: null,
            },
          },
          didDocumentMetadata: {},
        },
      })
    );
  });
  afterEach(() => sandbox.restore());
  it("We create a lexiWallet and create the derived encryption key", () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    const lexiWallet = new LexiWallet(signer, me, {});
    lexiWallet.generateKeyForSigning();
  });

  it("We create a LexiWallet that generates a key when initiated", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {});
    const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(decrypted).to.eql(obj);
  });

  it("We create a LexiWallet that does not  generate a key when initiated", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {});
    const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(decrypted).to.eql(obj);
  });

  it("We create a LexiWallet with options for passing in the resolver", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {
      resolve: async (did): Promise<DIDResolutionResult> => {
        return axios
          .get("https://did.civic.com/1.0/identifiers/" + did)
          .then<DIDResolutionResult>((res) => res.data);
      },
    });
    const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(decrypted).to.eql(obj);
  });

  it("We create a LexiWallet and call the sign method", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {});
    const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(
      lexiWallet.signMessage(Buffer.from(JSON.stringify(obj)))
    ).to.eventually.eql({});

    expect(decrypted).to.eql(obj);
  });

  it("We create a LexiWallet and call the encrypt method", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {});
    const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(lexiWallet.encrypt(obj, me)).to.eventually.eql({});

    expect(decrypted).to.eql(obj);
  });

  it("We create a LexiWallet without any options", async () => {
    // restore sandbox so we can reset the stub
    sandbox.restore();
    sandbox.stub(axios, "get").returns(
      Promise.resolve({
        data: {
          didDocument: {
            "@context": [
              "https://w3id.org/did/v1.0",
              "https://w3id.org/sol/v1",
            ],
            id: "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
            controller: [],
            verificationMethod: [[Object]],
            authentication: [],
            assertionMethod: [],
            capabilityInvocation: [
              "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa#default",
            ],
            capabilityDelegation: [],
            service: [],
            publicKey: [[Object]],
          },
          content: null,
          contentType: null,
          didResolutionMetadata: {
            duration: 3077,
            identifier: "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
            pattern: "^(did:sol:.+)$",
            driverUrl: "http://driver-did-sol:8080/1.0/identifiers/",
            didUrl: {
              didUrlString:
                "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
              did: [Object],
              path: "",
              query: null,
              fragment: null,
              parameters: {},
              parseTree: null,
              parseRuleCount: null,
            },
          },
          didDocumentMetadata: {},
        },
      })
    );

    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me);
    const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(decrypted).to.eql(obj);
  });

  it("Test what happens if we can't get a back a DIDDocument", async () => {
    // restore sandbox so we can reset the stub
    sandbox.restore();
    sandbox.stub(axios, "get").returns(
      Promise.resolve({
        data: {
          content: null,
          contentType: null,
          didResolutionMetadata: {
            duration: 3077,
            identifier: "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
            pattern: "^(did:sol:.+)$",
            driverUrl: "http://driver-did-sol:8080/1.0/identifiers/",
            didUrl: {
              didUrlString:
                "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
              did: [Object],
              path: "",
              query: null,
              fragment: null,
              parameters: {},
              parseTree: null,
              parseRuleCount: null,
            },
          },
          didDocumentMetadata: {},
        },
      })
    );

    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me);
    return expect(lexiWallet.encryptForMe(obj)).to.eventually.be.rejectedWith(
      `resolver_error: Could not resolve did:sol:${encode(
        signKey.publicKey
      )}: undefined, undefined`
    );
  });

  it("We should be able to decrypt a message from another wallet using the same signer and did.", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // Two wallets using the same signer and did
    const lexiWalletEncrypt = new LexiWallet(signer, me, {});
    const lexiWalletDecrypt = new LexiWallet(signer, me, {
      publicSigningString: "singing-string-decrypt",
    });
    const lexiWalletDecryptNoString = new LexiWallet(signer, me, {});

    // We encrypt using both wallet and try do decrypt both with the second one
    // We need to encrypt with the second so it cache the keys
    const encryptedFirst = await lexiWalletEncrypt.encryptForMe(obj);
    const encryptedSecond = await lexiWalletDecrypt.encryptForMe(obj);
    const decryptedFirst = await lexiWalletDecrypt.decrypt(encryptedFirst);
    const decryptedSecond = await lexiWalletDecrypt.decrypt(encryptedSecond);
    const decryptedSecondNoString = await lexiWalletDecryptNoString.decrypt(
      encryptedSecond
    );

    expect(decryptedFirst).to.eql(obj);
    expect(decryptedSecond).to.eql(obj);
    expect(decryptedSecondNoString).to.eql(obj);
  });
});
