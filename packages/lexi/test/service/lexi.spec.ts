import { sign } from "tweetnacl";

import { encode } from "bs58";
import { SignWalletWithKey } from "../../src/lib/key";
import { LexiWallet } from "../../src/service/lexi";
import * as chai from "chai";
import axios from "axios";
import type { DIDResolutionResult } from "did-resolver";
import * as sinon from "sinon";
import chaiAsPromised from "chai-as-promised";
import "mocha";
import { SinonSpy } from "sinon";
import { bytesToObj, objToBytes } from "../../src";
import { base64ToBytes, JWE, xc20pDirDecrypter } from "did-jwt";

export function stringToBytes(s: string): Uint8Array {
  return u8a.fromString(s, 'utf-8')
}

import { concat, fromString, toString } from 'uint8arrays'
const u8a = { toString, fromString, concat }

export function toSealed(ciphertext: string, tag?: string): Uint8Array {
  return u8a.concat([base64ToBytes(ciphertext), tag ? base64ToBytes(tag) : new Uint8Array(0)])
}

const { expect } = chai;
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
            verificationMethod: [
              {
                id: "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa#default",
                type: "Ed25519VerificationKey2018",
                controller:
                  "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
                publicKeyBase58: "6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
              },
            ],
            authentication: [],
            assertionMethod: [],
            keyAgreement: [],
            capabilityInvocation: [
              "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa#default",
            ],
            capabilityDelegation: [],
            service: [],
            publicKey: [
              {
                id: "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa#default",
                type: "Ed25519VerificationKey2018",
                controller:
                  "did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
                publicKeyBase58: "6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa",
              },
            ],
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
    const encryptedWithWallet = await lexiWallet.encryptForMe(objToBytes(obj));
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(bytesToObj(decrypted)).to.eql(obj);
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
    const encryptedWithWallet = await lexiWallet.encryptForMe(objToBytes(obj));
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(bytesToObj(decrypted)).to.eql(obj);
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
    const encryptedWithWallet = await lexiWallet.encryptForMe(objToBytes(obj));
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(bytesToObj(decrypted)).to.eql(obj);
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
    const encryptedWithWallet = await lexiWallet.encryptForMe(objToBytes(obj));
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(
      lexiWallet.signMessage(Buffer.from(JSON.stringify(obj)))
    ).to.eventually.eql({});

    expect(bytesToObj(decrypted)).to.eql(obj);
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
    const encryptedWithWallet = await lexiWallet.encryptForMe(objToBytes(obj));
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    await expect(lexiWallet.encrypt(objToBytes(obj), me)).to.be.rejectedWith(
      /Could not find X25519 key/
    );

    expect(bytesToObj(decrypted)).to.eql(obj);
  });

  it("We create a LexiWallet and call the encrypt method twice - should only sign once", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    sinon.spy(signer, "signMessage");

    // encrypt and decrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {});
    await lexiWallet.encryptForMe(objToBytes(obj));
    await lexiWallet.encryptForMe(objToBytes(obj));

    expect((signer.signMessage as SinonSpy).calledOnce).to.be.true;
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
    const encryptedWithWallet = await lexiWallet.encryptForMe(objToBytes(obj));
    const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

    expect(bytesToObj(decrypted)).to.eql(obj);
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
    return expect(
      lexiWallet.encryptForMe(objToBytes(obj))
    ).to.eventually.be.rejectedWith(
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

    // We encrypt using both wallet and try to decrypt both with the second one
    // We need to encrypt with the second so it cache the keys
    const encryptedFirst = await lexiWalletEncrypt.encryptForMe(
      objToBytes(obj)
    );
    const encryptedSecond = await lexiWalletDecrypt.encryptForMe(
      objToBytes(obj)
    );
    const decryptedFirst = await lexiWalletDecrypt.decrypt(encryptedFirst);
    const decryptedSecond = await lexiWalletDecrypt.decrypt(encryptedSecond);
    const decryptedSecondNoString = await lexiWalletDecryptNoString.decrypt(
      encryptedSecond
    );

    expect(bytesToObj(decryptedFirst)).to.eql(obj);
    expect(bytesToObj(decryptedSecond)).to.eql(obj);
    expect(bytesToObj(decryptedSecondNoString)).to.eql(obj);
  });

  it("should cache the signMessage result for publicSigningString in the instance", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    sinon.spy(signer, "signMessage");

    // The data we want to encrypt
    const obj = { hello: "world" };

    const lexiWallet = new LexiWallet(signer, me, {});

    const encrypted = await Promise.all([
      lexiWallet.encryptForMe(objToBytes(obj)),
      lexiWallet.encryptForMe(objToBytes(obj)),
    ]);
    await Promise.all(encrypted.map((e) => lexiWallet.decrypt(e)));

    expect((signer.signMessage as SinonSpy).calledOnce).to.be.true;
  });

  it("should cache the signMessage result for publicSigningString in the cypher text", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    sinon.spy(signer, "signMessage");

    // The data we want to encrypt
    const obj = { hello: "world" };

    const lexiWalletEncrypt = new LexiWallet(signer, me, {});
    const lexiWallet = new LexiWallet(signer, me, {});

    const encryptedFirst = await lexiWalletEncrypt.encryptForMe(
      objToBytes(obj)
    );
    const encryptedSecond = await lexiWalletEncrypt.encryptForMe(
      objToBytes(obj)
    );
    await lexiWallet.decrypt(encryptedFirst);
    await lexiWallet.decrypt(encryptedSecond);

    expect((signer.signMessage as SinonSpy).callCount).to.eq(2);
  });

  it("should generate different signing string for different lexi wallets", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    const wallet1 = new LexiWallet(signer, me, {});
    const wallet2 = new LexiWallet(signer, me, {});

    expect(wallet1["singleUsePublicString"]).to.not.eq(
      wallet2["singleUsePublicString"]
    );
  });

  it("should decrypt the CEK", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // The data we want to encrypt
    const obj = { hello: "world" };

    // encrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {});
    const encryptedWithWallet = await lexiWallet.encryptForMe(objToBytes(obj));

    // decrypt the CEK
    const CEK = await lexiWallet.decryptCEK(encryptedWithWallet);

    expect(CEK).to.have.length(32);    
  });

  it("should hydrate an encryption key box", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);

    // derive my did from this signing key
    const me = "did:sol:" + encode(signKey.publicKey);

    // encrypt using lexi-aware wallet
    const lexiWallet = new LexiWallet(signer, me, {});

    // decrypt the CEK
    const keyBox = await lexiWallet.getHydratedEncryptionKeyBox('hellokitty');

    expect(keyBox.encryptionKey?.secretKey).to.have.length(32);
    expect(keyBox.encryptionKey?.publicKey).to.have.length(32);
  });

  it("should return null when decrypting CEK for non-recipient", async () => {
    const signKey1 = sign.keyPair();
    const signKey2 = sign.keyPair();
    const signer1 = new SignWalletWithKey(signKey1);
    const signer2 = new SignWalletWithKey(signKey2);

    const did1 = "did:sol:" + encode(signKey1.publicKey);
    const did2 = "did:sol:" + encode(signKey2.publicKey);

    const obj = { hello: "world" };

    const lexiWallet1 = new LexiWallet(signer1, did1, {});
    const lexiWallet2 = new LexiWallet(signer2, did2, {});

    const encryptedWithWallet = await lexiWallet1.encryptForMe(objToBytes(obj));

    await expect(lexiWallet2.decryptCEK(encryptedWithWallet)).to.eventually.equal(null);
  });

  it("should decrypt the CEK and successfully decrypt the message", async () => {
    const signKey = sign.keyPair();
    const signer = new SignWalletWithKey(signKey);
    const did = "did:sol:" + encode(signKey.publicKey);

    const obj = { hello: "world" };

    const lexiWallet = new LexiWallet(signer, did, {});

    const encrypted = await lexiWallet.encryptForMe(objToBytes(obj));
    const CEK = await lexiWallet.decryptCEK(encrypted);

    // Implement a custom decrypt function using the CEK
    const customDecrypt = async (jwe: JWE, cek: Uint8Array) => {
      // This is a placeholder for the actual decryption logic
      // You would need to implement the same encryption algorithm used in LexiWallet
      // For this test, we're just simulating the decryption
      //return objToBytes(obj);

      const sealed = toSealed(jwe.ciphertext, jwe.tag)
      const aad = stringToBytes(jwe.aad ? `${jwe.protected}.${jwe.aad}` : jwe.protected)
      return xc20pDirDecrypter(cek).decrypt(sealed, base64ToBytes(jwe.iv), aad);
    };

    const decrypted = await customDecrypt(encrypted.payload, CEK!);

    expect(bytesToObj(decrypted!)).to.deep.equal(obj);
  });
});
