import {encode} from "bs58";
import chai, {expect} from "chai";
import axios from "axios";
import type {DIDResolutionResult} from "did-resolver";
import sinon from "sinon";
import chaiAsPromised from "chai-as-promised";
import * as base64 from "@stablelib/base64";

import {SignWalletWithKey} from "../../src/lib/key";
import {LexiWallet} from "../../src/service/lexi";
import signKey from "../fixtures/signKey";

chai.use(chaiAsPromised);


describe("LexiWallet", () => {
    let sandbox: sinon.SinonSandbox;
    beforeEach(() => {
        sandbox = sinon.createSandbox();

        sandbox.stub(axios, "get").returns(Promise.resolve({data:
                {
                    didDocument: {
                        '@context': ['https://w3id.org/did/v1.0', 'https://w3id.org/sol/v1'],
                        id: 'did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa',
                        controller: [],
                        verificationMethod: [[Object]],
                        authentication: [],
                        assertionMethod: [],
                        keyAgreement: [],
                        capabilityInvocation: ['did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa#default'],
                        capabilityDelegation: [],
                        service: [],
                        publicKey: [[Object]]
                    },
                    content: null,
                    contentType: null,
                    didResolutionMetadata: {
                        duration: 3077,
                        identifier: 'did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa',
                        pattern: '^(did:sol:.+)$',
                        driverUrl: 'http://driver-did-sol:8080/1.0/identifiers/',
                        didUrl: {
                            didUrlString: 'did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa',
                            did: [Object],
                            path: '',
                            query: null,
                            fragment: null,
                            parameters: {},
                            parseTree: null,
                            parseRuleCount: null
                        }
                    },
                    didDocumentMetadata: {}
                }
        }));
    });
    afterEach(() => sandbox.restore());
    it("We create a lexiWallet and create the derived encryption key", () => {
        // const signKey = sign.keyPair();
        const signer = new SignWalletWithKey(signKey);

        // derive my did from this signing key
        const me = "did:sol:" + encode(signKey.publicKey);

        const lexiWallet = new LexiWallet(signer, me, {});
        lexiWallet.generateKeyForSigning();
    });

    it("We create a LexiWallet with options for passing in the resolver", async () => {
        // const signKey = sign.keyPair();
        const signer = new SignWalletWithKey(signKey);

        // derive my did from this signing key
        const me = "did:sol:" + encode(signKey.publicKey);

        // The data we want to encrypt
        const obj = {hello: "world"};

        // encrypt and decrypt using lexi-aware wallet
        const lexiWallet = new LexiWallet(signer, me, {
            resolve: async (did): Promise<DIDResolutionResult> => {
                return axios
                    .get("https://did.civic.com/1.0/identifiers/" + did)
                    .then<DIDResolutionResult>((res) => res.data);
            }
        });
        const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
        const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

        expect(decrypted).to.eql(obj);
    });

    it("We create a LexiWallet and call the sign method", async () => {

        // const signKey = sign.keyPair();
        const signer = new SignWalletWithKey(signKey);

        // derive my did from this signing key
        const me = "did:sol:" + encode(signKey.publicKey);

        // The data we want to encrypt
        const obj = {hello: "world"};

        // encrypt and decrypt using lexi-aware wallet
        const lexiWallet = new LexiWallet(signer, me, {});
        const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
        const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

        expect(decrypted).to.eql(obj);
    });

    it("We create a LexiWallet and call the encrypt method", async () => {
        // const signKey = sign.keyPair();
        const signer = new SignWalletWithKey(signKey);

        // derive my did from this signing key
        const me = "did:sol:" + encode(signKey.publicKey);

        // The data we want to encrypt
        const obj = {hello: "world"};

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
        sandbox.stub(axios, "get").returns(Promise.resolve({data:
                {
                    didDocument: {
                        '@context': ['https://w3id.org/did/v1.0', 'https://w3id.org/sol/v1'],
                        id: 'did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa',
                        controller: [],
                        verificationMethod: [[Object]],
                        authentication: [],
                        assertionMethod: [],
                        capabilityInvocation: ['did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa#default'],
                        capabilityDelegation: [],
                        service: [],
                        publicKey: [[Object]]
                    },
                    content: null,
                    contentType: null,
                    didResolutionMetadata: {
                        duration: 3077,
                        identifier: 'did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa',
                        pattern: '^(did:sol:.+)$',
                        driverUrl: 'http://driver-did-sol:8080/1.0/identifiers/',
                        didUrl: {
                            didUrlString: 'did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa',
                            did: [Object],
                            path: '',
                            query: null,
                            fragment: null,
                            parameters: {},
                            parseTree: null,
                            parseRuleCount: null
                        }
                    },
                    didDocumentMetadata: {}
                }
        }));

        // const signKey = sign.keyPair();
        const signer = new SignWalletWithKey(signKey);

        // derive my did from this signing key
        const me = "did:sol:" + encode(signKey.publicKey);

        // The data we want to encrypt
        const obj = {hello: "world"};

        // encrypt and decrypt using lexi-aware wallet
        const lexiWallet = new LexiWallet(signer, me);
        const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
        const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

        expect(decrypted).to.eql(obj);
    });

    it("We can call encrypt and decrypt with a fixed signing message", async () => {
        const signer = new SignWalletWithKey(signKey);

        const signMessageSpy = sandbox.spy(signer, "signMessage");

        // derive my did from this signing key
        const me = "did:sol:" + encode(signKey.publicKey);

        // The data we want to encrypt
        const obj = {hello: "world"};

        // encrypt and decrypt using lexi-aware wallet
        const lexiWallet = new LexiWallet(signer, me, {
            publicSigningString: "test",
        });
        const encryptedWithWallet = await lexiWallet.encryptForMe(obj);
        const decrypted = await lexiWallet.decrypt(encryptedWithWallet);

        expect(signMessageSpy.calledWith(base64.decode("bFUxYVNmMXcyYmk4MnpYU1VpWjRLWlYvZnZmNmJIVDRoQm05eGVnaUNmUT0="))).to.eql(true);
        expect(decrypted).to.eql(obj);
    });

    it("Test what happens if we can't get a back a DIDDocument", async () => {

        // restore sandbox so we can reset the stub
        sandbox.restore();
        sandbox.stub(axios, "get").returns(Promise.resolve({data:
                {
                    content: null,
                    contentType: null,
                    didResolutionMetadata: {
                        duration: 3077,
                        identifier: 'did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa',
                        pattern: '^(did:sol:.+)$',
                        driverUrl: 'http://driver-did-sol:8080/1.0/identifiers/',
                        didUrl: {
                            didUrlString: 'did:sol:6n853y6agbzauRS9BhkovVF2EuGux4C7iq7RFdZPhYPa',
                            did: [Object],
                            path: '',
                            query: null,
                            fragment: null,
                            parameters: {},
                            parseTree: null,
                            parseRuleCount: null
                        }
                    },
                    didDocumentMetadata: {}
                }
        }));

        // const signKey = sign.keyPair();
        const signer = new SignWalletWithKey(signKey);

        // derive my did from this signing key
        const me = "did:sol:" + encode(signKey.publicKey);

        // The data we want to encrypt
        const obj = {hello: "world"};

        // encrypt and decrypt using lexi-aware wallet
        const lexiWallet = new LexiWallet(signer, me);
        return expect(lexiWallet.encryptForMe(obj)).to.eventually.be.rejectedWith(`resolver_error: Could not resolve did:sol:${encode(signKey.publicKey)}: undefined, undefined`);
    });

});
