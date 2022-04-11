import type {DIDDocument, DIDResolutionResult, VerificationMethod} from "did-resolver";
import {decode, encode} from "bs58";
import {convertPublicKey} from "ed2curve-esm";
import axios from "axios";
import {generateX25519KeyPairFromSignature, publicString} from "./key";
import type {SignWallet} from "./wallet";

const augmentDIDmainKeyToKeyAgreement = async (didDocument: DIDDocument): Promise<DIDDocument> => {
  // key agreement key already exists, so we can use it
  if (didDocument.keyAgreement && didDocument.keyAgreement.length) return didDocument;

  if (!didDocument.publicKey || !didDocument.publicKey.length) {
    throw Error('Cannot augment DID document for x25519. The document has no keys')
  }

  const keyAgreementKeys = didDocument.publicKey.map(key => ({
    ...key,
    id: key.id + '_keyAgreement',
    type: 'X25519KeyAgreementKey2019',
    publicKeyBase58: encode(convertPublicKey(decode(key.publicKeyBase58 || '')))
  }));

  // add the new key to the document
  return {
    ...didDocument,
    publicKey: [...didDocument.publicKey, ...keyAgreementKeys],
    keyAgreement: keyAgreementKeys.map(key => key.id)
  }
};

const augmentDIDLexi = (signer: SignWallet) => async (didDocument: DIDDocument): Promise<DIDDocument> => {
  const lexiKeypair = await generateX25519KeyPairFromSignature(publicString, signer);
  const lexiKey = {
    id: 'lexi',
    type: 'X25519KeyAgreementKey2019',
    publicKeyBase58: encode(lexiKeypair.publicKey)
  } as VerificationMethod;

  const keyAgreement = didDocument.keyAgreement || [];

  // add the new key to the document
  return {
    ...didDocument,
    keyAgreement: [
      ...keyAgreement,
      lexiKey
    ]
  }
};

type Resolver = (didUrl: string) => Promise<DIDResolutionResult>
type AugmentDocument = (didDocument: DIDDocument) => Promise<DIDDocument>;

const augmentedResolver = (resolve: Resolver, augmentDocument: AugmentDocument):Resolver =>
  async (didUrl: string) => {
    const resolutionResult = await resolve(didUrl);
    if (!resolutionResult.didDocument) return resolutionResult;
    const augmentedDocument = await augmentDocument(resolutionResult.didDocument);
    return {
      ...resolutionResult,
      didDocument: augmentedDocument
    }
  }

export const mainKeyToKeyAgreementResolver = (resolve: Resolver) => augmentedResolver(resolve, augmentDIDmainKeyToKeyAgreement);

export const lexiResolver = (resolve: Resolver, signer: SignWallet) => augmentedResolver(resolve, augmentDIDLexi(signer));

export const simpleResolver = async (did: string): Promise<DIDResolutionResult> => axios
  .get<DIDResolutionResult>('https://did.civic.com/1.0/identifiers/' + did)
  .then(res => res.data)

export const resolveDID = mainKeyToKeyAgreementResolver(simpleResolver);
