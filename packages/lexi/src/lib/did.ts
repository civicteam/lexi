import axios from "axios";
import {encode} from "bs58";
import type {DIDDocument, DIDResolutionResult, VerificationMethod,} from "did-resolver";
import type EncryptionKeyBox from "./encryption_key_box";
import {generateX25519KeyPairFromSignature} from "./key";
import type {SignWallet} from "./wallet";

export type LexiSignOptions = {
  publicSigningString?: string;
};

export type LexiOptions = LexiSignOptions & {
  resolve?: Resolver;
};

const augmentDIDLexi =
  (
    signer: SignWallet,
    encryptionKeyBox: EncryptionKeyBox,
    publicSigningString: string
  ) =>
  async (didDocument: DIDDocument): Promise<DIDDocument> => {
    const keyPair = await generateX25519KeyPairFromSignature(
      signer,
      publicSigningString,
      encryptionKeyBox
    );

    const lexiKey = {
      id: `${didDocument.id}#lexi-key`,
      type: "X25519KeyAgreementKey2019",
      controller: didDocument.id,
      publicKeyBase58: encode(keyPair.publicKey),
    } as VerificationMethod;

    // add the new key to the document
    return {
      ...didDocument,
      verificationMethod: [...(didDocument.verificationMethod ?? []), lexiKey],
      keyAgreement: [...(didDocument.keyAgreement ?? []), lexiKey.id],
    };
  };

export type Resolver = (didUrl: string) => Promise<DIDResolutionResult>;
type AugmentDocument = (didDocument: DIDDocument) => Promise<DIDDocument>;

const augmentedResolver =
  (resolve: Resolver, augmentDocument: AugmentDocument): Resolver =>
  async (didUrl: string) => {
    const resolutionResult = await resolve(didUrl);
    if (!resolutionResult.didDocument) return resolutionResult;
    const augmentedDocument = await augmentDocument(
      resolutionResult.didDocument
    );
      return {
          ...resolutionResult,
          didDocument: augmentedDocument,
      };
  };

export const lexiResolver = (
  resolve: Resolver,
  signer: SignWallet,
  encryptionKey: EncryptionKeyBox,
  publicSigningString: string
):Resolver => {
  return augmentedResolver(
    resolve,
    augmentDIDLexi(signer, encryptionKey, publicSigningString)
  );
};

export const simpleResolver = async (
  did: string
): Promise<DIDResolutionResult> => {
    return axios
        .get("https://did.civic.com/1.0/identifiers/" + did, {
            headers: {
                // the uniresolver is sensitive to the accept header.
                // if application/json, it returns a did document, if missing or */*,
                // a did resolution response containing a did document
                Accept: "*/*",
            },
        })
        .then<DIDResolutionResult>((res) => res.data);
};

export const resolveDID = simpleResolver;
