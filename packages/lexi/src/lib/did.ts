import axios from "axios";
import { encode } from "bs58";
import type {
  DIDDocument,
  DIDResolutionResult,
  VerificationMethod,
} from "did-resolver";
import { generateX25519KeyPairFromSignature } from "./key";
import type { SignWallet } from "./wallet";

export type LexiSignOptions = {
  friendlyString?: string;
};

export type LexiOptions = LexiSignOptions & {
  resolve?: Resolver;
};

const augmentDIDLexi =
  (signer: SignWallet, signatureInput: string) =>
  async (didDocument: DIDDocument): Promise<DIDDocument> => {
    const keyPair = await generateX25519KeyPairFromSignature(
      signer,
      signatureInput
    );

    const lexiKey = {
      id: "lexi",
      type: "X25519KeyAgreementKey2019",
      publicKeyBase58: encode(keyPair.publicKey),
    } as VerificationMethod;

    const keyAgreement = didDocument.keyAgreement || [];

    // add the new key to the document
    return {
      ...didDocument,
      keyAgreement: [...keyAgreement, lexiKey],
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
  signatureInput: string
) => {
  return augmentedResolver(resolve, augmentDIDLexi(signer, signatureInput));
};

export const simpleResolver = async (
  did: string
): Promise<DIDResolutionResult> =>
  axios
    .get("https://did.civic.com/1.0/identifiers/" + did)
    .then<DIDResolutionResult>((res) => res.data);

export const resolveDID = simpleResolver;
