# lexi

An encryption mechanism based on "Lexi Magic" - deriving an encryption key from signing public data

## Motivation

It’s strange that most crypto wallets don’t support encryption. After all, at a mathematical level, asymmetric encryption and signing are equivalent actions. Specifically, encrypting data with a public key, and signing a hash with a private key are equivalent, as are the associated decryption and signature verification functions.

Although crypto wallets are primarily (in some cases exclusively) concerned with signing crypto transactions, the value in an encryption feature in Web3, where data are frequently stored on decentralised file stores such as IPFS, is obvious.

Lexi provides means to derive an encryption key via a wallet signature for cases where the wallet does not support encryption.

## Installing

```shell
yarn add @civic/lexi
```

## Example

##### 1. Create a Lexi Wallet

```typescript
const signWallet = {
  signMessage: (message: Uint8Array) => wallet.signMessage(message),
};
const lexiWallet = new LexiWallet(signWallet, did);
```

##### 2. Encrypt some data for your DID

```typescript
const encryptedMessage = await lexiWallet.encryptForMe(objectToEncrypt);
```

Once encrypted, the lexi result string will be similar to:

```
{
  "signingString": "BhgeP5xMXKp/aowFkEGrm+p/ky7oqhvTqzFpMvnvmQQ=",
  "algorithm": "ED25519",
  "schema": "lexi-encryption-v1",
  "payload": {
    "protected": "eyJlbmMiOiJYQzIwUCJ9",
    "iv": "ZgJD_F2zZcj5QDvkmBaPDSaC4Wg6VGOI",
    "ciphertext": "eJM-oFTxXfhosrUFXiXmQv8IPa8eUEGyB2oqqk4yWfLTC5kWdR4-DOslusV1v4o",
    "tag": "v8OJ4sWaSbYwmvZXmPPiyA",
    "recipients": [
      {
        "encrypted_key": "7bBtVPs0cRRNStkh_gf7qxHNk_MfmhIStBQkkQfoNZQ",
        "header": {
          "alg": "ECDH-ES+XC20PKW",
          "iv": "GzsPPIs2P1CeM7tTEfd-1ZleG752c0lA",
          "tag": "E1lLAKxNDeb7kO8FVlKvrA",
          "epk": {
            "kty": "OKP",
            "crv": "X25519",
            "x": "_zZnYLQNtXwHgxVEqaObirX5k62sFg5wuVahf_6-wWE"
          },
          "kid": "lexi"
        }
      }
    ]
  }
}

```

##### 3. Decrypt some previous encrypted data

```javascript
const decryptedData = await lexiWallet.decrypt(encryptedLexiString);
```

The result of the decryption should be the original object you encrypted.

## lexi API

### LexiWallet

The `LexiWallet` is how you interact with lexi.

##### constructor(wallet: [SignWallet](#signwallet-type), myDID: string, options?: [LexiOptions](#lexioptions-type))

Will instantiate a new LexiWallet object. The LexiOptions parameter is optional but a wallet and did must be provided.

##### generateKeyForSigning(): `void`

Generate and store the keys for signing. This can be called if you want to have control over when the `signMessage` method will be called. Otherwise, it will be called on encrypt/decrypt if there is no key saved for the signing string.

##### encrypt(plaintext: Record`<string, unknown>`, did: string): Promise`<string>`

Encrypt an object for a DID. The payload will be encrypted for the DID by adding a new Verification Method to it based on Lexi:

```typescript
const keyPair = await generateX25519KeyPairFromSignature(
  signer,
  publicSigningString,
  encryptionKeyBox
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
```

##### encryptForMe(plaintext: Record`<string, unknown>`): Promise`<string>`

Encrypt an object for the did used in the wallet. The process is the same as `encrypt`.

##### decrypt(lexitext: string): Promise`<Record<string, unknown>>`

Decrypts a lexi text and returns the original encrypted data. If the signing string is different from the one in the LexiWallet, `signMessage` will be called with the new string.

#### SignWallet `type`

```typescript
interface SignWallet {
  // the signMessage method to sign a message with a wallet
  signMessage(message: Uint8Array): Promise<Uint8Array>;
}
```

#### LexiOptions `type`

```typescript
type LexiSignOptions = {
  // the public random string used for signing. If this is not provided,
  // a 32 byte string will be randomly generated.
  publicSigningString?: string;
};

type LexiOptions = LexiSignOptions & {
  // the DID resolved to be used. If this is not provided, did.civic.com will
  // be used.
  resolve?: Resolver;
};
```
