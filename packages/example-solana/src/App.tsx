import React, {FC, ReactNode, useCallback, useMemo, useState} from 'react';
import './App.css';

import { WalletAdapterNetwork } from '@solana/wallet-adapter-base';
import {ConnectionProvider, useWallet, WalletProvider} from '@solana/wallet-adapter-react';
import { WalletModalProvider, WalletMultiButton } from '@solana/wallet-adapter-react-ui';
import {
  LedgerWalletAdapter,
  PhantomWalletAdapter,
  SolflareWalletAdapter,
} from '@solana/wallet-adapter-wallets';
import { clusterApiUrl } from '@solana/web3.js';
import {bytesToObj, LexiWallet, objToBytes} from "@civic/lexi";
import {EncryptionPackage} from "@civic/lexi/dist/lib/encrypt";

require('@solana/wallet-adapter-react-ui/styles.css');

export const App: FC = () => {
  return (
    <Context>
      <Content />
    </Context>
  );
};

const Context: FC<{ children: ReactNode }> = ({ children }) => {
  // The network can be set to 'devnet', 'testnet', or 'mainnet-beta'.
  const network = WalletAdapterNetwork.Devnet;

  // You can also provide a custom RPC endpoint.
  const endpoint = useMemo(() => clusterApiUrl(network), [network]);

  // @solana/wallet-adapter-wallets includes all the adapters but supports tree shaking and lazy loading --
  // Only the wallets you configure here will be compiled into your application, and only the dependencies
  // of wallets that your users connect to will be loaded.
  const wallets = useMemo(
    () => [
      new PhantomWalletAdapter(),
      new SolflareWalletAdapter({ network }),
      new LedgerWalletAdapter(),
    ],
    [network]
  );

  return (
    <ConnectionProvider endpoint={endpoint}>
      <WalletProvider wallets={wallets} autoConnect>
        <WalletModalProvider>{children}</WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
};

const Content: FC = () => {
  const [seed, setSeed] = useState("secret")
  const [input, setInput] = useState("")
  const [output, setOutput] = useState<EncryptionPackage | null>(null)
  const wallet = useWallet();

  const lexi = useMemo(() => {
    if (wallet && wallet.publicKey) {
      const signWallet = {
        signMessage: (message: Uint8Array) => {
          if (wallet.signMessage) {
            return wallet.signMessage(message)
          } else {
            return Promise.reject("Wallet does not support signing")
          }
        },
      }
      return new LexiWallet(signWallet, "did:sol:" + wallet.publicKey.toBase58(), { publicSigningString : seed})
    }
  }, [wallet, seed])

  const encrypt = useCallback(async () => {
    lexi?.encryptForMe(objToBytes({ message: input })).then(setOutput)
  }, [input, lexi])

  const decrypt = useCallback(async () => {
    const encryptionPackage = JSON.parse(input) as EncryptionPackage
    lexi?.decrypt(encryptionPackage).then((decrypted) => setOutput(bytesToObj(decrypted)))
  }, [input, lexi])

  const clear = useCallback(() => {
    setInput("")
    setOutput(null)
  }, [])

  return <div>
    <div className="ml-auto p-5">
      <WalletMultiButton />
    </div>
    <div className="flex justify-center items-center flex-wrap w-1/2 mx-auto">
      <div className="w-full pt-3">
        <h1 className="text-center text-3xl">Encrypt</h1>
      </div>
      <div className="w-full text-center pt-3 text-gray-800">
        <input className="text-center" value={seed} onChange={(e) => setSeed(e.target.value)} />
      </div>
      <div className="w-full text-center pt-3 text-gray-800">
        <textarea onChange={(e) => setInput(e.target.value)}/>
      </div>
      <div className="w-full text-center pt-3">
        <button className="btn btn-blue" onClick={encrypt}>Encrypt</button>
        <button className="btn btn-blue" onClick={decrypt}>Decrypt</button>
        <button className="btn btn-blue" onClick={clear}>Clear</button>
      </div>
      <div className="w-full text-center pt-3 text-gray-800">
        {output && <textarea readOnly={true} value={JSON.stringify(output, null, 2)}/>}
      </div>
    </div>
  </div>;
};

export default App;
