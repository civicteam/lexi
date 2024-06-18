import React, {FC, useCallback, useMemo, useState} from 'react';
import './App.css';

import { bytesToObj, LexiWallet, objToBytes } from "@civic/lexi";
import {useWallet, WalletProvider} from "./WalletContext";
import {EncryptionPackage} from "@civic/lexi/dist/lib/encrypt";

export const App: FC = () =>
  <WalletProvider>
    <Content/>
  </WalletProvider>;

const Content: FC = () => {
  const [seed, setSeed] = useState("secret")
  const [input, setInput] = useState("")
  const [output, setOutput] = useState<EncryptionPackage | null>(null)
  const wallet = useWallet();

  const lexi = useMemo(() => {
    if (wallet && wallet.account) {
      const signWallet = {
        signMessage: (message: Uint8Array) => {
          if (wallet.signMessage) {
            return wallet.signMessage(message)
          } else {
            return Promise.reject("Wallet does not support signing")
          }
        },
      }
      const did = "did:pkh:eip155:1:" + wallet.account;
      return new LexiWallet(signWallet, did, { publicSigningString : seed})
    }
  }, [wallet, seed])

  const encrypt = useCallback(async () => {
    lexi?.encryptForMe(objToBytes({ message: input })).then(setOutput)
  }, [input, lexi])

  const decrypt = useCallback(async () => {
    const encryptionPackage = JSON.parse(input) as EncryptionPackage
    lexi?.decrypt(encryptionPackage).then((decrypted) => setOutput(bytesToObj(decrypted).message))
  }, [input, lexi])

  const clear = useCallback(() => {
    setInput("")
    setOutput(null)
  }, [])

  return <div>
    <div className="ml-auto p-5">
      {wallet?.account ?
        <button className="btn btn-blue" onClick={wallet.disconnect}>{wallet.account}</button> :
      <button className="btn btn-blue" onClick={wallet.connect}>Connect Wallet</button>
      }
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
