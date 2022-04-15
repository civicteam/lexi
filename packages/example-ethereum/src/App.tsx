import React, {FC, useCallback, useMemo, useState} from 'react';
import './App.css';

import {LexiWallet} from "@civic/lexi";
import {useWallet, WalletProvider} from "./WalletContext";

export const App: FC = () =>
  <WalletProvider>
    <Content/>
  </WalletProvider>;

const Content: FC = () => {
  const [seed, setSeed] = useState("secret")
  const [input, setInput] = useState("")
  const [output, setOutput] = useState("")
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
      const did = "did:ethr:" + wallet.account;
      console.log("DID", did)
      return new LexiWallet(signWallet, did, { publicSigningString : seed})
    }
  }, [wallet, seed])

  const encrypt = useCallback(async () => {
    lexi?.encryptForMe({ message: input }).then(setOutput)
  }, [input, lexi])

  const decrypt = useCallback(async () => {
    lexi?.decrypt(input).then(({message}) => setOutput(message as string))
  }, [input, lexi])

  const clear = useCallback(() => {
    setInput("")
    setOutput("")
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
        {output && <textarea readOnly={true} value={output}/>}
      </div>
    </div>
  </div>;
};

export default App;
