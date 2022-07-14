import React, { FC, ReactNode, useCallback, useMemo, useState } from "react";
import "./App.css";

import { WalletAdapterNetwork } from "@solana/wallet-adapter-base";
import {
  ConnectionProvider,
  useWallet,
  WalletProvider,
} from "@solana/wallet-adapter-react";
import {
  WalletModalProvider,
  WalletMultiButton,
} from "@solana/wallet-adapter-react-ui";
import {
  LedgerWalletAdapter,
  PhantomWalletAdapter,
  SlopeWalletAdapter,
  SolflareWalletAdapter,
  SolletExtensionWalletAdapter,
  SolletWalletAdapter,
  TorusWalletAdapter,
} from "@solana/wallet-adapter-wallets";
import { clusterApiUrl } from "@solana/web3.js";
import { LexiWallet } from "@civic/lexi";

require("./App.css");
require("@solana/wallet-adapter-react-ui/styles.css");

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
      new SlopeWalletAdapter(),
      new SolflareWalletAdapter({ network }),
      new TorusWalletAdapter(),
      new LedgerWalletAdapter(),
      new SolletWalletAdapter({ network }),
      new SolletExtensionWalletAdapter({ network }),
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
  const [message, setMessage] = useState("");
  const [encryptedMessage, setEncryptedMessage] = useState("");
  const [decryptedMessage, setDecryptedMessage] = useState("");
  const wallet = useWallet();

  const lexi = useMemo(() => {
    if (wallet && wallet.publicKey) {
      const signWallet = {
        signMessage: (message: Uint8Array) => {
          if (wallet.signMessage) {
            return wallet.signMessage(message);
          } else {
            return Promise.reject("Wallet does not support signing");
          }
        },
      };
      console.log("did:sol:" + wallet.publicKey.toBase58());
      return new LexiWallet(
        signWallet,
        "did:sol:devnet:" + wallet.publicKey.toBase58()
      );
    }
  }, [wallet]);

  const encrypt = useCallback(async () => {
    lexi?.encryptForMe({ message }).then((encryptedMessage: string) => {
      setEncryptedMessage(encryptedMessage);
    });
  }, [message, lexi]);

  const descrypt = useCallback(async () => {
    console.log(message, lexi);
    lexi?.decrypt(message).then((decrypted: Record<string, unknown>) => {
      setDecryptedMessage(JSON.stringify(decrypted));
    });
  }, [message, lexi]);

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      <WalletMultiButton />
      <textarea onChange={(e) => setMessage(e.target.value)} />
      <div style={{ display: "flex", flexDirection: "column" }}>
        <button onClick={encrypt}>Encrypt</button>
        {encryptedMessage && <textarea value={encryptedMessage} />}
      </div>
      <div style={{ display: "flex", flexDirection: "column" }}>
        <button onClick={descrypt}>Decrypt</button>
        {decryptedMessage && <textarea value={decryptedMessage} />}
      </div>
    </div>
  );
};

export default App;
