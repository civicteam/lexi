import React, {createContext, FC, PropsWithChildren, useContext, useEffect, useState} from "react";
import {ethers} from "ethers";
import Web3Modal, {IProviderOptions} from "web3modal";
import {CoinbaseWalletSDK} from "@coinbase/wallet-sdk";
import WalletConnectProvider from "@walletconnect/web3-provider";

const providerOptions: IProviderOptions = {
  metamask: {
    id: "injected",
    name: "MetaMask",
    type: "injected",
    check: "isMetaMask"
  },
  walletlink: {
    package: CoinbaseWalletSDK,
    options: {
      appName: "Lexi Example",
      infuraId: process.env.INFURA_KEY
    }
  },
  walletconnect: {
    package: WalletConnectProvider,
    options: {
      infuraId: "INFURA_ID",
      network: "rinkeby",
      qrcodeModalOptions: {
        mobileLinks: [
          "rainbow",
          "metamask",
          "argent",
          "trust",
          "imtoken",
          "pillar"
        ]
      }
    }
  }
} as unknown as IProviderOptions;

const web3Modal = new Web3Modal({
  network: "mainnet",
  cacheProvider: true,
  disableInjectedProvider: false,
  providerOptions
})

export type WalletContextProps = {
  account: string,
  signMessage: (message: Uint8Array) => Promise<Uint8Array>
  connect: () => Promise<void>
  disconnect: () => Promise<void>
}
export const WalletContext = createContext<WalletContextProps>(
  {
    account: "",
    signMessage: async (message: Uint8Array) => message,
    connect: async () => {},
    disconnect: async () => {}
  }
);

export const WalletProvider: FC<PropsWithChildren<unknown>> = ({ children }) => {
  const [provider, setProvider] = useState<any>();
  const [library, setLibrary] = useState<ethers.providers.Web3Provider>();
  const [account, setAccount] = useState<string>();
  const [error, setError] = useState<any>();
  const [chainId, setChainId] = useState<number>();
  const [network, setNetwork] = useState<number>();

  const connect = async () => {
    try {
      const provider = await web3Modal.connect();
      const library = new ethers.providers.Web3Provider(provider);
      const accounts = await library.listAccounts();
      const network = await library.getNetwork();
      setProvider(provider);
      setLibrary(library);
      if (accounts) {
        setAccount(accounts[0]);
      }
      setChainId(network.chainId);
    } catch (error) {
      setError(error);
    }
  };

  const signMessage = async (message: Uint8Array) :Promise<Uint8Array> => {
    if (!library?.provider?.request) return Promise.reject("No provider");

    const request = {
      method: "personal_sign",
      params: [Buffer.from(message).toString('hex'), account]
    };

    console.log("Request  ", request);
    return library.provider.request(request);
  };

  const refreshState = () => {
    setAccount(undefined);
    setChainId(undefined);
    setNetwork(undefined);
  };

  const disconnect = async () => {
    await web3Modal.clearCachedProvider();
    refreshState();
  };

  useEffect(() => {
    if (web3Modal.cachedProvider) {
      connect();
    }
  }, []);

  useEffect(() => {
    if (provider?.on) {
      const handleAccountsChanged = (accounts: string[]) => {
        console.log("accountsChanged", accounts);
        if (accounts) {
          setAccount(accounts[0]);
        }
      };

      const handleChainChanged = (_hexChainId: number) => {
        setChainId(_hexChainId);
      };

      const handleDisconnect = () => {
        console.log("disconnect", error);
        disconnect();
      };

      provider.on("accountsChanged", handleAccountsChanged);
      provider.on("chainChanged", handleChainChanged);
      provider.on("disconnect", handleDisconnect);

      return () => {
        if (provider.removeListener) {
          provider.removeListener("accountsChanged", handleAccountsChanged);
          provider.removeListener("chainChanged", handleChainChanged);
          provider.removeListener("disconnect", handleDisconnect);
        }
      };
    }
  }, [provider]);

  const props = {
    account,
    signMessage,
    connect,
    disconnect
  }

  return (
    <WalletContext.Provider value={props}>{children}</WalletContext.Provider>
  );
};

export const useWallet = (): WalletContextProps => useContext(WalletContext);
