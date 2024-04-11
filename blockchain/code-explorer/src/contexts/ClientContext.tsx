import { MsgExecuteContract, MsgInstantiateContract, MsgStoreCode } from "cosmjs-types/cosmwasm/wasm/v1/tx";
import { Registry } from "cosmwasm";
import React from "react";

import { CosmWasmClient, SigningCosmWasmClient } from "../ui-utils/clients";
import {
  msgExecuteContractTypeUrl,
  msgInstantiateContractTypeUrl,
  msgStoreCodeTypeUrl,
} from "../ui-utils/txs";

export interface ClientContextValue {
  readonly nodeUrl: string;
  readonly client: CosmWasmClient | null;
  readonly typeRegistry: Registry;
  readonly resetClient: (nodeUrl: string) => void;
  readonly userAddress?: string;
  readonly setUserAddress: (newUserAddress?: string) => void;
  readonly signingClient?: SigningCosmWasmClient;
  readonly setSigningClient: (newSigningClient?: SigningCosmWasmClient) => void;
}

/**
 * "only used when a component does not have a matching Provider above it in the tree"
 *
 * @see https://reactjs.org/docs/context.html#reactcreatecontext
 */
const dummyContext: ClientContextValue = {
  nodeUrl: "",
  client: null,
  typeRegistry: new Registry([
    [msgStoreCodeTypeUrl, MsgStoreCode],
    [msgInstantiateContractTypeUrl, MsgInstantiateContract],
    [msgExecuteContractTypeUrl, MsgExecuteContract],
  ]),
  resetClient: () => {},
  setUserAddress: () => {},
  setSigningClient: () => {},
};

export const ClientContext = React.createContext<ClientContextValue>(dummyContext);
