import "./ContractPage.css";

import { Coin as ICoin } from "cosmjs-types/cosmos/base/v1beta1/coin";
import { Tx } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { Any } from "cosmjs-types/google/protobuf/any";
import { Coin, Contract, ContractCodeHistoryEntry, IndexedTx, Registry } from "cosmwasm";
import React from "react";
import { Link, useParams } from "react-router-dom";

import { CodeLink } from "../../components/CodeLink";
import { FooterRow } from "../../components/FooterRow";
import { Header } from "../../components/Header";
import { ClientContext } from "../../contexts/ClientContext";
import { settings } from "../../settings";
import { ellideMiddle, printableBalance } from "../../ui-utils";
import { CosmWasmClient } from "../../ui-utils/clients";
import { makeTags } from "../../ui-utils/sdkhelpers";
import {
  ErrorState,
  errorState,
  isErrorState,
  isLoadingState,
  LoadingState,
  loadingState,
} from "../../ui-utils/states";
import { ExecuteContract } from "./ExecuteContract";
import { Execution, ExecutionsTable } from "./ExecutionsTable";
import { HistoryInfo } from "./HistoryInfo";
import { InitializationInfo } from "./InitializationInfo";
import { QueryContract } from "./QueryContract";

type IAnyMsgExecuteContract = {
  readonly typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract";
  readonly value: Uint8Array;
};

export type Result<T> = { readonly result?: T; readonly error?: string };

function isStargateMsgExecuteContract(msg: Any): msg is IAnyMsgExecuteContract {
  return msg.typeUrl === "/cosmwasm.wasm.v1.MsgExecuteContract" && !!msg.value;
}

const getAndSetDetails = (
  client: CosmWasmClient,
  contractAddress: string,
  setDetails: (details: Contract | ErrorState | LoadingState) => void,
): void => {
  client
    .getContract(contractAddress)
    .then(setDetails)
    .catch(() => setDetails(errorState));
};

const getAndSetContractCodeHistory = (
  client: CosmWasmClient,
  contractAddress: string,
  setContractCodeHistory: (contractCodeHistory: readonly ContractCodeHistoryEntry[]) => void,
): void => {
  client
    .getContractCodeHistory(contractAddress)
    .then(setContractCodeHistory)
    .catch((error) => {
      console.error(error);
    });
};

const getAndSetInstantiationTxHash = (
  client: CosmWasmClient,
  contractAddress: string,
  setInstantiationTxHash: (instantiationTxHash: string | undefined | ErrorState | LoadingState) => void,
): void => {
  client
    .searchTx({
      tags: makeTags(`message.module=wasm&instantiate._contract_address=${contractAddress}`),
    })
    .then((results) => {
      const first = results.find(() => true);
      setInstantiationTxHash(first?.hash);
    })
    .catch(() => setInstantiationTxHash(errorState));
};

function getExecutionFromStargateMsgExecuteContract(typeRegistry: Registry, tx: IndexedTx) {
  return (msg: IAnyMsgExecuteContract, i: number) => {
    const decodedMsg = typeRegistry.decode({ typeUrl: msg.typeUrl, value: msg.value });
    return {
      key: `${tx.hash}_${i}`,
      height: tx.height,
      transactionId: tx.hash,
      msg: decodedMsg,
    };
  };
}

export function ContractPage(): JSX.Element {
  const { client, typeRegistry } = React.useContext(ClientContext);
  const { contractAddress: contractAddressParam } = useParams<{ readonly contractAddress: string }>();
  const contractAddress = contractAddressParam || "";

  const [details, setDetails] = React.useState<Contract | ErrorState | LoadingState>(loadingState);
  const [balance, setBalance] = React.useState<readonly ICoin[] | ErrorState | LoadingState>(loadingState);
  const [instantiationTxHash, setInstantiationTxHash] = React.useState<
    string | undefined | ErrorState | LoadingState
  >(loadingState);
  const [contractCodeHistory, setContractCodeHistory] = React.useState<readonly ContractCodeHistoryEntry[]>(
    [],
  );
  const [executions, setExecutions] = React.useState<readonly Execution[] | ErrorState | LoadingState>(
    loadingState,
  );

  React.useEffect(() => {
    if (!client) return;

    getAndSetContractCodeHistory(client, contractAddress, setContractCodeHistory);
    getAndSetDetails(client, contractAddress, setDetails);
    getAndSetInstantiationTxHash(client, contractAddress, setInstantiationTxHash);

    Promise.all(settings.backend.denominations.map((denom) => client.getBalance(contractAddress, denom)))
      .then((balances) => {
        const filteredBalances = balances.filter((balance): balance is Coin => balance !== null);
        setBalance(filteredBalances);
      })
      .catch(() => setBalance(errorState));

    client
      .searchTx({
        tags: makeTags(`message.module=wasm&execute._contract_address=${contractAddress}`),
      })
      .then((txs) => {
        const out = txs.reduce((executions: readonly Execution[], tx: IndexedTx): readonly Execution[] => {
          const decodedTx = Tx.decode(tx.tx);
          const txExecutions = (decodedTx?.body?.messages ?? [])
            .filter(isStargateMsgExecuteContract)
            .map(getExecutionFromStargateMsgExecuteContract(typeRegistry, tx));
          return [...executions, ...txExecutions];
        }, []);
        setExecutions(out);
      })
      .catch(() => setExecutions(errorState));
  }, [client, contractAddress, typeRegistry]);

  const pageTitle = <span title={contractAddress}>Contract {ellideMiddle(contractAddress, 15)}</span>;

  return (
    <div className="page">
      <Header />
      <div className="container mt-3 contract-container">
        <div className="row white-row white-row-first">
          <div className="col">
            <nav aria-label="breadcrumb">
              <ol className="breadcrumb">
                <li className="breadcrumb-item">
                  <Link to="/codes">Codes</Link>
                </li>
                <li className="breadcrumb-item">
                  {isLoadingState(details) ? (
                    <span>Loading …</span>
                  ) : isErrorState(details) ? (
                    <span>Error</span>
                  ) : (
                    <CodeLink codeId={details.codeId} />
                  )}
                </li>
                <li className="breadcrumb-item active" aria-current="page">
                  {pageTitle}
                </li>
              </ol>
            </nav>
          </div>
        </div>
        <div className="row white-row">
          <div className="col-12 col-md-6">
            <h1>{pageTitle}</h1>
            <ul className="list-group list-group-horizontal mb-3">
              <li className="list-group-item" title="Bank tokens owned by this contract">
                Balance:{" "}
                {isLoadingState(balance)
                  ? "Loading …"
                  : isErrorState(balance)
                  ? "Error"
                  : printableBalance(balance)}
              </li>
            </ul>
          </div>
          <div className="col-12 col-md-6">
            {isLoadingState(details) ? (
              <p>Loading …</p>
            ) : isErrorState(details) ? (
              <p>An Error occurred when loading contract</p>
            ) : (
              <>
                <InitializationInfo contract={details} instantiationTxHash={instantiationTxHash} />
                <HistoryInfo contractCodeHistory={contractCodeHistory} />
                <QueryContract contractAddress={contractAddress} />
                <ExecuteContract contractAddress={contractAddress} />
              </>
            )}
          </div>
        </div>
        <div className="row white-row white-row-last">
          <div className="col">
            <h2>Executions</h2>
            {isLoadingState(executions) ? (
              <p>Loading …</p>
            ) : isErrorState(executions) ? (
              <p>An Error occurred when loading transactions</p>
            ) : executions.length !== 0 ? (
              <ExecutionsTable executions={executions} />
            ) : (
              <p>Contract was not yet executed</p>
            )}
          </div>
        </div>

        <FooterRow />
      </div>
    </div>
  );
}
