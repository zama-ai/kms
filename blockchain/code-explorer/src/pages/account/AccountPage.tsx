import { Coin } from "cosmjs-types/cosmos/base/v1beta1/coin";
import { Tx } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { IndexedTx, Registry } from "cosmwasm";
import React from "react";
import { Link, useParams } from "react-router-dom";

import { FooterRow } from "../../components/FooterRow";
import { Header } from "../../components/Header";
import { ClientContext } from "../../contexts/ClientContext";
import { settings } from "../../settings";
import { ellideMiddle, printableBalance } from "../../ui-utils";
import {
  ErrorState,
  errorState,
  isErrorState,
  isLoadingState,
  LoadingState,
  loadingState,
} from "../../ui-utils/states";
import { AnyMsgSend, isAnyMsgSend } from "../../ui-utils/txs";
import { Transfer, TransfersTable } from "./TransfersTable";

type ICoin = Coin;

function getTransferFromStargateMsgSend(typeRegistry: Registry, tx: IndexedTx) {
  return (msg: AnyMsgSend, i: number) => {
    const decodedMsg = typeRegistry.decode({ typeUrl: msg.typeUrl, value: msg.value });
    return {
      key: `${tx.hash}_${i}`,
      height: tx.height,
      transactionId: tx.hash,
      msg: decodedMsg,
    };
  };
}

export function AccountPage(): JSX.Element {
  const { client, typeRegistry } = React.useContext(ClientContext);
  const { address: addressParam } = useParams<{ readonly address: string }>();
  const address = addressParam || "";

  const [balance, setBalance] = React.useState<readonly ICoin[] | ErrorState | LoadingState>(loadingState);
  const [transfers, setTransfers] = React.useState<readonly Transfer[] | ErrorState | LoadingState>(
    loadingState,
  );

  React.useEffect(() => {
    if (!client) return;

    Promise.all(settings.backend.denominations.map((denom) => client.getBalance(address, denom)))
      .then((balances) => {
        const filteredBalances = balances.filter((balance): balance is Coin => balance !== null);
        setBalance(filteredBalances);
      })
      .catch(() => setBalance(errorState));
    client
      .searchTx({ sentFromOrTo: address })
      .then((txs) => {
        const out = txs.reduce((transfers: readonly Transfer[], tx: IndexedTx): readonly Transfer[] => {
          const decodedTx = Tx.decode(tx.tx);
          const txTransfers = (decodedTx?.body?.messages ?? [])
            .filter(isAnyMsgSend)
            .map(getTransferFromStargateMsgSend(typeRegistry, tx));
          return [...transfers, ...txTransfers];
        }, []);
        setTransfers(out);
      })
      .catch(() => setTransfers(errorState));
  }, [address, client, typeRegistry]);

  const pageTitle = <span title={address}>Account {ellideMiddle(address, 15)}</span>;

  return (
    <div className="page">
      <Header />
      <div className="container mt-3 contract-container">
        <div className="row white-row white-row-first">
          <div className="col">
            <nav aria-label="breadcrumb">
              <ol className="breadcrumb">
                <li className="breadcrumb-item">
                  <Link to="/">Home</Link>
                </li>
                <li className="breadcrumb-item active" aria-current="page">
                  {pageTitle}
                </li>
              </ol>
            </nav>
          </div>
        </div>

        <div className="row white-row">
          <div className="col">
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
        </div>

        <div className="row white-row white-row-last">
          <div className="col">
            <h2>Token transfers</h2>
            <p>Incoming and outgoing bank token transfers</p>
            {isLoadingState(transfers) ? (
              <p>Loading …</p>
            ) : isErrorState(transfers) ? (
              <p>Error</p>
            ) : transfers.length === 0 ? (
              <p>No transfer found</p>
            ) : (
              <TransfersTable transfers={transfers} />
            )}
          </div>
        </div>

        <FooterRow />
      </div>
    </div>
  );
}
