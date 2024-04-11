import { Contract } from "cosmwasm";
import React from "react";

import { AccountLink } from "../../components/AccountLink";
import { TransactionLink } from "../../components/TransactionLink";
import { ErrorState, isErrorState, isLoadingState, LoadingState } from "../../ui-utils/states";

interface Props {
  readonly contract: Contract;
  readonly instantiationTxHash: string | undefined | ErrorState | LoadingState;
}

export function InitializationInfo({ contract, instantiationTxHash }: Props): JSX.Element {
  return (
    <div className="card mb-3">
      <ul className="list-group list-group-flush">
        <li className="list-group-item">
          Instantiation transaction:{" "}
          {isLoadingState(instantiationTxHash) ? (
            "Loading …"
          ) : isErrorState(instantiationTxHash) ? (
            "Error"
          ) : instantiationTxHash === undefined ? (
            "–"
          ) : (
            <TransactionLink transactionId={instantiationTxHash} />
          )}
        </li>
        <li className="list-group-item">
          Creator: <AccountLink address={contract.creator} maxLength={null} />
        </li>
        <li className="list-group-item">
          Admin: {contract.admin ? <AccountLink address={contract.admin} maxLength={null} /> : "–"}
        </li>
      </ul>
    </div>
  );
}
