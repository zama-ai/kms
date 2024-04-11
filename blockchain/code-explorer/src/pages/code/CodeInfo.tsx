import { CodeDetails } from "cosmwasm";
import React from "react";

import { AccountLink } from "../../components/AccountLink";
import { TransactionLink } from "../../components/TransactionLink";
import { ErrorState, isErrorState, isLoadingState, LoadingState } from "../../ui-utils/states";

interface Props {
  readonly code: CodeDetails;
  readonly uploadTxHash: string | undefined | ErrorState | LoadingState;
}

export function CodeInfo({ code, uploadTxHash }: Props): JSX.Element {
  return (
    <div className="card mb-3">
      <ul className="list-group list-group-flush">
        <li className="list-group-item">
          Upload transaction:{" "}
          {isLoadingState(uploadTxHash) ? (
            "Loading …"
          ) : isErrorState(uploadTxHash) ? (
            "Error"
          ) : uploadTxHash === undefined ? (
            "–"
          ) : (
            <TransactionLink transactionId={uploadTxHash} />
          )}
        </li>
        <li className="list-group-item">
          Creator: <AccountLink address={code.creator} maxLength={null} />
        </li>
        <li className="list-group-item">Checksum: {code.checksum}</li>
      </ul>
    </div>
  );
}
