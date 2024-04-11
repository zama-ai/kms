import { Tx } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import React from "react";

import { printableBalance } from "../../ui-utils";

interface Props {
  readonly tx: Tx;
}

export function TxInfo({ tx }: Props): JSX.Element {
  return (
    <div className="card mb-3">
      <ul className="list-group list-group-flush">
        <li className="list-group-item">Memo: {tx.body?.memo || "–"}</li>
        <li className="list-group-item">Fee: {printableBalance(tx.authInfo?.fee?.amount ?? [])}</li>
        <li className="list-group-item">Gas: {tx.authInfo?.fee?.gasLimit?.toString() ?? "0"}</li>
        <li className="list-group-item">Signatures: {tx.signatures?.length ?? 0}</li>
      </ul>
    </div>
  );
}
