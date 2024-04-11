import { MsgExecuteContract } from "cosmjs-types/cosmwasm/wasm/v1/tx";
import React from "react";

import { AccountLink } from "../../components/AccountLink";
import { TransactionLink } from "../../components/TransactionLink";

export interface Execution {
  readonly key: string;
  readonly height: number;
  readonly transactionId: string;
  readonly msg: MsgExecuteContract;
}

interface Props {
  readonly executions: readonly Execution[];
}

export function ExecutionsTable({ executions }: Props): JSX.Element {
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">#</th>
          <th scope="col">Height</th>
          <th scope="col">Transaction ID</th>
          <th scope="col">Sender</th>
        </tr>
      </thead>
      <tbody>
        {executions.map((execution, index) => (
          <tr key={execution.key}>
            <th scope="row">{index + 1}</th>
            <td>{execution.height}</td>
            <td>
              <TransactionLink transactionId={execution.transactionId} />
            </td>
            <td>
              <AccountLink address={execution.msg.sender} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
