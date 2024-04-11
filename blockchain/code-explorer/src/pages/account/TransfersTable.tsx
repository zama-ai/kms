import { MsgSend } from "cosmjs-types/cosmos/bank/v1beta1/tx";
import React from "react";

import { AccountLink } from "../../components/AccountLink";
import { TransactionLink } from "../../components/TransactionLink";
import { printableBalance } from "../../ui-utils";

export interface Transfer {
  readonly key: string;
  readonly height: number;
  readonly transactionId: string;
  readonly msg: MsgSend;
}

interface Props {
  readonly transfers: readonly Transfer[];
}

export function TransfersTable({ transfers: executions }: Props): JSX.Element {
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">#</th>
          <th scope="col">Height</th>
          <th scope="col">Transaction ID</th>
          <th scope="col">Sender</th>
          <th scope="col">Recipient</th>
          <th scope="col">Amount</th>
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
              <AccountLink address={execution.msg.fromAddress} />
            </td>
            <td>
              <AccountLink address={execution.msg.toAddress} />
            </td>
            <td>{printableBalance(execution.msg.amount)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
