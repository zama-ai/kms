import { fromRfc3339, IndexedTx } from "cosmwasm";
import React from "react";

const checkMark = "✔"; // U+2714 HEAVY CHECK MARK
const xMark = "🗙"; // U+1F5D9 CANCELLATION X

interface Props {
  readonly tx: IndexedTx;
  readonly timestamp: string;
}

export function ExecutionInfo({ tx, timestamp }: Props): JSX.Element {
  const time = timestamp ? fromRfc3339(timestamp) : null;
  const success = tx.code === 0;

  return (
    <ul className="list-group list-group-horizontal mb-3">
      <li className="list-group-item">Height: {tx.height}</li>
      <li className="list-group-item">
        <span title={timestamp}>Time: {time?.toLocaleString()}</span>
      </li>
      <li className="list-group-item">
        <span title={`Execution succeeded: ${success ? "yes" : "no"}`}>
          Success: {success ? checkMark : `${xMark} (error code ${tx.code})`}
        </span>
      </li>
    </ul>
  );
}
