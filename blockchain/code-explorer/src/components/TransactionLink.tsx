import React from "react";
import { Link } from "react-router-dom";

import { ellideMiddle } from "../ui-utils";

interface Props {
  readonly transactionId: string;
  readonly maxLength?: number | null;
}

export function TransactionLink({ transactionId, maxLength = 20 }: Props): JSX.Element {
  return (
    <Link to={`/transactions/${transactionId}`} title={transactionId}>
      {ellideMiddle(transactionId, maxLength || 99999)}
    </Link>
  );
}
