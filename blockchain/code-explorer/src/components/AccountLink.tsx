import React from "react";
import { Link } from "react-router-dom";

import { ellideMiddle } from "../ui-utils";

interface Props {
  readonly address: string;
  readonly maxLength?: number | null;
}

export function AccountLink({ address, maxLength = 20 }: Props): JSX.Element {
  return (
    <Link to={`/accounts/${address}`} title={address}>
      {ellideMiddle(address, maxLength || 99999)}
    </Link>
  );
}
