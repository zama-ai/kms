import React from "react";

import { ClientContext } from "../contexts/ClientContext";

export function UserAddress(): JSX.Element {
  const { userAddress } = React.useContext(ClientContext);

  return userAddress ? (
    <div className="mr-3 p-2 rounded bg-white">
      <span>My address: </span>
      <span>{userAddress}</span>
    </div>
  ) : (
    <></>
  );
}
