import { MsgInstantiateContract as IMsgInstantiateContract } from "cosmjs-types/cosmwasm/wasm/v1/tx";
import React, { Fragment } from "react";
import ReactJson from "react-json-view";

import { AccountLink } from "../../../components/AccountLink";
import { CodeLink } from "../../../components/CodeLink";
import { parseMsgContract, printableBalance } from "../../../ui-utils";

interface Props {
  readonly msg: IMsgInstantiateContract;
}

export function MsgInstantiateContract({ msg }: Props): JSX.Element {
  return (
    <Fragment>
      <li className="list-group-item">
        Sender: <AccountLink address={msg.sender || "-"} maxLength={null} />
      </li>
      <li className="list-group-item">
        Code ID: <CodeLink codeId={msg.codeId?.toNumber() ?? 0} text={msg.codeId?.toString() ?? "-"} />
      </li>
      <li className="list-group-item">Label: {msg.label}</li>
      <li className="list-group-item">Init funds: {printableBalance(msg.funds)}</li>
      <li className="list-group-item">
        <span title="The contract level message">Init message</span>:
        <ReactJson src={parseMsgContract(msg.msg)} />
      </li>
    </Fragment>
  );
}
