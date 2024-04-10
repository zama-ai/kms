import { MsgExecuteContract as IMsgExecuteContract } from "cosmjs-types/cosmwasm/wasm/v1/tx";
import React, { Fragment } from "react";
import ReactJson from "react-json-view";

import { AccountLink } from "../../../components/AccountLink";
import { ContractLink } from "../../../components/ContractLink";
import { parseMsgContract, printableBalance } from "../../../ui-utils";

interface Props {
  readonly msg: IMsgExecuteContract;
}

export function MsgExecuteContract({ msg }: Props): JSX.Element {
  return (
    <Fragment>
      <li className="list-group-item">
        Contract: <ContractLink address={msg.contract ?? "-"} maxLength={null} />
      </li>
      <li className="list-group-item">
        Sender: <AccountLink address={msg.sender ?? "-"} maxLength={null} />
      </li>
      <li className="list-group-item">Sent funds: {printableBalance(msg.funds)}</li>
      <li className="list-group-item">
        <span title="The contract level message">Handle message</span>:
        <ReactJson src={parseMsgContract(msg.msg)} />
      </li>
    </Fragment>
  );
}
