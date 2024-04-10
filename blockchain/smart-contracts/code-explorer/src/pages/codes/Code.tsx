import "./Code.css";

import React from "react";
import { Link } from "react-router-dom";

import { ClientContext } from "../../contexts/ClientContext";
import { ellideMiddle } from "../../ui-utils";
import {
  ErrorState,
  errorState,
  isErrorState,
  isLoadingState,
  LoadingState,
  loadingState,
} from "../../ui-utils/states";

export interface CodeData {
  readonly codeId: number;
  readonly checksum: string;
  readonly creator: string;
}

interface Props {
  readonly data: CodeData;
  readonly index: number;
}

interface InstantiationInfo {
  readonly instantiations: number;
}

export function Code({ data, index }: Props): JSX.Element {
  const { client } = React.useContext(ClientContext);
  const [instantiationInfo, setInstantiationInfo] = React.useState<
    InstantiationInfo | ErrorState | LoadingState
  >(loadingState);

  React.useEffect(() => {
    client
      ?.getContracts(data.codeId)
      .then((contracts) => {
        setInstantiationInfo({
          instantiations: contracts.length,
        });
      })
      .catch(() => setInstantiationInfo(errorState));
    // Don't make clientContext.client a dependency. Whenever it changes, this component is recreated entirely
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data.codeId]);

  return (
    <div className={"flex-element-two-two mb-3" + (index % 2 ? " pl-lg-2" : " pr-lg-2")}>
      <Link to={`/codes/${data.codeId}`} className="code-content">
        <div className="id">#{data.codeId}</div>
        <div className="details">
          Creator: {ellideMiddle(data.creator, 30)}
          <br />
          Checksum: {data.checksum.slice(0, 10)}
          <br />
          Instances:{" "}
          {isLoadingState(instantiationInfo)
            ? "Loading …"
            : isErrorState(instantiationInfo)
            ? "Error"
            : instantiationInfo.instantiations}
        </div>
      </Link>
    </div>
  );
}
