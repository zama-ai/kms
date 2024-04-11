import React, { Fragment } from "react";

import { ClientContext } from "../contexts/ClientContext";
import { settings } from "../settings";
import { ErrorState, errorState, LoadingState, loadingState } from "../ui-utils/states";
import { EndpointSelector } from "./EndpointSelector";
import { NodeInfoModal } from "./NodeInfoModal";

const hrStyle: React.CSSProperties = {
  borderColor: "rgba(255, 255, 255, 0.8)",
};
const whiteText = { color: "#f0f0f0" };

function Separator(): JSX.Element {
  return <Fragment> | </Fragment>;
}

/** Place me as a row in a container */
export function FooterRow(): JSX.Element {
  const { client, nodeUrl, resetClient } = React.useContext(ClientContext);

  const [chainId, setChainId] = React.useState<string | ErrorState | LoadingState>(loadingState);
  const [height, setHeight] = React.useState<number | ErrorState | LoadingState>(loadingState);

  const updateHeight = React.useCallback(() => {
    client
      ?.getHeight()
      .then(setHeight)
      .catch(() => setHeight(errorState));
  }, [client]);

  React.useEffect(() => {
    client
      ?.getChainId()
      .then(setChainId)
      .catch(() => setChainId(errorState));
    updateHeight();
  }, [client, updateHeight]);

  return (
    <div className="row">
      <div className="col">
        <hr style={hrStyle} />
        <NodeInfoModal htmlId="nodeInfoModal" chainId={chainId} height={height} />
        <div style={whiteText} className="dropdown text-center font-weight-light mb-3">
          Endpoint{" "}
          <EndpointSelector
            currentUrl={nodeUrl}
            urls={settings.backend.nodeUrls}
            urlChanged={(newUrl) => resetClient(newUrl)}
          />{" "}
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            data-toggle="modal"
            data-target="#nodeInfoModal"
            onClick={updateHeight}
          >
            Node info
          </button>
          <Separator />
          <a href="https://github.com/CosmWasm/code-explorer" style={whiteText}>
            Fork me on GitHub
          </a>
        </div>
      </div>
    </div>
  );
}
