import React from "react";

import { ClientContext } from "../contexts/ClientContext";
import { ErrorState, isErrorState, isLoadingState, LoadingState } from "../ui-utils/states";

interface Props {
  readonly htmlId: string;
  readonly chainId: string | ErrorState | LoadingState;
  readonly height: number | ErrorState | LoadingState;
}

export function NodeInfoModal({ htmlId, chainId, height }: Props): JSX.Element {
  const clientContext = React.useContext(ClientContext);

  return (
    <div
      className="modal fade"
      id={htmlId}
      tabIndex={-1}
      role="dialog"
      aria-labelledby="exampleModalLabel"
      aria-hidden="true"
    >
      <div className="modal-dialog" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="exampleModalLabel">
              Node info
            </h5>
            <button type="button" className="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="modal-body">
            Endpoint: {clientContext.nodeUrl}
            <br />
            Chain ID: {isLoadingState(chainId) ? "Loading …" : isErrorState(chainId) ? "Error" : chainId}
            <br />
            Height: {isLoadingState(height) ? "Loading …" : isErrorState(height) ? "Error" : height}
          </div>
        </div>
      </div>
    </div>
  );
}
