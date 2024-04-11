import "./CodePage.css";

import { CodeDetails } from "cosmwasm";
import React from "react";
import { Link, useParams } from "react-router-dom";

import { FooterRow } from "../../components/FooterRow";
import { Header } from "../../components/Header";
import { ClientContext } from "../../contexts/ClientContext";
import { makeTags } from "../../ui-utils/sdkhelpers";
import {
  ErrorState,
  errorState,
  isErrorState,
  isLoadingState,
  LoadingState,
  loadingState,
} from "../../ui-utils/states";
import { CodeInfo } from "./CodeInfo";
import InstanceRow from "./InstanceRow";
import { InstancesEmptyState } from "./InstancesEmptyState";

export function CodePage(): JSX.Element {
  const { client } = React.useContext(ClientContext);
  const { codeId: codeIdParam } = useParams<{ readonly codeId: string }>();
  const codeId = parseInt(codeIdParam || "0", 10);

  const [details, setDetails] = React.useState<CodeDetails | ErrorState | LoadingState>(loadingState);
  const [contracts, setContracts] = React.useState<readonly string[] | ErrorState | LoadingState>(
    loadingState,
  );
  const [uploadTxHash, setUploadTxHash] = React.useState<string | undefined | ErrorState | LoadingState>(
    loadingState,
  );

  React.useEffect(() => {
    client
      ?.getContracts(codeId)
      .then(setContracts)
      .catch(() => setContracts(errorState));
    client
      ?.getCodeDetails(codeId)
      .then(setDetails)
      .catch(() => setDetails(errorState));
    client
      ?.searchTx({
        tags: makeTags(`message.module=wasm&store_code.code_id=${codeId}`),
      })
      .then((results) => {
        const first = results.find(() => true);
        setUploadTxHash(first?.hash);
      });
  }, [client, codeId]);

  const pageTitle = <span>Code #{codeId}</span>;

  return (
    <div className="page">
      <Header />
      <div className="container mt-3">
        <div className="row white-row white-row-first">
          <div className="col">
            <nav aria-label="breadcrumb">
              <ol className="breadcrumb">
                <li className="breadcrumb-item">
                  <Link to="/codes">Codes</Link>
                </li>
                <li className="breadcrumb-item active" aria-current="page">
                  {pageTitle}
                </li>
              </ol>
            </nav>
          </div>
        </div>
        <div className="row white-row">
          <div className="col">
            <h1>{pageTitle}</h1>
            <ul className="list-group list-group-horizontal mb-3">
              <li className="list-group-item">Type: Wasm</li>
              <li className="list-group-item">
                Size:{" "}
                {isLoadingState(details)
                  ? "Loading …"
                  : isErrorState(details)
                  ? "Error"
                  : Math.round(details.data.length / 1024) + " KiB"}
              </li>
            </ul>
          </div>
          <div className="col">
            {isLoadingState(details) ? (
              <span>Loading …</span>
            ) : isErrorState(details) ? (
              <span>Error</span>
            ) : (
              <CodeInfo code={details} uploadTxHash={uploadTxHash} />
            )}
          </div>
        </div>
        <div className="row white-row white-row-last">
          <div className="col">
            <h2>Instances</h2>
            {isLoadingState(contracts) ? (
              <p>Loading …</p>
            ) : isErrorState(contracts) ? (
              <p>Error loading instances</p>
            ) : contracts.length === 0 ? (
              <InstancesEmptyState />
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">#</th>
                    <th scope="col">Label</th>
                    <th scope="col">Contract</th>
                    <th scope="col">Creator</th>
                    <th scope="col">Admin</th>
                    <th scope="col">Executions</th>
                  </tr>
                </thead>
                <tbody>
                  {contracts.map((address, index) => (
                    <InstanceRow position={index + 1} address={address} key={address} />
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
        <FooterRow />
      </div>
    </div>
  );
}
