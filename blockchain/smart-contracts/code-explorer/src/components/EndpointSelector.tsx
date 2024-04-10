import React, { Fragment } from "react";

import { NonEmptyArray } from "../settings/backend";

interface Props {
  readonly currentUrl: string;
  readonly urls: NonEmptyArray<string>;
  readonly urlChanged: (newUrl: string) => void;
}

export function EndpointSelector({ urls, currentUrl, urlChanged }: Props): JSX.Element {
  if (urls.length === 1) {
    return <Fragment>{currentUrl}</Fragment>;
  } else {
    return (
      <Fragment>
        <button
          className="btn btn-secondary btn-sm dropdown-toggle"
          type="button"
          id="dropdownMenuButton"
          data-toggle="dropdown"
          aria-haspopup="true"
          aria-expanded="false"
        >
          {currentUrl}
        </button>
        <div className="dropdown-menu" aria-labelledby="dropdownMenuButton">
          {urls.map((url) => (
            <button
              key={url}
              className={`dropdown-item` + (url === currentUrl ? " active" : "")}
              type="button"
              onClick={() => urlChanged(url)}
            >
              {url}
            </button>
          ))}
        </div>
      </Fragment>
    );
  }
}
