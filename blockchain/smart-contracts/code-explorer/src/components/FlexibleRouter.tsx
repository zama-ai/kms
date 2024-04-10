import React from "react";
import { BrowserRouter, HashRouter } from "react-router-dom";

interface Props {
  readonly type: "browser-router" | "hash-router";
  readonly children: React.ReactNode;
}

export function FlexibleRouter({ type, children }: Props): JSX.Element {
  switch (type) {
    case "browser-router":
      return <BrowserRouter basename={process.env.PUBLIC_URL}>{children}</BrowserRouter>;
    case "hash-router":
      return <HashRouter>{children}</HashRouter>;
  }
}
