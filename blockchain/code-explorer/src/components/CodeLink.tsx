import React from "react";
import { Link } from "react-router-dom";

interface Props {
  readonly codeId: number;
  readonly text?: string;
}

export function CodeLink({ codeId, text }: Props): JSX.Element {
  return <Link to={`/codes/${codeId}`}>{text || `Code #${codeId}`}</Link>;
}
