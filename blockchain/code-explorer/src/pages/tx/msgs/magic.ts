import { fromHex } from "cosmwasm";

function arrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  const difference = a.some((byte, index) => b[index] !== byte);
  return !difference;
}

function arrayStartsWith(a: Uint8Array, prefix: Uint8Array): boolean {
  return arrayEqual(a.slice(0, prefix.length), prefix);
}

const magic = {
  gzip: fromHex("1F8B"),
  wasm: fromHex("0061736d"),
};

export type SupportedTypes = "gzip" | "wasm";

export function getFileType(data: Uint8Array): SupportedTypes | undefined {
  if (arrayStartsWith(data, magic.gzip)) return "gzip";
  if (arrayStartsWith(data, magic.wasm)) return "wasm";
  return undefined;
}
