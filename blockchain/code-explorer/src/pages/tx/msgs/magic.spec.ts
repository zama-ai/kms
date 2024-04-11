import { fromHex } from "cosmwasm";

import { getFileType } from "./magic";

describe("getFileType", () => {
  it("works", () => {
    expect(getFileType(fromHex(""))).toBeUndefined();
    expect(getFileType(fromHex("1F"))).toBeUndefined();
    expect(getFileType(fromHex("1F8B"))).toEqual("gzip");
    expect(getFileType(fromHex("1F8Baa"))).toEqual("gzip");
    expect(getFileType(fromHex("1F8Baabb"))).toEqual("gzip");

    expect(getFileType(fromHex("00"))).toBeUndefined();
    expect(getFileType(fromHex("0061"))).toBeUndefined();
    expect(getFileType(fromHex("006173"))).toBeUndefined();
    expect(getFileType(fromHex("0061736d"))).toEqual("wasm");
    expect(getFileType(fromHex("0061736daa"))).toEqual("wasm");
    expect(getFileType(fromHex("0061736daabb"))).toEqual("wasm");
  });
});
