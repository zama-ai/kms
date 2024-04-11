import { ellideMiddle, ellideRight } from ".";

describe("ellideMiddle", () => {
  it("works", () => {
    expect(ellideMiddle("abcde", 1)).toEqual("…");
    expect(ellideMiddle("abcde", 2)).toEqual("a…");
    expect(ellideMiddle("abcde", 3)).toEqual("a…e");
    expect(ellideMiddle("abcde", 4)).toEqual("ab…e");
    expect(ellideMiddle("abcde", 5)).toEqual("abcde");
    expect(ellideMiddle("abcde", 6)).toEqual("abcde");
  });
});

describe("ellideRight", () => {
  it("works", () => {
    expect(ellideRight("abcde", 1)).toEqual("…");
    expect(ellideRight("abcde", 2)).toEqual("a…");
    expect(ellideRight("abcde", 3)).toEqual("ab…");
    expect(ellideRight("abcde", 4)).toEqual("abc…");
    expect(ellideRight("abcde", 5)).toEqual("abcde");
    expect(ellideRight("abcde", 6)).toEqual("abcde");
  });
});
