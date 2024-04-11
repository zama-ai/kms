import { makeTags } from "./sdkhelpers";

describe("makeTags", () => {
  it("works for happy path", () => {
    expect(makeTags("a=b")).toEqual([{ key: "a", value: "b" }]);
    expect(makeTags("a=b&c=d")).toEqual([
      { key: "a", value: "b" },
      { key: "c", value: "d" },
    ]);
  });

  it("works for empty value", () => {
    expect(makeTags("a=")).toEqual([{ key: "a", value: "" }]);
  });

  it("throws for missing assignment", () => {
    expect(() => makeTags("foo")).toThrowError(/equal sign missing/i);
  });

  it("throws for multiple assignments", () => {
    expect(() => makeTags("a=b=c")).toThrowError(/multiple equal signs found/i);
  });

  it("throws for empty key", () => {
    expect(() => makeTags("=a")).toThrowError(/key must not be empty/i);
  });
});
