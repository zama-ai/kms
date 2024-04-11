export interface Tag {
  readonly key: string;
  readonly value: string;
}

export function makeTags(oneLiner: string): Tag[] {
  return oneLiner.split("&").map((pair) => {
    if (pair.indexOf("=") === -1) throw new Error("Parsing error: Equal sign missing");
    const parts = pair.split("=");
    if (parts.length > 2) {
      throw new Error(
        "Parsing error: Multiple equal signs found. If you need escaping support, please create a PR.",
      );
    }
    const [key, value] = parts;
    if (!key) throw new Error("Parsing error: Key must not be empty");
    return { key, value };
  });
}
