import { Coin } from "cosmjs-types/cosmos/base/v1beta1/coin";
import { Decimal, fromUtf8 } from "cosmwasm";

export function ellideMiddle(str: string, maxOutLen: number): string {
  if (str.length <= maxOutLen) {
    return str;
  }
  const ellide = "…";
  const frontLen = Math.ceil((maxOutLen - ellide.length) / 2);
  const tailLen = Math.floor((maxOutLen - ellide.length) / 2);
  return str.slice(0, frontLen) + ellide + str.slice(str.length - tailLen, str.length);
}

export function ellideRight(str: string, maxOutLen: number): string {
  if (str.length <= maxOutLen) {
    return str;
  }
  const ellide = "…";
  const frontLen = maxOutLen - ellide.length;
  return str.slice(0, frontLen) + ellide;
}

// NARROW NO-BREAK SPACE (U+202F)
const thinSpace = "\u202F";

function printableCoin(coin: Coin): string {
  if (coin.denom?.startsWith("u")) {
    const ticker = coin.denom.slice(1).toUpperCase();
    return Decimal.fromAtomics(coin.amount ?? "0", 6).toString() + thinSpace + ticker;
  } else {
    return coin.amount + thinSpace + coin.denom;
  }
}

export function printableBalance(balance: readonly Coin[]): string {
  if (balance.length === 0) return "–";
  return balance.map(printableCoin).join(", ");
}

export function parseMsgContract(msg: Uint8Array): any {
  const json = fromUtf8(msg);

  return JSON.parse(json);
}
