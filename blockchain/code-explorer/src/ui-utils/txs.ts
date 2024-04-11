import { Any } from "cosmjs-types/google/protobuf/any";

type IAny = Any;

export const msgSendTypeUrl = "/cosmos.bank.v1beta1.MsgSend";
export const msgStoreCodeTypeUrl = "/cosmwasm.wasm.v1.MsgStoreCode";
export const msgInstantiateContractTypeUrl = "/cosmwasm.wasm.v1.MsgInstantiateContract";
export const msgExecuteContractTypeUrl = "/cosmwasm.wasm.v1.MsgExecuteContract";

export interface AnyMsgSend {
  readonly typeUrl: "/cosmos.bank.v1beta1.MsgSend";
  readonly value: Uint8Array;
}

export interface AnyMsgStoreCode {
  readonly typeUrl: "/cosmwasm.wasm.v1.MsgStoreCode";
  readonly value: Uint8Array;
}

export interface AnyMsgInstantiateContract {
  readonly typeUrl: "/cosmwasm.wasm.v1.MsgInstantiateContract";
  readonly value: Uint8Array;
}

export interface AnyMsgExecuteContract {
  readonly typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract";
  readonly value: Uint8Array;
}

export function isAnyMsgSend(msg: IAny): msg is AnyMsgSend {
  return msg.typeUrl === msgSendTypeUrl && !!msg.value;
}

export function isAnyMsgStoreCode(msg: IAny): msg is AnyMsgStoreCode {
  return msg.typeUrl === msgStoreCodeTypeUrl && !!msg.value;
}

export function isAnyMsgInstantiateContract(msg: IAny): msg is AnyMsgInstantiateContract {
  return msg.typeUrl === msgInstantiateContractTypeUrl && !!msg.value;
}

export function isAnyMsgExecuteContract(msg: IAny): msg is AnyMsgExecuteContract {
  return msg.typeUrl === msgExecuteContractTypeUrl && !!msg.value;
}
