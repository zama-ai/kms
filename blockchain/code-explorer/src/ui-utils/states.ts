import { isNonNullObject } from "cosmwasm";

const runtimeCodes = {
  error: "_\u2588_ErrorState_\u2588_" as const,
  loading: "_\u2588_LoadingState_\u2588_" as const,
};

export interface ErrorState {
  readonly type: typeof runtimeCodes.error;
}

export interface LoadingState {
  readonly type: typeof runtimeCodes.loading;
}

export function isErrorState(state: unknown): state is ErrorState {
  if (!isNonNullObject(state)) return false;
  return (state as ErrorState).type === runtimeCodes.error;
}

export function isLoadingState(state: unknown): state is LoadingState {
  if (!isNonNullObject(state)) return false;
  return (state as LoadingState).type === runtimeCodes.loading;
}

export const errorState: ErrorState = { type: runtimeCodes.error };
export const loadingState: LoadingState = { type: runtimeCodes.loading };
