/* eslint-disable @typescript-eslint/no-unused-vars */

import { BackendSettings, getCurrentBackend } from "./backend";

export interface DeploymentSettings {
  readonly routerType: "browser-router" | "hash-router";
}

export interface Settings {
  /** Where do we connect to */
  readonly backend: BackendSettings;
  /** How are we hosted */
  readonly deployment: DeploymentSettings;
}

const developmentServer: DeploymentSettings = {
  routerType: "browser-router",
};

const ghPages: DeploymentSettings = {
  routerType: "hash-router",
};

const firebaseHosting: DeploymentSettings = {
  routerType: "browser-router",
};

export const settings: Settings = {
  backend: getCurrentBackend(),
  deployment: process.env.NODE_ENV === "production" ? ghPages : developmentServer,
};
