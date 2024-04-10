🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨<br>
This repository was unmaintained for a long time and most likely contains security issues in the dependency tree.
The code remains here for reference but it is highly recommended to not use it anymore.<br>
<br>
Many new tools have been developed by other teams in the meantime which go beyond what we developed here. Let's use and promote those tools to broaden the CosmWasm ecosystem. Giving up cosebases is part of innovation. Cheers!
<br>
🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦🪦

# CosmWasm Code Explorer

## Use hosted

The explorer is deployed at https://cosmwasm.github.io/code-explorer and is configured
for Cliffnet.

## Use local

You need to install the code-explorer dependencies before choosing which network you want to connect to:

```sh
yarn install
```

### Run against testnets

You don't need to run a local network in order to connect to the testnets, you just need the right start script for each network.

#### Musslenet

Coming soon!

### Run against local networks

Clone the CosmJS repo in order to run a local Launchpad or Stargate network:

```sh
git clone --depth 1 --branch v0.24.0-alpha.11 https://github.com/cosmos/cosmjs.git
```

Also make sure to comply with the [prerequisites](https://github.com/cosmos/cosmjs/blob/v0.24.0-alpha.11/HACKING.md#prerequisite).

#### Launchpad

In order to run a local Launchpad network follow [these instructions](https://github.com/cosmos/cosmjs/tree/v0.24.0-alpha.11/scripts/launchpad).

The start script that makes the code-explorer connect to a local Launchpad network is:

```sh
yarn start-launchpad
```

#### Stargate

In order to run a local Stargate network, follow [these instructions](https://github.com/cosmos/cosmjs/tree/v0.24.0-alpha.11/scripts/wasmd).

The start script that makes the code-explorer connect to a local Stargate network is:

```sh
yarn start-stargate
```

## Build instructions

You can build a code explorer and deploy it as static HTML/JS files.

Requirements: yarn, Node.js 10+

```
yarn install
PUBLIC_URL=https://cosmwasm.github.io/code-explorer/ REACT_APP_BACKEND=cliffnet yarn build
```

## Credits

Background image from https://unsplash.com/photos/QqCLSA3EQUg
