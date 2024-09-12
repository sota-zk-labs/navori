## 1. Introduction

## 2. How to Run

1. Install the Aptos CLI: [Aptos CLI documentation](https://aptos.dev/en/build/cli).
2. Clone the repository.
3. Initialize your account and deploy the module.

```bash
aptos init 
```

#### Using the Package Concept:

Fill in the new account address from `.aptos/config.yaml` into the `Move.toml` file.

```bash
aptos move publish --included-artifacts none
```

#### Using an Object

**Compile the Code**

Ensure that `<your_account_name>` is left as a placeholder in the `Move.toml` file:

```toml
[addresses]
verifier_addr = "_"
```

Compile your Move code by running the following command. Replace `<your_account_name>` with your account name
and `<your_address>` with your account address from `.aptos/config.yaml`.

```bash
aptos move compile --named-addresses <your_account_name>=<your_address>
```

**Deploy Code to an Object**

```bash
aptos move create-object-and-publish-package --address-name <your_account_name> --named-addresses <your_account_name>=<your_address>
```

**Upgrade Code in an Existing Package**

```bash
aptos move upgrade-object-package --object-address <object_address> --named-addresses <your_account_name>=<object_address>
```

The reference source for the verifier part https://etherscan.io/address/0xd51A3D50d4D2f99a345a66971E650EEA064DD8dF#code
CPU layout 7 contracts: https://vscode.blockscan.com/ethereum/0x28e3ad4201ba416b23d9950503db28a9232be32a