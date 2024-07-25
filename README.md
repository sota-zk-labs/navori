The reference source for the verifier part https://etherscan.io/address/0xd51A3D50d4D2f99a345a66971E650EEA064DD8dF#code

## 1. Introduction

## 2. How to run

1. Install the Aptos CLI : [Aptos CLI documentation](https://aptos.dev/en/build/cli).
2. Clone the repository
3. Init account and deploy the module

```bash
aptos init 
```

#### With package concept:

Fill the new account address in .aptos/config.yaml to the Move.toml file

```bash
aptos move publish --included-artifacts none
```

#### With object

**Compile code**

Make sure <your_account_name> is left as a placeholder _

```toml
[addresses]
verifier_addr = "_"
```

Compile your move code running the below command.

Replace <your_account_name> with your account name and <your_address> with your account address in .aptos/config.yaml

```bash
aptos move compile --named-addresses <your_account_name>=<your_address>
```

**Deploy code to an object**

```bash
aptos move create-object-and-publish-package --address-name <your_account_name> --named-addresses <your_account_name>=<your_address>
```

**Upgrade code in an existing package**

```bash
aptos move upgrade-object-package --object-address <object_address> --named-addresses <your_account_name>=<object_address>
```

## 3. Local Testing and Gas Profiling

For local testing and to profile gas usage, adjust the scripts/verify_fri.json file with the appropriate contract
address and data. Execute the following command:

```bash
aptos move run --json-file .\scripts\verify_fri.json --profile-gas   
```


