The reference source for the verifier part https://etherscan.io/address/0xd51A3D50d4D2f99a345a66971E650EEA064DD8dF#code

## 1. Introduction

## 2. How to run
1. Install the Aptos CLI : [Aptos CLI documentation](https://aptos.dev/en/build/cli).
2. Clone the repository
3. Run the following commands:
Init account and deploy the contract
```bash
aptos init 
```
Fill the new account address in .aptos/config.yaml to the Move.toml file

```bash
aptos move publish
```

## 3. Local Testing and Gas Profiling
   For local testing and to profile gas usage, adjust the scripts/verify_fri.json file with the appropriate contract 
address and data. Execute the following command:
```bash
aptos move run --json-file .\scripts\verify_fri.json --profile-gas   
```
