#!/bin/bash

# Extract deployed addresses from deploy.json
LIB=$(jq -r '.info[0].deployed_at' deploy.json)
CPU=$(jq -r '.info[1].deployed_at' deploy.json)
VERIFIER=$(jq -r '.info[2].deployed_at' deploy.json)

# Compile the Move script with named addresses
aptos move compile-script \
  --package-dir verifier \
  --named-addresses lib_addr="$LIB",cpu_addr="$CPU",verifier_addr="$VERIFIER" \
  --output-file script.mv

# Execute the compiled script on Aptos devnet
aptos move run-script \
  --compiled-script-path script.mv \
  --private-key "$PK" \
  --url https://api.devnet.aptoslabs.com/v1 \
  --assume-yes
