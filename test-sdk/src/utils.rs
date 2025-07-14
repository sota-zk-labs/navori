use std::future::Future;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use anyhow::anyhow;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::{serialize_values, MoveValue};
use aptos_sdk::rest_client::aptos_api_types::{Event, MoveType};
use aptos_sdk::rest_client::error::RestError;
use aptos_sdk::rest_client::{Client, Transaction};
use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::account_address::AccountAddress;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::{EntryFunction, SignedTransaction, TransactionPayload};
use aptos_sdk::types::LocalAccount;
use tokio::time::sleep;

pub fn build_payload(verifier_address: AccountAddress, module: &str, func: &str, params: &Vec<MoveValue>) -> anyhow::Result<(f64, TransactionPayload)> {
    let payload_bytes = serialize_values(params);
    let mut size = 0u64;
    for x in &payload_bytes {
        size += x.len() as u64;
    }
    let size = (size as f64) / 1024.0;
    Ok((size, TransactionPayload::EntryFunction(EntryFunction::new(
        ModuleId::new(
            verifier_address,
            Identifier::new(module)?,
        ),
        Identifier::new(func)?,
        vec![],
        payload_bytes,
    ))))
}

fn build_transaction(
    payload: TransactionPayload,
    sender: &LocalAccount,
    chain_id: ChainId,
) -> SignedTransaction {
    let i = sender.increment_sequence_number();
    let tx = TransactionBuilder::new(
        payload,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        chain_id,
    )
    .sender(sender.address())
    .sequence_number(i)
    .max_gas_amount(200000)
    .gas_unit_price(100)
    .build();
    sender.sign_transaction(tx)
}

pub async fn build_and_submit(
    client: &Client,
    payload: TransactionPayload,
    sender: &LocalAccount,
    chain_id: ChainId,
    try_cnt: Option<u8>,
    sleep_duration: Option<Duration>,
) -> Result<Transaction, RestError> {
    retry_until_success(
        move || {
            let payload = payload.clone();
            let client = client.clone();
            async move {
                let tx = build_transaction(payload, sender, chain_id);
                Ok(client.submit_and_wait(&tx).await?.into_inner())
            }
        },
        try_cnt.unwrap_or(1),
        sleep_duration.unwrap_or(Duration::from_millis(2000)),
    ).await
}

pub fn get_event_from_transaction(
    transaction: &Transaction,
    event_type: MoveType,
) -> anyhow::Result<&Event> {
    let event = match transaction {
        Transaction::UserTransaction(txn) => txn.events.iter().find(|s| s.typ == event_type),
        Transaction::BlockMetadataTransaction(_) => None,
        Transaction::PendingTransaction(_) => None,
        Transaction::GenesisTransaction(_) => None,
        Transaction::StateCheckpointTransaction(_) => None,
        Transaction::BlockEpilogueTransaction(_) => None,
        Transaction::ValidatorTransaction(_) => None,
    };
    event.ok_or(anyhow!("Failed to get event"))
}

pub async fn retry_until_success<F, Fut, T, E>(
    mut f: F,
    retries: u8,
    delay: Duration,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut attempts = 0;

    loop {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                attempts += 1;
                if attempts >= retries {
                    return Err(e);
                }
                sleep(delay).await;
            }
        }
    }
}

#[inline]
pub fn str_to_u256(s: &str) -> anyhow::Result<U256> {
    U256::from_str(s).map_err(|e| e.into())
}

#[inline]
pub fn str_to_u64(s: &str) -> anyhow::Result<u64> {
    u64::from_str(s).map_err(|e| e.into())
}
