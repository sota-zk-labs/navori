use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::MoveValue;
use aptos_sdk::rest_client::aptos_api_types::MoveType;
use log::info;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;
use std::time::Duration;

use crate::config::{AppConfig, StatInfo};

use crate::utils::{build_and_submit, build_payload, get_event_from_transaction};
use serde::Deserialize;
use tokio::time::Instant;

pub async fn register_continuous_memory_page(
    config: &AppConfig,
    data: ContinuousMemoryPage,
) -> anyhow::Result<StatInfo> {
    let t = Instant::now();
    let mut values = vec![];
    for e in &data.values {
        values.push(MoveValue::U256(U256::from_str(e)?));
    }

    // {
    //     let txs = Arc::new(values.chunks(500).map(|chunk| {
    //         build_transaction(TransactionPayload::EntryFunction(EntryFunction::new(
    //             ModuleId::new(
    //                 config.verifier_address,
    //                 Identifier::new("memory_page_fact_registry").unwrap(),
    //             ),
    //             Identifier::new("prepush_memorypage_values").unwrap(),
    //             vec![],
    //             serialize_values(&vec![MoveValue::Vector(chunk.to_vec())]),
    //         )), &config.account, config.chain_id)
    //     }).collect::<Vec<_>>());
    //     let txs = retry_until_success(move || {
    //         let txs = txs.clone();
    //         let client = config.client.clone();
    //         async move {
    //             client.submit_batch(&txs).await
    //         }
    //     }, 3, Duration::from_millis(2000)).await?.into_inner();
    //     txs.
    //     for tx in txs {
    //         stat.gas_used += t
    //     }
    // }

    let (size, payload) = build_payload(
        config.verifier_address,
        "memory_page_fact_registry",
        "register_continuous_memorypage",
        &vec![
            MoveValue::U256(U256::from_str(&data.start_addr)?),
            MoveValue::Vector(values),
            MoveValue::U256(U256::from_str(&data.z)?),
            MoveValue::U256(U256::from_str(&data.alpha)?),
        ],
    )?;
    let mut stat = StatInfo {
        time: 0.0,
        gas_used: 0,
        size,
    };
    loop {
        let transaction = build_and_submit(
            &config.client,
            payload.clone(),
            &config.account,
            config.chain_id,
            Some(10),
            Some(Duration::from_millis(3000)),
        )
        .await?;

        let transaction_info = transaction.transaction_info()?;
        stat.gas_used += transaction_info.gas_used.0;
        info!(
            "register_continuous_memory_page finished: id={}; hash={}; gas={}",
            transaction_info.version,
            transaction_info.hash.to_string(),
            transaction_info.gas_used
        );
        if get_event_from_transaction(
            &transaction,
            MoveType::from_str(&format!(
                "{}::memory_page_fact_registry::LogMemoryPageFactContinuous",
                config.verifier_address
            ))?,
        )
        .is_ok()
        {
            break;
        }
    }
    stat.time = t.elapsed().as_secs_f32();
    Ok(stat)
}

pub async fn register_continuous_page_batch(
    config: &AppConfig,
    data: MemoryPageEntries,
) -> anyhow::Result<Vec<StatInfo>> {
    let mut stats = vec![];
    for memory in data.memory_page_entries {
        stats.push(register_continuous_memory_page(config, memory).await?);
    }
    Ok(stats)
}

pub fn sample_register_continuous_page_batch(index: u64) -> anyhow::Result<MemoryPageEntries> {
    let file_path = format!(
        "./data/memory_page_fact_registry/register_continuous_page_batch_{}.json",
        index
    );
    let input_file = File::open(file_path)?;
    let reader = BufReader::new(input_file);
    let memory_page_entries: MemoryPageEntries = serde_json::from_reader(reader)?;
    Ok(memory_page_entries)
}

pub fn sample_register_continuous_page(index: u64) -> anyhow::Result<ContinuousMemoryPage> {
    let file_path = format!(
        "./data/memory_page_fact_registry/register_memory_page_{}.json",
        index
    );
    let input_file = File::open(file_path)?;
    let reader = BufReader::new(input_file);
    let continuous_memory_page: ContinuousMemoryPage = serde_json::from_reader(reader)?;
    Ok(continuous_memory_page)
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContinuousMemoryPage {
    pub start_addr: String,
    pub values: Vec<String>,
    pub z: String,
    pub alpha: String,
    pub prime: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MemoryPageEntries {
    pub memory_page_entries: Vec<ContinuousMemoryPage>,
}
