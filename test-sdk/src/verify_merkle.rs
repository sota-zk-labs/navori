use crate::config::{AppConfig, StatInfo};
use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::MoveValue;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;

use crate::utils::{build_and_submit, build_payload};
use log::info;
use tokio::time::Instant;

pub async fn verify_merkle(
    config: &AppConfig,
    verify_merkle_input: VerifyMerkleTransactionInput,
) -> anyhow::Result<StatInfo> {
    let t = Instant::now();
    let (size, payload) = build_payload(
        config.verifier_address,
        "merkle_statement_contract",
        "verify_merkle",
        &vec![
            verify_merkle_input.merkle_view,
            verify_merkle_input.initial_merkle_queue,
            verify_merkle_input.height,
            verify_merkle_input.expected_root,
        ],
    )?;

    let transaction = build_and_submit(
        &config.client,
        payload,
        &config.account,
        config.chain_id,
        Some(1),
        None,
    )
    .await?;
    let transaction_info = transaction.transaction_info()?;
    info!(
        "verify_merkle_statement finished: id={}; hash={}; gas={}",
        transaction_info.version,
        transaction_info.hash.to_string(),
        transaction_info.gas_used
    );

    let stat = StatInfo {
        time: t.elapsed().as_secs_f32(),
        gas_used: transaction_info.gas_used.0,
        size,
    };
    Ok(stat)
}

pub fn sample_verify_merkle_input(index: isize) -> anyhow::Result<VerifyMerkleTransactionInput> {
    let file_path = format!("./data/merkle_verify/merkle_verify_{}.json", index);
    let input_file = File::open(file_path)?;
    let reader = BufReader::new(input_file);
    let merkle_verify_input: MerkleVerifyInput = serde_json::from_reader(reader)?;

    let mut merkle_view_vec = vec![];
    for i in 0..merkle_verify_input.merkle_view.len() {
        merkle_view_vec.push(MoveValue::U256(U256::from_str(
            &merkle_verify_input.merkle_view[i].clone(),
        )?));
    }
    let merkle_view = MoveValue::Vector(merkle_view_vec);

    let mut initial_merkle_queue_vec = vec![];
    for i in 0..merkle_verify_input.initial_merkle_queue.len() {
        initial_merkle_queue_vec.push(MoveValue::U256(U256::from_str(
            &merkle_verify_input.initial_merkle_queue[i],
        )?));
    }
    let initial_merkle_queue = MoveValue::Vector(initial_merkle_queue_vec);

    let height = MoveValue::U8(u8::from_str(&merkle_verify_input.height.clone())?);
    let expected_root =
        MoveValue::U256(U256::from_str(&merkle_verify_input.expected_root.clone())?);
    Ok(VerifyMerkleTransactionInput {
        merkle_view,
        initial_merkle_queue,
        height,
        expected_root,
    })
}

#[derive(Serialize, Debug)]
pub struct VerifyMerkleTransactionInput {
    pub merkle_view: MoveValue,
    pub initial_merkle_queue: MoveValue,
    pub height: MoveValue,
    pub expected_root: MoveValue,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MerkleVerifyInput {
    pub merkle_view: Vec<String>,
    pub initial_merkle_queue: Vec<String>,
    pub height: String,
    pub expected_root: String,
}
