use std::fs::File;
use std::io::BufReader;

use crate::config::{AppConfig, StatInfo};
use crate::utils::{build_and_submit, build_payload};
use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::MoveValue;
use serde::Deserialize;
use std::str::FromStr;
use tokio::time::Instant;

pub async fn verify_fri(
    config: &AppConfig,
    verify_fri_input: VerifyFriTransactionInput,
) -> anyhow::Result<StatInfo> {
    let t = Instant::now();
    let (size, payload) = build_payload(
        config.verifier_address,
        "fri_statement_contract",
        "verify_fri",
        &vec![
            verify_fri_input.proof,
            verify_fri_input.fri_queue,
            verify_fri_input.evaluation_point,
            verify_fri_input.fri_step_size,
            verify_fri_input.expected_root,
        ],
    )?;
    let transaction = build_and_submit(
        &config.client,
        payload,
        &config.account,
        config.chain_id,
        Some(5),
        None,
    )
    .await?;
    let transaction_info = transaction.transaction_info()?;

    Ok(StatInfo {
        time: t.elapsed().as_secs_f32(),
        gas_used: transaction_info.gas_used.0,
        size,
    })
}

pub fn sample_verify_fri_input(index: isize) -> anyhow::Result<VerifyFriTransactionInput> {
    let file_path = format!("./data/fri_verify/fri_verify_{}.json", index);
    let input_file = File::open(file_path)?;
    let reader = BufReader::new(input_file);
    let fri_verify_input: FriVerifyInput = serde_json::from_reader(reader)?;

    //proof
    let mut proof_vec = vec![];
    for i in 0..fri_verify_input.proof.len() {
        proof_vec.push(MoveValue::U256(U256::from_str(
            &fri_verify_input.proof[i].clone(),
        )?));
    }
    let proof = MoveValue::Vector(proof_vec);

    //queue
    let mut fri_queue_vec = vec![];
    for i in 0..fri_verify_input.fri_queue.len() {
        fri_queue_vec.push(MoveValue::U256(U256::from_str(
            &fri_verify_input.fri_queue[i].clone(),
        )?));
    }
    let fri_queue = MoveValue::Vector(fri_queue_vec);

    let evaluation_point =
        MoveValue::U256(U256::from_str(&fri_verify_input.evaluation_point.clone())?);
    let fri_step_size = MoveValue::U8(u8::from_str(&fri_verify_input.fri_step_size.clone())?);
    let expected_root = MoveValue::U256(U256::from_str(&fri_verify_input.expected_root.clone())?);
    Ok(VerifyFriTransactionInput {
        proof,
        fri_queue,
        evaluation_point,
        fri_step_size,
        expected_root,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FriVerifyInput {
    pub proof: Vec<String>,
    pub fri_queue: Vec<String>,
    pub evaluation_point: String,
    pub fri_step_size: String,
    pub expected_root: String,
}

#[derive(Clone)]
pub struct VerifyFriTransactionInput {
    pub proof: MoveValue,
    pub fri_queue: MoveValue,
    pub evaluation_point: MoveValue,
    pub fri_step_size: MoveValue,
    pub expected_root: MoveValue,
}
