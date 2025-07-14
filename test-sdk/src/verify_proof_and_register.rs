use crate::config::{AppConfig, StatInfo, VparStat};
use crate::utils::{build_and_submit, build_payload, get_event_from_transaction};
use anyhow::ensure;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::{serialize_values, MoveValue};
use aptos_sdk::rest_client::aptos_api_types::MoveType;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use serde::Deserialize;
use std::fs;
use std::str::FromStr;
use tokio::time::Instant;

pub async fn verify_proof_and_register(
    config: &AppConfig,
    data: &VerifyProofAndRegisterData,
) -> anyhow::Result<VparStat> {
    let module_name = "gps_statement_verifier";

    // Prepush task metadata transaction
    let t = Instant::now();
    let (size, payload) = build_payload(
        config.verifier_address,
        module_name,
        "prepush_task_metadata",
        &vec![
            MoveValue::Vector(
                data.task_metadata
                    .iter()
                    .map(|v| MoveValue::U256(*v))
                    .collect(),
            )
        ],
    )?;
    let tx = build_and_submit(
        &config.client,
        payload,
        &config.account,
        config.chain_id,
        Some(5),
        None,
    )
    .await?;
    let tx_info = tx.transaction_info()?;
    let prepush_task_metadata_stat = StatInfo {
        time: t.elapsed().as_secs_f32(),
        gas_used: tx_info.gas_used.0,
        size,
    };

    // Prepush data to verify proof and register transaction
    let t = Instant::now();
    let (size, payload) = build_payload(
        config.verifier_address,
        module_name,
        "prepush_data_to_verify_proof_and_register",
        &vec![
            MoveValue::Vector(
                data.proof_params
                    .iter()
                    .map(|v| MoveValue::U256(*v))
                    .collect(),
            ),
            MoveValue::Vector(data.proof.iter().map(|v| MoveValue::U256(*v)).collect()),
            MoveValue::Vector(
                data.cairo_aux_input
                    .iter()
                    .map(|v| MoveValue::U256(*v))
                    .collect(),
            ),
            MoveValue::U256(data.cairo_verifier_id),
        ],
    )?;
    let tx = build_and_submit(
        &config.client,
        payload,
        &config.account,
        config.chain_id,
        Some(5),
        None,
    )
    .await?;
    let tx_info = tx.transaction_info()?;
    let prepush_data_stat = StatInfo {
        time: t.elapsed().as_secs_f32(),
        gas_used: tx_info.gas_used.0,
        size,
    };

    // Verify_proof_and_register
    let cnt_loop = 9;
    let mut vpar_stat = vec![];
    for i in 1..=cnt_loop {
        let t = Instant::now();
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(config.verifier_address, Identifier::new(module_name)?),
            Identifier::new("verify_proof_and_register")?,
            vec![],
            serialize_values(&vec![]),
        ));
        let tx = build_and_submit(
            &config.client,
            payload,
            &config.account,
            config.chain_id,
            Some(5),
            None,
        )
        .await?;
        let tx_info = tx.transaction_info()?;
        vpar_stat.push(StatInfo {
            time: t.elapsed().as_secs_f32(),
            gas_used: tx_info.gas_used.0,
            size: 0.0,
        });
        if i == cnt_loop {
            let event = get_event_from_transaction(
                &tx,
                MoveType::from_str(&format!(
                    "{}::{}::VparFinished",
                    config.verifier_address, module_name
                ))?,
            );
            ensure!(
                event.is_ok(),
                "verify_proof_and_register not finished".to_string()
            );
        }
    }

    let t = Instant::now();
    let payload = TransactionPayload::EntryFunction(EntryFunction::new(
        ModuleId::new(config.verifier_address, Identifier::new(module_name)?),
        Identifier::new("reset_data")?,
        vec![],
        serialize_values(&vec![]),
    ));
    let tx = build_and_submit(
        &config.client,
        payload,
        &config.account,
        config.chain_id,
        Some(5),
        None,
    )
    .await?;
    let tx_info = tx.transaction_info()?;
    let reset_data_stat = StatInfo {
        time: t.elapsed().as_secs_f32(),
        gas_used: tx_info.gas_used.0,
        size: 0.0,
    };

    Ok(VparStat {
        prepush_task_metadata: prepush_task_metadata_stat,
        prepush_data: prepush_data_stat,
        vpar: vpar_stat,
        reset_data: reset_data_stat,
    })
}

pub fn sample_vpar_data(test_num: isize) -> anyhow::Result<VerifyProofAndRegisterData> {
    let data = serde_json::from_str::<VerifyProofAndRegisterDataJson>(
        fs::read_to_string(format!(
            "./data/gps/verify_proof_and_register_{}.json",
            test_num
        ))?
        .as_str(),
    )?;
    Ok(VerifyProofAndRegisterData::from(data))
}

#[derive(Debug)]
pub struct VerifyProofAndRegisterData {
    pub proof_params: Vec<U256>,
    pub proof: Vec<U256>,
    pub task_metadata: Vec<U256>,
    pub cairo_aux_input: Vec<U256>,
    pub cairo_verifier_id: U256,
    pub pre_registered_facts: Option<Vec<U256>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofAndRegisterDataJson {
    pub proof_params: Vec<String>,
    pub proof: Vec<String>,
    pub task_metadata: Vec<String>,
    pub cairo_aux_input: Vec<String>,
    pub cairo_verifier_id: String,
    pub pre_registered_facts: Option<Vec<String>>,
}

impl From<VerifyProofAndRegisterDataJson> for VerifyProofAndRegisterData {
    fn from(value: VerifyProofAndRegisterDataJson) -> Self {
        VerifyProofAndRegisterData {
            proof_params: value
                .proof_params
                .iter()
                .map(|x| U256::from_str(x).unwrap())
                .collect(),
            proof: value
                .proof
                .iter()
                .map(|x| U256::from_str(x).unwrap())
                .collect(),
            task_metadata: value
                .task_metadata
                .iter()
                .map(|x| U256::from_str(x).unwrap())
                .collect(),
            cairo_aux_input: value
                .cairo_aux_input
                .iter()
                .map(|x| U256::from_str(x).unwrap())
                .collect(),
            cairo_verifier_id: U256::from_str(value.cairo_verifier_id.as_str()).unwrap(),
            pre_registered_facts: value
                .pre_registered_facts
                .map(|data| data.iter().map(|x| U256::from_str(x).unwrap()).collect()),
        }
    }
}
