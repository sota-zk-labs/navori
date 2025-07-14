pub mod config;
pub mod register_continuous_memory_page;
pub mod utils;
pub mod verify_fri;
pub mod verify_merkle;
pub mod verify_proof_and_register;

use crate::config::{AppConfig, Config, GlobalStat, StatInfo};
use crate::register_continuous_memory_page::{
    register_continuous_memory_page, register_continuous_page_batch,
    sample_register_continuous_page, sample_register_continuous_page_batch,
};
use crate::verify_fri::{sample_verify_fri_input, verify_fri};
use crate::verify_merkle::{sample_verify_merkle_input, verify_merkle};
use crate::verify_proof_and_register::{sample_vpar_data, verify_proof_and_register};
use log::info;
use std::fs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig::from(Config::from_path("config.toml")?);

    let mut stat = GlobalStat::default();

    let sequence_number = config
        .client
        .get_account(config.account.address())
        .await?
        .into_inner()
        .sequence_number;
    config.account.set_sequence_number(sequence_number);

    for i in 1..=3 {
        let merkle_input = sample_verify_merkle_input(i)?;
        stat.verify_merkle
            .push(verify_merkle(&config, merkle_input).await?);
    }

    for i in 1..=8 {
        stat.verify_fri
            .push(verify_fri(&config, sample_verify_fri_input(i)?).await?);
        info!("Verify FRI {} success", i);
    }

    for i in 1..=3 {
        stat.rcmp.append(
            &mut register_continuous_page_batch(&config, sample_register_continuous_page_batch(i)?)
                .await?,
        );
    }

    for i in 1..=20 {
        let register_continuous_page_input = sample_register_continuous_page(i)?;
        stat.rcmp
            .push(register_continuous_memory_page(&config, register_continuous_page_input).await?);
        info!("Register continuous page {} success", i);
    }

    stat.vpar = verify_proof_and_register(&config, &sample_vpar_data(1).unwrap()).await?;

    fs::write("data/stat.json", serde_json::to_string_pretty(&stat)?)?;

    let mut verify_merkle_stat = StatInfo {
        time: 0.0,
        gas_used: 0,
        size: 0.0,
    };
    println!("verify merkle");
    for (i, x) in stat.verify_merkle.iter().enumerate() {
        println!("[{}], [{:.2}], [{}], [{:.2}],", i + 1, x.time, x.gas_used, x.size);
        verify_merkle_stat.gas_used += x.gas_used;
        verify_merkle_stat.time += x.time;
        verify_merkle_stat.size += x.size;
    }
    dbg!(&verify_merkle_stat);

    let mut verify_fri_stat = StatInfo {
        time: 0.0,
        gas_used: 0,
        size: 0.0,
    };
    println!("verify fri");
    for (i, x) in stat.verify_fri.iter().enumerate() {
        println!("[{}], [{:.2}], [{}], [{:.2}],", i + 1, x.time, x.gas_used, x.size);
        verify_fri_stat.time += x.time;
        verify_fri_stat.gas_used += x.gas_used;
        verify_fri_stat.size += x.size;
    }
    dbg!(&verify_fri_stat);

    let mut rcmp_stat = StatInfo {
        time: 0.0,
        gas_used: 0,
        size: 0.0,
    };

    println!("rcmp");
    for (i, x) in stat.rcmp.iter().enumerate() {
        println!("[{}], [{:.2}], [{}], [{:.2}],", i + 1, x.time, x.gas_used, x.size);
        rcmp_stat.gas_used += x.gas_used;
        rcmp_stat.time += x.time;
        rcmp_stat.size += x.size;
    }
    dbg!(&rcmp_stat);

    let mut vpar_stat = StatInfo {
        time: 0.0,
        gas_used: 0,
        size: 0.0,
    };

    println!("vpar");
    println!(
        "[{:.2}], [{}], [{:.2}],",
        stat.vpar.prepush_task_metadata.time, stat.vpar.prepush_task_metadata.gas_used, stat.vpar.prepush_task_metadata.size
    );
    vpar_stat.gas_used += stat.vpar.prepush_task_metadata.gas_used;
    vpar_stat.time += stat.vpar.prepush_task_metadata.time;
    vpar_stat.size += stat.vpar.prepush_task_metadata.size;
    println!(
        "[{:.2}], [{}], [{:.2}],",
        stat.vpar.prepush_data.time, stat.vpar.prepush_data.gas_used, stat.vpar.prepush_data.size
    );
    vpar_stat.gas_used += stat.vpar.prepush_data.gas_used;
    vpar_stat.time += stat.vpar.prepush_data.time;
    vpar_stat.size += stat.vpar.prepush_data.size;
    for (i, x) in stat.vpar.vpar.iter().enumerate() {
        println!("[{}], [{:.2}], [{}],", i + 1, x.time, x.gas_used,);
        vpar_stat.gas_used += x.gas_used;
        vpar_stat.time += x.time;
    }
    println!(
        "[{:.2}], [{}],",
        stat.vpar.reset_data.time, stat.vpar.reset_data.gas_used
    );
    vpar_stat.gas_used += stat.vpar.reset_data.gas_used;
    vpar_stat.time += stat.vpar.reset_data.time;
    dbg!(&vpar_stat);

    println!(
        "total time: {}",
        verify_merkle_stat.time + verify_fri_stat.time + rcmp_stat.time + vpar_stat.time
    );
    println!(
        "total gas used: {}",
        verify_merkle_stat.gas_used
            + verify_fri_stat.gas_used
            + rcmp_stat.gas_used
            + vpar_stat.gas_used
    );
    println!(
        "total input size: {}",
        verify_merkle_stat.size
            + verify_fri_stat.size
            + rcmp_stat.size
            + vpar_stat.size
    );
    Ok(())
}
