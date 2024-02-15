use std::path::PathBuf;

use anyhow::Result;
use bitcoin::{Amount, OutPoint, TxOut};
use bitcoin::consensus::Encodable;
use bitcoincore_rpc::RawTx;
use clap::Parser;
use log::{debug, info};

use crate::settings::Settings;
use crate::vault::vault_contract::VaultCovenant;
use crate::wallet::Wallet;

mod settings;
mod vault;
mod wallet;



#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "settings.toml")]
    settings_file: PathBuf,

//    #[command(subcommand)]
//    action: Action,
}

#[derive(Parser)]
enum Action {
    Deposit,
    Trigger{destination: String},
    Complete,
    Cancel,
    Status,
}

fn main() -> Result<()> {
    env_logger::init();

    println!("lets do something with cat... or something");

    let args = Cli::parse();
    let settings = Settings::from_toml_file(&args.settings_file)?;

    info!("Getting miner wallet all set up");
    let miner_wallet = Wallet::new("miner", &settings);
    while miner_wallet.get_balance()? < Amount::from_btc(1.0f64)? {
        debug!("Mining some blocks to get some coins");
        miner_wallet.mine_blocks(Some(1))?;
    }

    let fee_wallet = Wallet::new("fee_payment", &settings);
    while fee_wallet.get_balance()? < Amount::from_sat(50_000) {
        let fee_address = fee_wallet.get_new_address()?;
        miner_wallet.send(&fee_address, Amount::from_sat(10_000))?;
        miner_wallet.mine_blocks(Some(1))?;
    }

    println!("lets make a vault");
    let timelock_in_blocks = 20;
    let mut vault = VaultCovenant::new(timelock_in_blocks, &settings)?;

    info!("depositing into vault");
    let vault_address = vault.address()?;
    let deposit_tx = miner_wallet.send(&vault_address, Amount::from_sat(100_000_000))?;
    vault.set_amount(Amount::from_sat(100_000_000));
    vault.set_current_outpoint(deposit_tx);
    info!("deposit txid: {}", deposit_tx.txid);
    miner_wallet.mine_blocks(Some(1))?;

    info!("Triggering a withdrawal");
    let withdrawal_address = fee_wallet.get_new_address()?;
    let fee_paying_address = fee_wallet.get_new_address()?;
    let fee_paying_utxo = miner_wallet.send(&fee_paying_address, Amount::from_sat(10_000))?;
    miner_wallet.mine_blocks(Some(1))?;
    let trigger_tx = vault.create_trigger_tx(&fee_paying_utxo, TxOut {
        script_pubkey: fee_paying_address.script_pubkey(),
        value: Amount::from_sat(10_000),
    }, &withdrawal_address)?;
    let signed_tx = fee_wallet.sign_tx(&trigger_tx)?;
    let mut serialized_tx = Vec::new();
    signed_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let txid = fee_wallet.broadcast_tx(&serialized_tx, None)?;
    info!("sent trigger transaction txid: {}", txid);
    vault.set_current_outpoint(OutPoint {
        txid,
        vout: 0,
    });
    miner_wallet.mine_blocks(Some(1))?;


    info!("Completing the withdrawal");

    let fee_paying_address = fee_wallet.get_new_address()?;
    let fee_paying_utxo = miner_wallet.send(&fee_paying_address, Amount::from_sat(10_000))?;
    info!("need to mine {timelock_in_blocks} blocks for the timelock");
    miner_wallet.mine_blocks(Some(timelock_in_blocks as u64))?;
    let compete_tx = vault.create_complete_tx(&fee_paying_utxo, TxOut {
        script_pubkey: fee_paying_address.script_pubkey(),
        value: Amount::from_sat(10_000),
    },
    &withdrawal_address,
    &trigger_tx)?;
    let signed_tx = fee_wallet.sign_tx(&compete_tx)?;
    let mut serialized_tx = Vec::new();
    signed_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let txid = fee_wallet.broadcast_tx(&serialized_tx, None)?;
    info!("sent txid: {}", txid);
    miner_wallet.mine_blocks(Some(1))?;

/*
    info!("Cancelling the withdrawal");
    let fee_paying_address = fee_wallet.get_new_address()?;
    let fee_paying_utxo = miner_wallet.send(&fee_paying_address, Amount::from_sat(10_000))?;
    let cancel_tx = vault.create_cancel_tx(&fee_paying_utxo, TxOut {
        script_pubkey: fee_paying_address.script_pubkey(),
        value: Amount::from_sat(10_000),
    })?;

    let signed_tx = fee_wallet.sign_tx(&cancel_tx)?;
    let mut serialized_tx = Vec::new();
    signed_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let txid = fee_wallet.broadcast_tx(&serialized_tx, None)?;
    info!("sent txid: {}", txid);
    miner_wallet.mine_blocks(Some(1))?;

 */

    Ok(())
}
