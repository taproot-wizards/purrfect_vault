use std::path::PathBuf;

use anyhow::Result;
use bitcoin::consensus::Encodable;
use bitcoin::{Amount, OutPoint, TxOut};
use bitcoincore_rpc::RawTx;
use clap::Parser;
use lazy_static::lazy_static;
use log::{debug, info, LevelFilter};
use secp256kfun::G;

use crate::settings::Settings;
use crate::vault::basic_recursive_covenant::BasicRecursiveCovenant;
use crate::vault::vault_contract::VaultCovenant;
use crate::wallet::Wallet;

mod settings;
mod vault;
mod wallet;

lazy_static! {
    static ref G_X: [u8; 32] = G.into_point_with_even_y().0.to_xonly_bytes();
}

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "settings.toml")]
    settings_file: PathBuf,
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

    /*
    println!("Let's make a recursive covenant!");
    let contract = BasicRecursiveCovenant::new(&settings)?;
    let funding_utxo = miner_wallet.send(&contract.address()?, Amount::from_sat(100_000_000))?;
    info!("funding txid: {}", funding_utxo.txid);
    info!("funding vout: {}", funding_utxo.vout);
    miner_wallet.mine_blocks(Some(1))?;

    info!("ok, lets spend it");

    let spend_tx = contract.create_spending_transaction(
        &funding_utxo,
        TxOut {
            script_pubkey: contract.address()?.script_pubkey(),
            value: Amount::from_sat(100_000_000),
        },
        Amount::from_sat(99_999_700),
    )?;
    let mut serialized_tx = Vec::new();
    spend_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let sent_txid = miner_wallet.broadcast_tx(&serialized_tx, None)?;
    miner_wallet.mine_blocks(Some(1))?;
    info!("sent txid: {}", sent_txid);
     */

    println!("lets make a vault");
    let mut vault = VaultCovenant::new(&settings)?;
    let fee_paying_address = fee_wallet.get_new_address()?;
    let fee_paying_utxo = miner_wallet.send(&fee_paying_address, Amount::from_sat(100_000))?;
    info!("funding txid: {}", fee_paying_utxo.txid);
    info!("depositing into vault");
    let vault_address = vault.address()?;
    let deposit_tx = miner_wallet.send(&vault_address, Amount::from_sat(100_000_000))?;
    vault.set_amount(Amount::from_sat(100_000_000));
    vault.set_current_outpoint(deposit_tx);
    info!("deposit txid: {}", deposit_tx.txid);
    miner_wallet.mine_blocks(Some(1))?;

    let cancel_tx = vault.create_cancel_tx(&fee_paying_utxo, TxOut {
        script_pubkey: fee_paying_address.script_pubkey(),
        value: Amount::from_sat(100_000),
    })?;

    let signed_tx = fee_wallet.sign_tx(&cancel_tx)?;
    let mut serialized_tx = Vec::new();
    signed_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let txid = fee_wallet.broadcast_tx(&serialized_tx, None)?;
    info!("sent txid: {}", txid);
    miner_wallet.mine_blocks(Some(1))?;
    Ok(())
}
