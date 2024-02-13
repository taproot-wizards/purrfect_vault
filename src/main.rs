use std::path::PathBuf;

use anyhow::Result;
use bitcoin::consensus::Encodable;
use bitcoin::{Amount, OutPoint, TxOut};
use bitcoincore_rpc::RawTx;
use clap::Parser;
use lazy_static::lazy_static;
use log::{debug, info};
use secp256kfun::G;

use crate::settings::Settings;
use crate::vault::basic_recursive_covenant::BasicRecursiveCovenant;
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

    let miner_address = miner_wallet.get_new_address()?;

    /*
    let contract = vault::single_output_constraint_contract::SingleOutputEncumberingContract::new(
        &miner_address,
        Amount::from_sat(99_000_000),
        &settings,
    )?;
    info!("contract address: {}", contract.address()?);

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
    )?;
    let mut serialized_tx = Vec::new();
    spend_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let sent_txid = miner_wallet.broadcast_tx(&serialized_tx, None)?;
    miner_wallet.mine_blocks(Some(1))?;
    info!("sent txid: {}", sent_txid);

    */

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

    info!("Let's spend it again!");
    let funding_utxo = OutPoint {
        txid: sent_txid,
        vout: 0,
    };
    let spend_tx = contract.create_spending_transaction(
        &funding_utxo,
        TxOut {
            script_pubkey: contract.address()?.script_pubkey(),
            value: Amount::from_sat(99_999_700),
        },
        Amount::from_sat(99_999_400),
    )?;
    let mut serialized_tx = Vec::new();
    spend_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let sent_txid = miner_wallet.broadcast_tx(&serialized_tx, None)?;
    miner_wallet.mine_blocks(Some(1))?;
    info!("sent txid: {}", sent_txid);

    Ok(())
}
