use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use bitcoin::consensus::Encodable;
use bitcoin::{Address, Amount, OutPoint, TxOut};
use bitcoincore_rpc::{RawTx, RpcApi};
use clap::Parser;
use log::{debug, error, info};

use crate::settings::Settings;
use crate::vault::contract::VaultState::{Completed, Inactive, Triggered};
use crate::vault::contract::{VaultCovenant, VaultState};
use crate::wallet::Wallet;

mod settings;
mod vault;
mod wallet;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "settings.toml")]
    settings_file: PathBuf,

    #[command(subcommand)]
    action: Action,
}

#[derive(Parser)]
enum Action {
    Deposit,
    Trigger { destination: String },
    Steal { destination: String },
    Complete,
    Cancel,
    Status,
}

fn main() -> Result<()> {
    env_logger::init();

    println!("A kinda vault-y thing with CATs!");

    let args = Cli::parse();

    let settings = match Settings::from_toml_file(&args.settings_file) {
        Ok(settings) => settings,
        Err(e) => {
            error!("Error reading settings file: {}", e);
            info!(
                "Creating a new settings file at {}",
                args.settings_file.display()
            );
            let settings = Settings::default();
            settings.to_toml_file(&args.settings_file)?;
            settings
        }
    };

    match args.action {
        Action::Deposit => deposit(&settings)?,
        Action::Trigger { destination } => trigger(&destination, false, &settings)?,
        Action::Steal { destination } => trigger(&destination, true, &settings)?,
        Action::Complete => complete(&settings)?,
        Action::Cancel => cancel(&settings)?,
        Action::Status => status(&settings)?,
    }
    Ok(())
}

fn status(settings: &Settings) -> Result<()> {
    let vault = VaultCovenant::from_file(&settings.vault_file).map_err(|e| {
        error!("No vault found: {}.", e);
        error!("You can create a vault with the deposit command.");
        e
    })?;
    let client = Wallet::create_rpc_client(settings, None);
    let latest_vault_transaction =
        client.get_raw_transaction(&vault.get_current_outpoint()?.txid, None)?;
    let latest_state_onchain: VaultState = (latest_vault_transaction, vault.address()?).into();
    if latest_state_onchain == vault.get_state() {
        info!(
            "Vault state is consistent with the latest on-chain transaction: {:?}",
            latest_state_onchain
        );
    } else if latest_state_onchain == Triggered {
        error!("Onchain state is Triggered, but the internal vault state is not. YOU MIGHT BE GETTING ROBBED! Run the `cancel` command to cancel the withdrawal and SAVE YOUR MONEY!");
    } else if vault.get_state() == Completed {
        info!("Vault state is Completed. This is expected after a successful withdrawal.");
    } else {
        error!(
            "Vault state is inconsistent with the latest on-chain transaction: {:?}",
            latest_state_onchain
        );
    }
    Ok(())
}

fn cancel(settings: &Settings) -> Result<()> {
    info!("Cancelling the withdrawal");
    let miner_wallet = Wallet::new("miner", settings);
    let fee_wallet = Wallet::new("fee_payment", settings);
    let mut vault = VaultCovenant::from_file(&settings.vault_file)?;

    let fee_paying_address = fee_wallet.get_new_address()?;
    let fee_paying_utxo = miner_wallet.send(&fee_paying_address, Amount::from_sat(10_000))?;
    let cancel_tx = vault.create_cancel_tx(
        &fee_paying_utxo,
        TxOut {
            script_pubkey: fee_paying_address.script_pubkey(),
            value: Amount::from_sat(10_000),
        },
    )?;

    let signed_tx = fee_wallet.sign_tx(&cancel_tx)?;
    let mut serialized_tx = Vec::new();
    signed_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let txid = fee_wallet.broadcast_tx(&serialized_tx, None)?;
    info!("sent txid: {}", txid);
    miner_wallet.mine_blocks(Some(1))?;
    vault.set_current_outpoint(OutPoint { txid, vout: 0 });
    vault.set_state(Inactive);
    vault.to_file(&settings.vault_file)?;

    Ok(())
}

fn complete(settings: &Settings) -> Result<()> {
    info!("Completing the withdrawal");
    let miner_wallet = Wallet::new("miner", settings);
    let fee_wallet = Wallet::new("fee_payment", settings);
    let mut vault = VaultCovenant::from_file(&settings.vault_file)?;
    let timelock_in_blocks = vault.timelock_in_blocks;
    let withdrawal_address = vault.get_withdrawal_address()?;
    let trigger_tx = vault.get_trigger_transaction()?;

    let fee_paying_address = fee_wallet.get_new_address()?;
    let fee_paying_utxo = miner_wallet.send(&fee_paying_address, Amount::from_sat(10_000))?;
    info!("need to mine {timelock_in_blocks} blocks for the timelock");
    miner_wallet.mine_blocks(Some(timelock_in_blocks as u64))?;
    let compete_tx = vault.create_complete_tx(
        &fee_paying_utxo,
        TxOut {
            script_pubkey: fee_paying_address.script_pubkey(),
            value: Amount::from_sat(10_000),
        },
        &withdrawal_address,
        &trigger_tx,
    )?;
    let signed_tx = fee_wallet.sign_tx(&compete_tx)?;
    let mut serialized_tx = Vec::new();
    signed_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let txid = fee_wallet.broadcast_tx(&serialized_tx, None)?;
    info!("sent txid: {}", txid);
    miner_wallet.mine_blocks(Some(1))?;
    vault.set_current_outpoint(OutPoint { txid, vout: 0 });
    vault.set_state(Completed);
    vault.to_file(&settings.vault_file)?;

    Ok(())
}

fn trigger(destination: &str, steal: bool, settings: &Settings) -> Result<()> {
    info!("Triggering a withdrawal");
    let miner_wallet = Wallet::new("miner", settings);
    let fee_wallet = Wallet::new("fee_payment", settings);
    let mut vault = VaultCovenant::from_file(&settings.vault_file)?;

    let withdrawal_address = Address::from_str(destination)?.require_network(settings.network)?;

    let fee_paying_address = fee_wallet.get_new_address()?;
    let fee_paying_utxo = miner_wallet.send(&fee_paying_address, Amount::from_sat(10_000))?;
    miner_wallet.mine_blocks(Some(1))?;
    let trigger_tx = vault.create_trigger_tx(
        &fee_paying_utxo,
        TxOut {
            script_pubkey: fee_paying_address.script_pubkey(),
            value: Amount::from_sat(10_000),
        },
        &withdrawal_address,
    )?;
    let signed_tx = fee_wallet.sign_tx(&trigger_tx)?;
    let mut serialized_tx = Vec::new();
    signed_tx.consensus_encode(&mut serialized_tx).unwrap();
    debug!("serialized tx: {:?}", serialized_tx.raw_hex());
    let txid = fee_wallet.broadcast_tx(&serialized_tx, None)?;
    info!("sent trigger transaction txid: {}", txid);
    miner_wallet.mine_blocks(Some(1))?;

    vault.set_current_outpoint(OutPoint { txid, vout: 0 });
    if !steal {
        vault.set_withdrawal_address(Some(withdrawal_address));
        vault.set_trigger_transaction(Some(trigger_tx));
        vault.set_state(Triggered);
    }
    vault.to_file(&settings.vault_file)?;

    Ok(())
}

fn deposit(settings: &Settings) -> Result<()> {
    if VaultCovenant::from_file(&settings.vault_file).is_ok() {
        info!("Vault already exists. Delete the vault file if you want to start over.");
        return Ok(());
    }
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
    vault.to_file(&settings.vault_file)?;

    Ok(())
}
