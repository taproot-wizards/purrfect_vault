use std::str::FromStr;
use anyhow::{anyhow, Result};
use bitcoin::{Address, Amount, Network, OutPoint, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, XOnlyPublicKey};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoincore_rpc::jsonrpc::serde_json;
use log::{debug, info};
use secp256kfun::{G, Point};
use secp256kfun::marker::{EvenY, NonZero, Public};
use serde::{Deserialize, Serialize};

use crate::settings::Settings;
use crate::vault::signature_building;
use crate::vault::script::{vault_cancel_withdrawal, vault_complete_withdrawal, vault_trigger_withdrawal};
use crate::vault::signature_building::{
    get_sigmsg_components, TxCommitmentSpec,
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) enum VaultState {
    Inactive,
    Triggered,
    Completed
}

/// Get the vault state from the transaction and the vault address
impl From<(Transaction, Address)> for VaultState {
    fn from(spec: (Transaction, Address)) -> Self {
        let (tx, address) = spec;
        if tx.output.len() == 2 && tx.output.get(1).unwrap().value == Amount::from_sat(546) {
            VaultState::Triggered
        } else if tx.output.len() == 1 && tx.output.first().unwrap().script_pubkey != address.script_pubkey() {
            VaultState::Completed
        } else {
            VaultState::Inactive
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct VaultCovenant {
    current_outpoint: Option<OutPoint>,
    amount: Amount,
    network: Network,
    pub(crate) timelock_in_blocks: u16,
    withdrawal_address: Option<String>,
    trigger_transaction: Option<Transaction>,
    state: VaultState,
}

impl Default for VaultCovenant {
    fn default() -> Self {
        Self {
            current_outpoint: None,
            amount: Amount::ZERO,
            network: Network::Regtest,
            timelock_in_blocks: 20,
            withdrawal_address: None,
            trigger_transaction: None,
            state: VaultState::Inactive,
        }
    }
}

impl VaultCovenant {
    pub(crate) fn new(timelock_in_blocks: u16, settings: &Settings) -> Result<Self> {
        Ok(Self {
            network: settings.network,
            timelock_in_blocks,
            ..Default::default()
        })
    }

    pub(crate) fn from_file(filename: &Option<String>) -> Result<Self> {
        let filename = filename.clone().unwrap_or("vault_covenant.json".to_string());
        info!("reading vault covenant from file: {}", filename);
        let file = std::fs::File::open(filename)?;
        let covenant: VaultCovenant = serde_json::from_reader(file)?;
        Ok(covenant)
    }

    pub(crate) fn to_file(&self, filename: &Option<String>) -> Result<()> {
        let filename = filename.clone().unwrap_or("vault_covenant.json".to_string());
        info!("writing vault covenant to file: {}", filename);
        let file = std::fs::File::create(filename)?;
        serde_json::to_writer(file, self)?;
        Ok(())
    }

    pub(crate) fn set_current_outpoint(&mut self, outpoint: OutPoint) {
        self.current_outpoint = Some(outpoint);
    }

    pub(crate) fn get_current_outpoint(&self) -> Result<OutPoint> {
        self.current_outpoint.ok_or(anyhow!("no current outpoint"))
    }
    pub(crate) fn set_amount(&mut self, amount: Amount) {
        self.amount = amount;
    }

    pub(crate) fn set_withdrawal_address(&mut self, address: Option<Address>) {
        self.withdrawal_address = address.map(|a| a.to_string());
    }

    pub(crate) fn get_withdrawal_address(&self) -> Result<Address> {
        Ok(
            Address::from_str(self.withdrawal_address.as_ref().ok_or(anyhow!("no withdrawal address"))?)?.require_network(self.network)?
        )
    }

    pub(crate) fn set_trigger_transaction(&mut self, txn: Option<Transaction>) {
        self.trigger_transaction = txn;
    }

    pub(crate) fn get_trigger_transaction(&self) -> Result<Transaction> {
        self.trigger_transaction.clone().ok_or(anyhow!("no trigger transaction"))
    }

    pub(crate) fn set_state(&mut self, state: VaultState) {
        if state == VaultState::Completed {
            self.set_trigger_transaction(None);
            self.set_withdrawal_address(None);
        }
        self.state = state;
    }

    pub(crate) fn get_state(&self) -> VaultState {
        self.state.clone()
    }

    pub(crate) fn address(&self) -> Result<Address> {
        let spend_info = self.taproot_spend_info()?;
        Ok(Address::p2tr_tweaked(spend_info.output_key(), self.network))
    }

    fn taproot_spend_info(&self) -> Result<TaprootSpendInfo> {
        // hash G into a NUMS point
        let hash = sha256::Hash::hash(G.to_bytes_uncompressed().as_slice());
        let point: Point<EvenY, Public, NonZero> = Point::from_xonly_bytes(hash.into_32())
            .ok_or(anyhow!("G_X hash should be a valid x-only point"))?;
        let nums_key = XOnlyPublicKey::from_slice(point.to_xonly_bytes().as_slice())?;
        let secp = Secp256k1::new();
        Ok(TaprootBuilder::new()
            .add_leaf(1, vault_trigger_withdrawal())?
            .add_leaf(2, vault_complete_withdrawal(self.timelock_in_blocks))?
            .add_leaf(2, vault_cancel_withdrawal())?
            .finalize(&secp, nums_key)
            .expect("finalizing taproot spend info with a NUMS point should always work"))
    }

    pub(crate) fn create_trigger_tx(&self,
                                    fee_paying_utxo: &OutPoint,
                                    fee_paying_output: TxOut,
                                    target_address: &Address,
    ) -> Result<Transaction> {
        let mut vault_txin = TxIn {
            previous_output: self.current_outpoint.ok_or(anyhow!("no current outpoint"))?,
            ..Default::default()
        };
        let fee_txin = TxIn {
            previous_output: *fee_paying_utxo,
            ..Default::default()
        };
        let vault_output = TxOut {
            script_pubkey: self.address()?.script_pubkey(),
            value: self.amount,
        };
        let target_output = TxOut {
            script_pubkey: target_address.script_pubkey(),
            value: Amount::from_sat(546),
        };


        let txn = Transaction {
            lock_time: LockTime::ZERO,
            version: Version::TWO,
            input: vec![vault_txin.clone(), fee_txin],
            output: vec![vault_output.clone(), target_output.clone()],
        };


        let tx_commitment_spec = TxCommitmentSpec {
            prev_sciptpubkeys: false,
            prev_amounts: false,
            outputs: false,
            ..Default::default()
        };

        let leaf_hash = TapLeafHash::from_script(&vault_trigger_withdrawal(), LeafVersion::TapScript);
        let vault_txout = TxOut {
            script_pubkey: self.address()?.script_pubkey().clone(),
            value: self.amount,
        };
        let contract_components = signature_building::grind_transaction(
            txn,
            signature_building::GrindField::LockTime,
            &[vault_txout.clone(), fee_paying_output.clone()],
            leaf_hash,
        )?;


        let mut txn = contract_components.transaction;
        let witness_components = get_sigmsg_components(
            &tx_commitment_spec,
            &txn,
            0,
            &[vault_txout.clone(), fee_paying_output.clone()],
            None,
            leaf_hash,
            TapSighashType::Default,
        )?;

        for component in witness_components.iter() {
            debug!(
                "pushing component <0x{}> into the witness",
                component.to_hex_string(Case::Lower)
            );
            vault_txin.witness.push(component.as_slice());
        }

        let mut target_scriptpubkey_buffer = Vec::new();
        target_output.script_pubkey.consensus_encode(&mut target_scriptpubkey_buffer)?;
        vault_txin.witness.push(target_scriptpubkey_buffer.as_slice());

        let mut amount_buffer = Vec::new();
        self.amount.consensus_encode(&mut amount_buffer)?;
        vault_txin.witness.push(amount_buffer.as_slice());
        let mut scriptpubkey_buffer = Vec::new();
        vault_output.script_pubkey.consensus_encode(&mut scriptpubkey_buffer)?;
        vault_txin.witness.push(scriptpubkey_buffer.as_slice());

        let mut fee_amount_buffer = Vec::new();
        fee_paying_output.value.consensus_encode(&mut fee_amount_buffer)?;
        vault_txin.witness.push(fee_amount_buffer.as_slice());
        let mut fee_scriptpubkey_buffer = Vec::new();
        fee_paying_output.script_pubkey.consensus_encode(&mut fee_scriptpubkey_buffer)?;
        vault_txin.witness.push(fee_scriptpubkey_buffer.as_slice());

        let computed_signature =
            signature_building::compute_signature_from_components(&contract_components.signature_components)?;
        let mangled_signature: [u8; 63] = computed_signature[0..63].try_into().unwrap(); // chop off the last byte, so we can provide the 0x00 and 0x01 bytes on the stack
        vault_txin.witness.push(mangled_signature);

        vault_txin.witness.push(vault_trigger_withdrawal().to_bytes());
        vault_txin.witness.push(
            self.taproot_spend_info()?
                .control_block(&(vault_trigger_withdrawal().clone(), LeafVersion::TapScript))
                .expect("control block should work")
                .serialize(),
        );
        txn.input.first_mut().unwrap().witness = vault_txin.witness.clone();

        Ok(txn)
    }

    pub(crate) fn create_complete_tx(&self,
                                     fee_paying_utxo: &OutPoint,
                                     fee_paying_output: TxOut,
                                     target_address: &Address,
                                     trigger_tx: &Transaction,
    ) -> Result<Transaction> {
        let mut vault_txin = TxIn {
            previous_output: self.current_outpoint.ok_or(anyhow!("no current outpoint"))?,
            sequence: Sequence::from_height(self.timelock_in_blocks),
            ..Default::default()
        };
        let fee_txin = TxIn {
            previous_output: *fee_paying_utxo,
            ..Default::default()
        };

        let target_output = TxOut {
            script_pubkey: target_address.script_pubkey(),
            value: self.amount,
        };

        let txn = Transaction {
            lock_time: LockTime::ZERO,
            version: Version::TWO,
            input: vec![vault_txin.clone(), fee_txin],
            output: vec![target_output.clone()],
        };

        let tx_commitment_spec = TxCommitmentSpec {
            prevouts: false,
            outputs: false,
            ..Default::default()
        };

        let leaf_hash = TapLeafHash::from_script(&vault_complete_withdrawal(self.timelock_in_blocks), LeafVersion::TapScript);
        let vault_txout = TxOut {
            script_pubkey: self.address()?.script_pubkey().clone(),
            value: self.amount,
        };
        let contract_components = signature_building::grind_transaction(
            txn,
            signature_building::GrindField::Sequence,
            &[vault_txout.clone(), fee_paying_output.clone()],
            leaf_hash,
        )?;


        let mut txn = contract_components.transaction;
        let witness_components = get_sigmsg_components(
            &tx_commitment_spec,
            &txn,
            0,
            &[vault_txout.clone(), fee_paying_output.clone()],
            None,
            leaf_hash,
            TapSighashType::Default,
        )?;

        for component in witness_components.iter() {
            debug!(
                "pushing component <0x{}> into the witness",
                component.to_hex_string(Case::Lower)
            );
            vault_txin.witness.push(component.as_slice());
        }

        debug!("Previous TXID: {}", trigger_tx.txid());

        // stick all the previous txn components except the outputs into the witness
        let mut version_buffer = Vec::new();
        trigger_tx.version.consensus_encode(&mut version_buffer)?;
        vault_txin.witness.push(version_buffer.as_slice());

        // push the trigger_tx input in chunks no larger than 80 bytes
        let mut input_buffer = Vec::new();
        trigger_tx.input.consensus_encode(&mut input_buffer)?;
        //vault_txin.witness.push(input_buffer.as_slice());
        // TODO: handle the case where we have more than 2 chunks
        // we have to break this up into 80 byte chunks because there's a policy limit on the size of a single push
        let chunk_size = 80;
        for chunk in input_buffer.chunks(chunk_size) {
            vault_txin.witness.push(chunk);
        }

        let mut locktime_buffer = Vec::new();
        trigger_tx.lock_time.consensus_encode(&mut locktime_buffer)?;
        vault_txin.witness.push(locktime_buffer.as_slice());


        let mut vault_scriptpubkey_buffer = Vec::new();
        self.address()?.script_pubkey().consensus_encode(&mut vault_scriptpubkey_buffer)?;
        vault_txin.witness.push(vault_scriptpubkey_buffer.as_slice());

        let mut amount_buffer = Vec::new();
        self.amount.consensus_encode(&mut amount_buffer)?;
        vault_txin.witness.push(amount_buffer.as_slice());

        let mut target_scriptpubkey_buffer = Vec::new();
        target_output.script_pubkey.consensus_encode(&mut target_scriptpubkey_buffer)?;
        vault_txin.witness.push(target_scriptpubkey_buffer.as_slice());

        let mut fee_paying_prevout_buffer = Vec::new();
        fee_paying_utxo.consensus_encode(&mut fee_paying_prevout_buffer)?;
        vault_txin.witness.push(fee_paying_prevout_buffer.as_slice());


        let computed_signature =
            signature_building::compute_signature_from_components(&contract_components.signature_components)?;
        let mangled_signature: [u8; 63] = computed_signature[0..63].try_into().unwrap(); // chop off the last byte, so we can provide the 0x00 and 0x01 bytes on the stack
        vault_txin.witness.push(mangled_signature);

        vault_txin.witness.push(vault_complete_withdrawal(self.timelock_in_blocks).to_bytes());
        vault_txin.witness.push(
            self.taproot_spend_info()?
                .control_block(&(vault_complete_withdrawal(self.timelock_in_blocks).clone(), LeafVersion::TapScript))
                .expect("control block should work")
                .serialize(),
        );

        txn.input.first_mut().unwrap().witness = vault_txin.witness.clone();

        Ok(txn)
    }

    pub(crate) fn create_cancel_tx(&self,
                                   fee_paying_utxo: &OutPoint,
                                   fee_paying_output: TxOut,
    ) -> Result<Transaction> {
        let mut vault_txin = TxIn {
            previous_output: self.current_outpoint.ok_or(anyhow!("no current outpoint"))?,
            ..Default::default()
        };
        let fee_txin = TxIn {
            previous_output: fee_paying_utxo.clone(),
            ..Default::default()
        };
        let output = TxOut {
            script_pubkey: self.address()?.script_pubkey(),
            value: self.amount,
        };

        let txn = Transaction {
            lock_time: LockTime::ZERO,
            version: Version::TWO,
            input: vec![vault_txin.clone(), fee_txin],
            output: vec![output.clone()],
        };


        let tx_commitment_spec = TxCommitmentSpec {
            prev_sciptpubkeys: false,
            prev_amounts: false,
            outputs: false,
            ..Default::default()
        };

        let leaf_hash = TapLeafHash::from_script(&vault_cancel_withdrawal(), LeafVersion::TapScript);
        let vault_txout = TxOut {
            script_pubkey: self.address()?.script_pubkey().clone(),
            value: self.amount,
        };
        let contract_components = signature_building::grind_transaction(
            txn,
            signature_building::GrindField::LockTime,
            &[vault_txout.clone(), fee_paying_output.clone()],
            leaf_hash,
        )?;


        let mut txn = contract_components.transaction;
        let witness_components = get_sigmsg_components(
            &tx_commitment_spec,
            &txn,
            0,
            &[vault_txout.clone(), fee_paying_output.clone()],
            None,
            leaf_hash,
            TapSighashType::Default,
        )?;

        for component in witness_components.iter() {
            debug!(
                "pushing component <0x{}> into the witness",
                component.to_hex_string(Case::Lower)
            );
            vault_txin.witness.push(component.as_slice());
        }
        let computed_signature =
            signature_building::compute_signature_from_components(&contract_components.signature_components)?;

        let mut amount_buffer = Vec::new();
        self.amount.consensus_encode(&mut amount_buffer)?;
        vault_txin.witness.push(amount_buffer.as_slice());
        let mut scriptpubkey_buffer = Vec::new();
        output.script_pubkey.consensus_encode(&mut scriptpubkey_buffer)?;
        vault_txin.witness.push(scriptpubkey_buffer.as_slice());

        let mut fee_amount_buffer = Vec::new();
        fee_paying_output.value.consensus_encode(&mut fee_amount_buffer)?;
        vault_txin.witness.push(fee_amount_buffer.as_slice());
        let mut fee_scriptpubkey_buffer = Vec::new();
        fee_paying_output.script_pubkey.consensus_encode(&mut fee_scriptpubkey_buffer)?;
        vault_txin.witness.push(fee_scriptpubkey_buffer.as_slice());


        let mangled_signature: [u8; 63] = computed_signature[0..63].try_into().unwrap(); // chop off the last byte, so we can provide the 0x00 and 0x01 bytes on the stack
        vault_txin.witness.push(mangled_signature);

        vault_txin.witness.push(vault_cancel_withdrawal().to_bytes());
        vault_txin.witness.push(
            self.taproot_spend_info()?
                .control_block(&(vault_cancel_withdrawal().clone(), LeafVersion::TapScript))
                .expect("control block should work")
                .serialize(),
        );
        txn.input.first_mut().unwrap().witness = vault_txin.witness.clone();

        Ok(txn)
    }
}
