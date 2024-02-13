use anyhow::{anyhow, Result};
use bitcoin::{Address, Amount, Network, OutPoint, Script, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, XOnlyPublicKey};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::key::Secp256k1;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use log::debug;

use crate::G_X;
use crate::settings::Settings;
use crate::vault::{contract, signature_building};
use crate::vault::script::{vault_cancel_withdrawal, vault_complete_withdrawal, vault_trigger_withdrawal};
use crate::vault::signature_building::{
    get_sigmsg_components, TxCommitmentSpec,
};

pub(crate) enum VaultOperation {
    Trigger,
    Complete,
    Cancel
}

pub(crate) struct VaultCovenant {
    current_outpoint: Option<OutPoint>,
    amount: Amount,
    network: Network,
}

impl Default for VaultCovenant {
    fn default() -> Self {
        Self {
            current_outpoint: None,
            amount: Amount::ZERO,
            network: Network::Regtest,
        }
    }
}

impl VaultCovenant {
    pub(crate) fn new(settings: &Settings) -> Result<Self> {
        Ok(Self {
            network: settings.network,
            ..Default::default()
        })
    }

    pub(crate) fn set_current_outpoint(&mut self, outpoint: OutPoint) {
        self.current_outpoint = Some(outpoint);
    }
    pub(crate) fn set_amount(&mut self, amount: Amount) {
        self.amount = amount;
    }

    pub(crate) fn address(&self) -> Result<Address> {
        let spend_info = self.taproot_spend_info()?;
        Ok(Address::p2tr_tweaked(spend_info.output_key(), self.network))
    }

    fn taproot_spend_info(&self) -> Result<TaprootSpendInfo> {
        // TODO: change this to the hash of G_X, not G_X itself
        let nums_key = XOnlyPublicKey::from_slice(G_X.as_slice())?;
        let secp = Secp256k1::new();
        Ok(TaprootBuilder::new()
            .add_leaf(1, vault_trigger_withdrawal())?
            .add_leaf(2, vault_complete_withdrawal())?
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
        let contract_components = contract::grind_transaction(
            txn,
            contract::GrindField::LockTime,
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

    pub(crate) fn create_cancel_tx(&self,
    fee_paying_utxo: &OutPoint,
    fee_paying_output: TxOut
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
        let contract_components = contract::grind_transaction(
            txn,
            contract::GrindField::LockTime,
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

#[cfg(test)]
mod tests {
    use crate::vault::vault_contract::VaultCovenant;

    #[test]
    fn test_vault_covenant() {
        let vault_covenant = VaultCovenant::default();
        let address = vault_covenant.address().unwrap();
        println!("vault address: {}", address);
    }
}