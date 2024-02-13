use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::key::Secp256k1;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxIn,
    TxOut, XOnlyPublicKey,
};
use log::debug;

use crate::settings::Settings;
use crate::vault::script::constrained_outputs;
use crate::vault::{contract, signature_building};
use crate::vault::signature_building::{
    get_sigmsg_components, TxCommitmentSpec,
};
use crate::G_X;

pub(crate) struct SingleOutputEncumberingContract {
    output: TxOut,
    script: ScriptBuf,
    network: Network,
}

impl SingleOutputEncumberingContract {
    pub(crate) fn new(destination: &Address, amount: Amount, settings: &Settings) -> Result<Self> {
        let output = TxOut {
            value: amount,
            script_pubkey: destination.script_pubkey(),
        };
        let mut encoded_outputs = Vec::new();
        output.consensus_encode(&mut encoded_outputs)?;
        let output_for_hash = encoded_outputs.clone();
        let output_hash = sha256::Hash::hash(&output_for_hash);
        let mut encoded_output_hash = Vec::new();
        output_hash.consensus_encode(&mut encoded_output_hash)?;
        let encoded_output_bytes: [u8; 32] = encoded_output_hash.as_slice().try_into()?;
        let script = constrained_outputs(encoded_output_bytes);

        Ok(Self {
            output,
            script,
            network: settings.network,
        })
    }

    pub(crate) fn script(&self) -> &ScriptBuf {
        &self.script
    }

    pub(crate) fn address(&self) -> Result<Address> {
        let spend_info = self.taproot_spend_info()?;
        Ok(Address::p2tr_tweaked(spend_info.output_key(), self.network))
    }

    fn taproot_spend_info(&self) -> Result<TaprootSpendInfo> {
        let nums_key = XOnlyPublicKey::from_slice(G_X.as_slice())?;
        let secp = Secp256k1::new();
        Ok(TaprootBuilder::new()
            .add_leaf(0, self.script.clone())?
            .finalize(&secp, nums_key)
            .expect("finalizing taproot spend info with a NUMS point should always work"))
    }

    pub(crate) fn create_spending_transaction(
        &self,
        funding_utxo: &OutPoint,
        funding_output: TxOut,
    ) -> Result<Transaction> {
        // TODO: put a client in here and fetch the funding outpoint

        let mut txin = TxIn {
            previous_output: OutPoint {
                txid: funding_utxo.txid,
                vout: funding_utxo.vout,
            },
            ..Default::default()
        };

        let spend_tx = Transaction {
            lock_time: LockTime::ZERO,
            version: Version::TWO,
            input: vec![txin.clone()],
            output: vec![self.output.clone()],
        };

        let tx_commitment_spec = TxCommitmentSpec {
            outputs: false,
            ..Default::default()
        };

        // I think everything from here down is generic

        let leaf_hash = TapLeafHash::from_script(self.script(), LeafVersion::TapScript);
        let contract_components = contract::grind_transaction(
            spend_tx,
            contract::GrindField::LockTime,
            &[funding_output.clone()],
            leaf_hash,
        )?;
        let mut spend_tx = contract_components.transaction;
        let witness_components = get_sigmsg_components(
            &tx_commitment_spec,
            &spend_tx,
            0,
            &[funding_output],
            None,
            leaf_hash,
            TapSighashType::Default,
        )?;

        for component in witness_components.iter() {
            debug!(
                "pushing component <0x{}> into the witness",
                component.to_hex_string(Case::Lower)
            );
            txin.witness.push(component.as_slice());
        }
        let computed_signature =
            signature_building::compute_signature_from_components(&contract_components.signature_components)?;
        let mangled_signature: [u8; 63] = computed_signature[0..63].try_into().unwrap(); // chop off the last byte, so we can provide the 0x00 and 0x01 bytes on the stack
        txin.witness.push(mangled_signature);

        txin.witness.push(self.script().to_bytes());
        txin.witness.push(
            self.taproot_spend_info()?
                .control_block(&(self.script().clone(), LeafVersion::TapScript))
                .expect("control block should work")
                .serialize(),
        );
        spend_tx.input.first_mut().unwrap().witness = txin.witness.clone();

        Ok(spend_tx)
    }
}
