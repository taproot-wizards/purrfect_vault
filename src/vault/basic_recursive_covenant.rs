use anyhow::Result;
use bitcoin::{Address, Amount, Network, OutPoint, Script, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, XOnlyPublicKey};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::{OP_1SUB, OP_CAT, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_ROT, OP_SHA256, OP_SWAP, OP_TOALTSTACK};
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use log::debug;

use crate::G_X;
use crate::settings::Settings;
use crate::vault::{contract, signature_building};
use crate::vault::contract::{BIP0340_CHALLENGE_TAG, TAPSIGHASH_TAG};
use crate::vault::signature_building::{
    get_sigmsg_components, TxCommitmentSpec,
};

pub(crate) struct BasicRecursiveCovenant {
    script: ScriptBuf,
    network: Network,
}

impl BasicRecursiveCovenant {
    pub(crate) fn new(settings: &Settings) -> Result<Self> {

        let mut builder = Script::builder();
        // The witness program needs to have the signature components except the outputs and the pre_scriptpubkeys,
        // followed by the output amount, the script pubkey, and the mangled signature
        builder = builder
            .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
            .push_opcode(OP_DUP) // make a second copy of the scriptpubkey so we can check input = output
            .push_opcode(OP_TOALTSTACK)
            .push_opcode(OP_TOALTSTACK) // move both copies of scriptpubkey to the alt stack
            .push_opcode(OP_TOALTSTACK) // move the output amount to the alt stack
            // start with encoded leaf hash
            .push_opcode(OP_CAT) // encoded leaf hash
            .push_opcode(OP_CAT) // encoded leaf hash
            .push_opcode(OP_CAT) // input index
            .push_opcode(OP_CAT) // spend type
            .push_opcode(OP_FROMALTSTACK)// get the output amount
            .push_opcode(OP_FROMALTSTACK) // get the second copy of the scriptpubkey
            .push_opcode(OP_CAT) // cat the output amount and the second copy of the scriptpubkey
            .push_opcode(OP_SHA256) // hash the output
            .push_opcode(OP_SWAP) // move the hashed encoded outputs below our working sigmsg
            .push_opcode(OP_CAT) // outputs
            .push_opcode(OP_CAT) // prev sequences
            .push_opcode(OP_FROMALTSTACK) // get the other copy of the scriptpubkey
            .push_opcode(OP_SHA256) // hash the scriptpubkey, should now be consensus encoding
            .push_opcode(OP_SWAP) // move the hashed encoded scriptpubkeys below our working sigmsg
            .push_opcode(OP_CAT) // prev scriptpubkeys
            .push_opcode(OP_CAT) // prev amounts
            .push_opcode(OP_CAT) // prevouts
            .push_opcode(OP_CAT) // lock time
            .push_opcode(OP_CAT) // version
            .push_opcode(OP_CAT) // control
            .push_opcode(OP_CAT) // epoch
            .push_slice(*TAPSIGHASH_TAG) // push tag
            .push_opcode(OP_SHA256) // hash tag
            .push_opcode(OP_DUP) // dup hash
            .push_opcode(OP_ROT) // move the sighash to the top of the stack
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_SHA256) // tagged hash of the sighash
            .push_slice(*BIP0340_CHALLENGE_TAG) // push tag
            .push_opcode(OP_SHA256)
            .push_opcode(OP_DUP)
            .push_opcode(OP_ROT) // bring challenge to the top of the stack
            .push_slice(*G_X) // G is used for the pubkey and K
            .push_opcode(OP_DUP)
            .push_opcode(OP_DUP)
            .push_opcode(OP_TOALTSTACK) // we'll need a copy of G later to be our R value in the signature
            .push_opcode(OP_ROT) // bring the challenge to the top of the stack
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT)
            .push_opcode(OP_CAT) // cat the two tags, R, P, and M values together
            .push_opcode(OP_SHA256) // hash the whole thing to get the s value for the signature
            .push_opcode(OP_FROMALTSTACK) // bring G back from the alt stack to use as the R value in the signature
            .push_opcode(OP_SWAP)
            .push_opcode(OP_CAT) // cat the R value with the s value for a complete signature
            .push_opcode(OP_FROMALTSTACK) // grab the pre-computed signature minus the last byte from the alt stack
            .push_opcode(OP_DUP) // we'll need a second copy later to do the actual signature verification
            .push_slice([0x00u8]) // add the last byte of the signature, which should match what we computed. NOTE ⚠️: push_int(0) will not work here because it will push OP_FALSE, but we want an actual 0 byte
            .push_opcode(OP_CAT)
            .push_opcode(OP_ROT) // bring the script-computed signature to the top of the stack
            .push_opcode(OP_EQUALVERIFY) // check that the script-computed and pre-computed signatures match
            .push_int(0x01) // we need the last byte of the signature to be 0x01 because our k value is 1 (because K is G)
            .push_opcode(OP_CAT)
            .push_slice(*G_X) // push G again. TODO: DUP this from before and stick it in the alt stack or something
            .push_opcode(OP_CHECKSIG);
        let script = builder.into_script();

        Ok(Self {
            script,
            network: settings.network,
        })
    }

    fn script(&self) -> &ScriptBuf {
       &self.script
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
            .add_leaf(0, self.script.clone())?
            .finalize(&secp, nums_key)
            .expect("finalizing taproot spend info with a NUMS point should always work"))
    }

    pub(crate) fn create_spending_transaction(
        &self,
        funding_utxo: &OutPoint,
        funding_output: TxOut,
        amount: Amount,
    ) -> Result<Transaction> {
        // TODO: put a client in here and fetch the funding outpoint

        let mut txin = TxIn {
            previous_output: OutPoint {
                txid: funding_utxo.txid,
                vout: funding_utxo.vout,
            },
            ..Default::default()
        };

        let output = TxOut {
            script_pubkey: self.address()?.script_pubkey(),
            value: amount,
        };

        let spend_tx = Transaction {
            lock_time: LockTime::ZERO,
            version: Version::TWO,
            input: vec![txin.clone()],
            output: vec![output.clone()],
        };

        let tx_commitment_spec = TxCommitmentSpec {
            prev_sciptpubkeys: false,
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

        let mut amount_buffer = Vec::new();
        amount.consensus_encode(&mut amount_buffer)?;
        txin.witness.push(amount_buffer.as_slice());
        let mut scriptpubkey_buffer = Vec::new();
        output.script_pubkey.consensus_encode(&mut scriptpubkey_buffer)?;
        txin.witness.push(scriptpubkey_buffer.as_slice());


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
