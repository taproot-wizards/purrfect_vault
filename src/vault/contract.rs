use bitcoin::{Amount, Sequence, TapLeafHash, TapSighashType, Transaction, TxOut};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hex::{Case, DisplayHex};
use lazy_static::lazy_static;
use log::debug;
use secp256kfun::G;
use crate::vault::signature_building::{compute_challenge, compute_sigmsg_from_components, get_sigmsg_components, TxCommitmentSpec};


lazy_static! {
    pub(crate) static ref G_X: [u8; 32] = G.into_point_with_even_y().0.to_xonly_bytes();

    pub (crate) static ref TAPSIGHASH_TAG: [u8; 10] = {
        let mut tag = [0u8; 10];
        let val = "TapSighash".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
    pub (crate) static ref BIP0340_CHALLENGE_TAG: [u8; 17] = {
        let mut tag = [0u8; 17];
        let val = "BIP0340/challenge".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
    pub(crate) static ref DUST_AMOUNT: [u8; 8] = {
        let mut dust = [0u8; 8];
        let mut buffer = Vec::new();
        let amount = Amount::from_sat(546);
        amount.consensus_encode(&mut buffer).unwrap();
        dust.copy_from_slice(&buffer);
        dust
    };
}

pub(crate) struct ContractComponents {
    pub(crate) transaction: Transaction,
    pub(crate) signature_components: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) enum GrindField {
    LockTime,
    Sequence,
}

pub(crate) fn grind_transaction<S>(
    initial_tx: Transaction,
    grind_field: GrindField,
    prevouts: &[TxOut],
    leaf_hash: S,
) -> anyhow::Result<ContractComponents>
where
    S: Into<TapLeafHash> + Clone,
{
    let signature_components: Vec<Vec<u8>>;
    let mut counter = 0;

    let mut spend_tx = initial_tx.clone();

    loop {
        match grind_field {
            GrindField::LockTime => spend_tx.lock_time = LockTime::from_height(counter)?,
            GrindField::Sequence => {
                // make sure counter has the 31st bit set, so that it's not used as a relative timelock
                // (BIP68 tells us that bit disables the consensus meaning of sequence numbers for RTL)
                counter |= 1 << 31;
                // set the sequence number of the last input to the counter, we'll use that to pay fees if there is more than one input
                spend_tx.input.last_mut().unwrap().sequence = Sequence::from_consensus(counter);
            }
        }
        debug!("grinding counter {}", counter);

        let components_for_signature = get_sigmsg_components(
            &TxCommitmentSpec::default(),
            &spend_tx,
            0,
            prevouts,
            None,
            leaf_hash.clone(),
            TapSighashType::Default,
        )?;
        let sigmsg = compute_sigmsg_from_components(&components_for_signature)?;
        let challenge = compute_challenge(&sigmsg);

        if challenge[31] == 0x00 {
            debug!("Found a challenge with a 0 at the end!");
            debug!("{:?} is {}", grind_field, counter);
            debug!(
                "Here's the challenge: {}",
                challenge.to_hex_string(Case::Lower)
            );
            signature_components = components_for_signature;
            break;
        }
        counter += 1;
    }
    Ok(ContractComponents {
        transaction: spend_tx,
        signature_components,
    })
}
