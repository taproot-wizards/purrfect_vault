use bitcoin::{TapLeafHash, TapSighashType, Transaction, TxOut};
use bitcoin::absolute::LockTime;
use bitcoin::hex::{Case, DisplayHex};
use lazy_static::lazy_static;
use log::debug;
use crate::vault::signature_building::{compute_challenge, compute_sigmsg_from_components, get_sigmsg_components, TxCommitmentSpec};

lazy_static! {
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
}

pub(crate) struct ContractComponents {
    pub(crate) transaction: Transaction,
    pub(crate) signature_components: Vec<Vec<u8>>,
}

pub(crate) fn grind_transaction<S>(
    initial_tx: Transaction,
    prevouts: &[TxOut],
    leaf_hash: S,
) -> anyhow::Result<ContractComponents>
where
    S: Into<TapLeafHash> + Clone,
{
    let signature_components: Vec<Vec<u8>>;
    let mut locktime = 0;

    let mut spend_tx = initial_tx.clone();

    loop {
        spend_tx.lock_time = LockTime::from_height(locktime)?;
        debug!("grinding locktime {}", locktime);

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

        if challenge[31] == 0x01 {
            debug!("Found a challenge with a 1 at the end!");
            debug!("locktime is {}", locktime);
            debug!(
                "Here's the challenge: {}",
                challenge.to_hex_string(Case::Lower)
            );
            signature_components = components_for_signature;
            break;
        }
        locktime += 1;
    }
    Ok(ContractComponents {
        transaction: spend_tx,
        signature_components,
    })
}
