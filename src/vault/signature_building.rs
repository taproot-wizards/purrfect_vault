use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::sighash::{Annex, Error};
use bitcoin::{Amount, Sequence, TapLeafHash, TapSighash, TapSighashType, Transaction, TxOut};
use lazy_static::lazy_static;
use log::debug;
use secp256kfun::G;

lazy_static! {
    pub(crate) static ref G_X: [u8; 32] = G.into_point_with_even_y().0.to_xonly_bytes();
    pub(crate) static ref TAPSIGHASH_TAG: [u8; 10] = {
        let mut tag = [0u8; 10];
        let val = "TapSighash".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
    pub(crate) static ref BIP0340_CHALLENGE_TAG: [u8; 17] = {
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

#[derive()]
pub(crate) struct TxCommitmentSpec {
    pub(crate) epoch: bool,
    pub(crate) control: bool,
    pub(crate) version: bool,
    pub(crate) lock_time: bool,
    pub(crate) prevouts: bool,
    pub(crate) prev_amounts: bool,
    pub(crate) prev_sciptpubkeys: bool,
    pub(crate) sequences: bool,
    pub(crate) outputs: bool,
    pub(crate) spend_type: bool,
    pub(crate) annex: bool,
    pub(crate) single_output: bool,
    pub(crate) scriptpath: bool,
}

impl Default for TxCommitmentSpec {
    fn default() -> Self {
        Self {
            epoch: true,
            control: true,
            version: true,
            lock_time: true,
            prevouts: true,
            prev_amounts: true,
            prev_sciptpubkeys: true,
            sequences: true,
            outputs: true,
            spend_type: true,
            annex: true,
            single_output: true,
            scriptpath: true,
        }
    }
}

pub(crate) fn get_sigmsg_components<S: Into<TapLeafHash>>(
    spec: &TxCommitmentSpec,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    annex: Option<Annex>,
    leaf_hash: S,
    sighash_type: TapSighashType,
) -> Result<Vec<Vec<u8>>> {
    // all this serialization code was lifted from bitcoin-0.31.1/src/crypto/sighash.rs:597 and
    // then very violently hacked up.

    let mut components = Vec::new();

    let leaf_hash_code_separator = Some((leaf_hash.into(), 0xFFFFFFFFu32));

    let (sighash, anyone_can_pay) = match sighash_type {
        TapSighashType::Default => (bitcoin::TapSighashType::Default, false),
        TapSighashType::All => (bitcoin::TapSighashType::All, false),
        TapSighashType::None => (bitcoin::TapSighashType::None, false),
        TapSighashType::Single => (bitcoin::TapSighashType::Single, false),
        TapSighashType::AllPlusAnyoneCanPay => (TapSighashType::All, true),
        TapSighashType::NonePlusAnyoneCanPay => (bitcoin::TapSighashType::None, true),
        TapSighashType::SinglePlusAnyoneCanPay => (TapSighashType::Single, true),
    };

    if spec.epoch {
        let mut epoch = Vec::new();
        0u8.consensus_encode(&mut epoch)?;
        debug!("epoch: {:?}", epoch.to_hex_string(Case::Lower));
        components.push(epoch);
    }

    if spec.control {
        let mut control = Vec::new();
        (sighash_type as u8).consensus_encode(&mut control)?;
        debug!("control: {:?}", control.to_hex_string(Case::Lower));
        components.push(control);
    }

    if spec.version {
        let mut version = Vec::new();
        tx.version.consensus_encode(&mut version)?;
        debug!("version: {:?}", version.to_hex_string(Case::Lower));
        components.push(version);
    }

    if spec.lock_time {
        let mut lock_time = Vec::new();
        tx.lock_time.consensus_encode(&mut lock_time)?;
        debug!("lock_time: {:?}", lock_time.to_hex_string(Case::Lower));
        components.push(lock_time);
    }

    if !anyone_can_pay {
        if spec.prevouts {
            let mut prevouts = Vec::new();
            let mut buffer = Vec::new();
            for prevout in tx.input.iter() {
                prevout
                    .previous_output
                    .consensus_encode(&mut buffer)
                    .unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prevouts).unwrap();
            debug!("prevouts: {:?}", prevouts.to_hex_string(Case::Lower));
            components.push(prevouts);
        }

        if spec.prev_amounts {
            let mut prev_amounts = Vec::new();
            let mut buffer = Vec::new();
            for p in prevouts {
                p.value.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prev_amounts).unwrap();
            debug!(
                "prev_amounts: {:?}",
                prev_amounts.to_hex_string(Case::Lower)
            );
            components.push(prev_amounts);
        }
        if spec.prev_sciptpubkeys {
            let mut prev_sciptpubkeys = Vec::new();
            let mut buffer = Vec::new();
            for p in prevouts {
                p.script_pubkey.consensus_encode(&mut buffer).unwrap();
            }
            debug!(
                "prev_sciptpubkeys buffer: {:?}",
                buffer.to_hex_string(Case::Lower)
            );

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prev_sciptpubkeys).unwrap();
            debug!(
                "prev_sciptpubkeys: {:?}",
                prev_sciptpubkeys.to_hex_string(Case::Lower)
            );
            components.push(prev_sciptpubkeys);
        }
        if spec.sequences {
            let mut sequences = Vec::new();
            let mut buffer = Vec::new();
            for i in tx.input.iter() {
                i.sequence.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut sequences).unwrap();
            debug!("sequences: {:?}", sequences.to_hex_string(Case::Lower));
            components.push(sequences);
        }
    }

    if spec.outputs && sighash != TapSighashType::None && sighash != TapSighashType::Single {
        let mut outputs = Vec::new();
        let mut buffer = Vec::new();
        for o in tx.output.iter() {
            o.consensus_encode(&mut buffer).unwrap();
        }
        let hash = sha256::Hash::hash(&buffer);
        hash.consensus_encode(&mut outputs).unwrap();
        debug!("outputs: {:?}", outputs.to_hex_string(Case::Lower));
        components.push(outputs);
    }

    if spec.spend_type {
        let mut encoded_spend_type = Vec::new();
        let mut spend_type = 0u8;
        if annex.is_some() {
            spend_type |= 1u8;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2u8;
        }
        spend_type.consensus_encode(&mut encoded_spend_type)?;
        debug!(
            "spend_type: {:?}",
            encoded_spend_type.to_hex_string(Case::Lower)
        );
        components.push(encoded_spend_type);
    }

    // TODO: wrap these fields in spec checks. right now we dont use ANYONECANPAY so it doesnt matter. But some other applications might want to use it.

    // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
    //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
    //      amount (8): value of the previous output spent by this input.
    //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
    //      nSequence (4): nSequence of this input.
    if anyone_can_pay {
        let txin = &tx
            .input
            .get(input_index)
            .ok_or(Error::IndexOutOfInputsBounds {
                index: input_index,
                inputs_size: tx.input.len(),
            })?;
        let previous_output = prevouts
            .get(input_index)
            .ok_or(Error::IndexOutOfInputsBounds {
                index: input_index,
                inputs_size: prevouts.len(),
            })?;
        let mut prevout = Vec::new();
        txin.previous_output.consensus_encode(&mut prevout)?;
        debug!("input prevout: {:?}", prevout.to_hex_string(Case::Lower));
        components.push(prevout);
        let mut amount = Vec::new();
        previous_output.value.consensus_encode(&mut amount)?;
        debug!("input amount: {:?}", amount.to_hex_string(Case::Lower));
        components.push(amount);
        let mut script_pubkey = Vec::new();
        previous_output
            .script_pubkey
            .consensus_encode(&mut script_pubkey)?;
        debug!(
            "input script_pubkey: {:?}",
            script_pubkey.to_hex_string(Case::Lower)
        );
        components.push(script_pubkey);
        let mut sequence = Vec::new();
        txin.sequence.consensus_encode(&mut sequence)?;
        debug!("input sequence: {:?}", sequence.to_hex_string(Case::Lower));
        components.push(sequence);
    } else {
        let mut input_idx = Vec::new();
        (input_index as u32).consensus_encode(&mut input_idx)?;
        debug!("input index: {:?}", input_idx.to_hex_string(Case::Lower));
        components.push(input_idx);
    }

    // If an annex is present (the lowest bit of spend_type is set):
    //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
    //      includes the mandatory 0x50 prefix.
    if spec.annex {
        if let Some(annex) = annex {
            let mut encoded_annex = Vec::new();
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut encoded_annex)?;
            debug!("annex: {:?}", encoded_annex.to_hex_string(Case::Lower));
            components.push(encoded_annex);
        }
    }

    // * Data about this output:
    // If hash_type & 3 equals SIGHASH_SINGLE:
    //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
    if spec.single_output && sighash == TapSighashType::Single {
        let mut encoded_single_output = Vec::new();
        let mut enc = sha256::Hash::engine();
        tx.output
            .get(input_index)
            .ok_or(Error::SingleWithoutCorrespondingOutput {
                index: input_index,
                outputs_size: tx.output.len(),
            })?
            .consensus_encode(&mut enc)?;
        let hash = sha256::Hash::from_engine(enc);
        hash.consensus_encode(&mut encoded_single_output)?;
        debug!(
            "single_output: {:?}",
            encoded_single_output.to_hex_string(Case::Lower)
        );
        components.push(encoded_single_output);
    }

    //     if (scriptpath):
    //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
    //         ss += bytes([0])
    //         ss += struct.pack("<i", codeseparator_pos)

    if spec.scriptpath {
        #[allow(non_snake_case)]
        let KEY_VERSION_0 = 0u8;

        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            let mut encoded_leaf_hash = Vec::new();
            hash.as_byte_array()
                .consensus_encode(&mut encoded_leaf_hash)?;
            debug!(
                "leaf_hash: {:?}",
                encoded_leaf_hash.to_hex_string(Case::Lower)
            );
            components.push(encoded_leaf_hash);
            let mut encoded_leaf_hash = Vec::new();
            KEY_VERSION_0.consensus_encode(&mut encoded_leaf_hash)?;
            debug!(
                "leaf_ver: {:?}",
                encoded_leaf_hash.to_hex_string(Case::Lower)
            );
            components.push(encoded_leaf_hash);
            let mut encoded_leaf_hash = Vec::new();
            code_separator_pos.consensus_encode(&mut encoded_leaf_hash)?;
            debug!(
                "code_separator_pos: {:?}",
                encoded_leaf_hash.to_hex_string(Case::Lower)
            );
            components.push(encoded_leaf_hash);
        }
    }

    Ok(components)
}

pub(crate) fn compute_signature_from_components(components: &[Vec<u8>]) -> Result<[u8; 64]> {
    let sigmsg = compute_sigmsg_from_components(components)?;
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    let challenge = make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice());
    Ok(make_signature(&challenge))
}

pub(crate) fn compute_sigmsg_from_components(components: &[Vec<u8>]) -> Result<[u8; 32]> {
    debug!("creating sigmsg from components",);
    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input("TapSighash".as_bytes());
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);

    let mut serialized_tx = sha256::Hash::engine();
    serialized_tx.input(hashed_tag.as_ref());
    serialized_tx.input(hashed_tag.as_ref());

    {
        let tapsighash_engine = TapSighash::engine();
        assert_eq!(tapsighash_engine.midstate(), serialized_tx.midstate());
    }

    for component in components.iter() {
        serialized_tx.input(component.as_slice());
    }

    let tagged_hash = sha256::Hash::from_engine(serialized_tx);
    Ok(tagged_hash.into_32())
}

pub(crate) fn compute_challenge(sigmsg: &[u8; 32]) -> [u8; 32] {
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice())
}

fn make_signature(challenge: &[u8; 32]) -> [u8; 64] {
    let mut signature: [u8; 64] = [0; 64];
    signature[0..32].copy_from_slice(G_X.as_slice());
    signature[32..64].copy_from_slice(challenge);
    signature
}

fn make_tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    // make a hashed_tag which is sha256(tag)
    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input(tag);
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);

    // compute the message to be hashed. It is prefixed with the hashed_tag twice
    // for example, hashed_tag || hashed_tag || data
    let mut message = sha256::Hash::engine();
    message.input(hashed_tag.as_ref());
    message.input(hashed_tag.as_ref());
    message.input(data);
    let message = sha256::Hash::from_engine(message);
    message.into_32()
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
