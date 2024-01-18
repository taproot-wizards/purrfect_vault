use std::str::FromStr;
use bitcoin::{Address, Amount, Network, OutPoint, Script, ScriptBuf, TapLeafHash, TapSighash, TapSighashType, Transaction, TxIn, TxOut};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::key::{UntweakedKeypair};
use bitcoin::Network::Regtest;
use bitcoin::opcodes::all::{OP_2DUP, OP_CAT, OP_CHECKSIGVERIFY, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_ROT, OP_SHA256};

use bitcoin::secp256k1::{Secp256k1, ThirtyTwoByteHash};
use bitcoin::sighash::{Annex, Error, Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use schnorr_fun::{Message, Signature};
use secp256kfun::G;
use secp256kfun::marker::Public;
use anyhow::Result;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::hex::{Case, DisplayHex};
use bitcoincore_rpc::{Auth, Client};
use lazy_static::lazy_static;

lazy_static!(
    static ref G_X: [u8; 32] = G.into_point_with_even_y().0.to_xonly_bytes();
);

fn main() -> Result<()> {
    println!("lets do something with cat... or something");

    let client = get_rpc_client(Regtest, Auth::None)?;

    let secp = Secp256k1::new();

    let key_pair = UntweakedKeypair::from_seckey_slice(&secp, &[0x01; 32])?;

    let script = checksig_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("adding a tapscript should work")
        .finalize(&secp, key_pair.x_only_public_key().0)
        .expect("finalizing a taproot should work");

    let taproot_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), Regtest);
    println!("taproot address: {}", taproot_address);

    println!("ok, lets spend it");

    let mut txin = TxIn {
        previous_output: OutPoint {
            txid: "be52d27ab4ebed165cf3128332a12574c81f23eb733ebc879e39d3dc8a6a59a0".parse().expect("txid should be valid"),
            vout: 0,
        },
        script_sig: Default::default(),
        sequence: Default::default(),
        witness: Default::default(),
    };


    let amount = 99_900_000;
    let mut locktime = 0;
    let mut spend_tx;
    let mut final_signature = [0u8; 64];
    let mut final_challenge = [0u8; 32];

    loop {
        spend_tx = Transaction {
            lock_time: LockTime::from_height(locktime).unwrap(),
            version: Version::TWO,
            input: vec![
                txin.clone()
            ],
            output: vec![
                TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: Address::from_str("bcrt1py9ccnmdrk9z4ylvgt68htyazmssvsz0cdzjcm3p3m75dsc0j203q37qzse").expect("address should be valid").assume_checked().script_pubkey(),
                }
            ],
        };

        let mut sighash_cache = SighashCache::new(&spend_tx);
        let txout = TxOut {
            script_pubkey: taproot_address.script_pubkey(),
            value: Amount::from_sat(100_000_000), // we're always testing with 1 BTC.
        };
        let sighash = sighash_cache.taproot_script_spend_signature_hash(0, &Prevouts::All(&[txout.clone()]), TapLeafHash::from_script(&script, LeafVersion::TapScript), TapSighashType::Default).unwrap();
        let computed_sighash = sighash.clone().into_32();
        let my_computed_sighash = compute_sigmsg(&spend_tx, 0, &[txout], None, TapLeafHash::from_script(&script, LeafVersion::TapScript), TapSighashType::Default).unwrap();
        assert_eq!(computed_sighash, my_computed_sighash);
        let schnorr = schnorr_fun::test_instance!();
        let R = G.into_point_with_even_y().0;
        let P = G.into_point_with_even_y().0;
        assert_eq!(R, P);
        let sighash_bytes = sighash.clone().into_32();
        let message: Message<Public> = Message::raw(&sighash_bytes);
        let challenge = schnorr.challenge(&R, &P, message);
        let my_challenge = compute_challenge(&my_computed_sighash);
        assert_eq!(challenge.to_bytes(), my_challenge);
        //println!("challenge looks good!");

        let signature = Signature {
            s: challenge.into(),
            R,
        };
        let my_signature = make_signature(&my_challenge);
        assert_eq!(signature.to_bytes(), my_signature);
        //println!("signature looks good!");
        // println!("challenge: {}", challenge.to_string());
        if challenge.to_bytes()[31] == 0x01 {
            println!("Found a challenge with a 1 at the end!");
            println!("locktime is {}", locktime);
            println!("Here's the challenge: {}", challenge.to_string());
            println!("Here's the signature: {}", signature.to_string());
            println!("Here's G_X: {}", G_X.to_hex_string(Case::Lower));
            final_signature = signature.to_bytes();
            final_challenge = challenge.to_bytes();
            break;
        }
        locktime += 1;
    }


    let mut maliated_challenge = [0u8; 31];
    maliated_challenge.copy_from_slice(&final_challenge[0..31]);

    //txin.witness.push(final_signature.to_vec());
    txin.witness.push(G_X.as_slice());
    txin.witness.push(maliated_challenge.to_vec());

    println!("length of G_X: {}", G_X.as_slice().len());
    txin.witness.push(script.clone().to_bytes());
    txin.witness.push(&taproot_spend_info.control_block(&(script.clone(), LeafVersion::TapScript)).expect("control block should work").serialize());
    spend_tx.input.first_mut().unwrap().witness = txin.witness.clone();

    let mut serialized_tx = Vec::new();
    spend_tx.consensus_encode(&mut serialized_tx).unwrap();

    println!("Serialized transaction (hex): {}", hex::encode(serialized_tx));

    Ok(())
}


fn hello_world_script() -> ScriptBuf {
    let hashed_data = hex::decode("936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af").unwrap();
    let hash_bytes: [u8; 32] = hashed_data.try_into().unwrap();

    let mut builder = Script::builder();
    builder = builder.push_opcode(OP_CAT)
        .push_opcode(OP_SHA256)
        .push_slice(hash_bytes)
        .push_opcode(OP_EQUAL);
    builder.into_script()
}


// 2DUP CAT ROT DUP <G> EQUALVERIFY CHECKSIG
fn checksig_script() -> ScriptBuf {
    let mut builder = Script::builder();
    builder = builder
        .push_opcode(OP_2DUP)
        .push_int(0x02)
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_ROT)
        .push_opcode(OP_DUP)
        .push_slice(*G_X)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIGVERIFY);
    builder.into_script()
}

fn compute_sigmsg<S: Into<TapLeafHash>>(tx: &Transaction,
                                        input_index: usize,
                                        prevouts: &[TxOut],
                                        annex: Option<Annex>,
                                        leaf_hash: S,
                                        sighash_type: TapSighashType) -> Result<[u8;32]> {

    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input("TapSighash".as_bytes());
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);


    let mut serialized_tx = sha256::Hash::engine();
    serialized_tx.input(hashed_tag.as_ref());
    serialized_tx.input(hashed_tag.as_ref());

    {
        let tapsighash_engine = TapSighash::engine();
        assert_eq!(tapsighash_engine.midstate(), serialized_tx.midstate());
        // println!("Same midstate");
    }

    let leaf_hash_code_separator = Some((leaf_hash.into(), 0xFFFFFFFFu32));

    // all this serialization code was lifted from bitcoin-0.31.1/src/crypto/sighash.rs:597 and
    // then violently hacked up

    let (sighash, anyone_can_pay) = match sighash_type {
        TapSighashType::Default => (bitcoin::TapSighashType::Default, false),
        TapSighashType::All => (bitcoin::TapSighashType::All, false),
        TapSighashType::None => (bitcoin::TapSighashType::None, false),
        TapSighashType::Single => (bitcoin::TapSighashType::Single, false),
        TapSighashType::AllPlusAnyoneCanPay => (TapSighashType::All, true),
        TapSighashType::NonePlusAnyoneCanPay => (bitcoin::TapSighashType::None, true),
        TapSighashType::SinglePlusAnyoneCanPay => (TapSighashType::Single, true),
    };

    // epoch
    0u8.consensus_encode(&mut serialized_tx)?;

    // * Control:
    // hash_type (1).
    (sighash_type as u8).consensus_encode(&mut serialized_tx)?;

    // * Transaction Data:
    // nVersion (4): the nVersion of the transaction.
    tx.version.consensus_encode(&mut serialized_tx)?;

    // nLockTime (4): the nLockTime of the transaction.
    tx.lock_time.consensus_encode(&mut serialized_tx)?;

    // If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
    //     sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
    //     sha_amounts (32): the SHA256 of the serialization of all spent output amounts.
    //     sha_scriptpubkeys (32): the SHA256 of the serialization of all spent output scriptPubKeys.
    //     sha_sequences (32): the SHA256 of the serialization of all input nSequence.
    if !anyone_can_pay {
        {
            let mut buffer = Vec::new();
            for prevout in tx.input.iter() {
                prevout.previous_output.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut serialized_tx).unwrap();
        }
        {
            let mut buffer = Vec::new();
            for p in prevouts {
                p.value.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut serialized_tx).unwrap();
        }
        {
            let mut buffer = Vec::new();
            for p in prevouts {
                p.script_pubkey.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut serialized_tx).unwrap();
        }
        {
            let mut buffer = Vec::new();
            for i in tx.input.iter() {
                i.sequence.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut serialized_tx).unwrap();
        }
    }

    // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
    //     sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
    if sighash != TapSighashType::None && sighash != TapSighashType::Single {
        let mut buffer = Vec::new();
        for o in tx.output.iter() {
            o.consensus_encode(&mut buffer).unwrap();
        }
        let hash = sha256::Hash::hash(&buffer);
        hash.consensus_encode(&mut serialized_tx).unwrap();
        // tx.output.iter().for_each(|output| { output.consensus_encode(&mut serialized_tx).unwrap(); });
    }

    // * Data about this input:
    // spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0
    // if no annex is present, or 1 otherwise
    let mut spend_type = 0u8;
    if annex.is_some() {
        spend_type |= 1u8;
    }
    if leaf_hash_code_separator.is_some() {
        spend_type |= 2u8;
    }
    spend_type.consensus_encode(&mut serialized_tx)?;

    // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
    //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
    //      amount (8): value of the previous output spent by this input.
    //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
    //      nSequence (4): nSequence of this input.
    if anyone_can_pay {
        let txin =
            &tx.input.get(input_index).ok_or(Error::IndexOutOfInputsBounds {
                index: input_index,
                inputs_size: tx.input.len(),
            })?;
        let previous_output = prevouts.get(input_index).ok_or(Error::IndexOutOfInputsBounds {
            index: input_index,
            inputs_size: prevouts.len(),
        })?;
        txin.previous_output.consensus_encode(&mut serialized_tx)?;
        previous_output.value.consensus_encode(&mut serialized_tx)?;
        previous_output.script_pubkey.consensus_encode(&mut serialized_tx)?;
        txin.sequence.consensus_encode(&mut serialized_tx)?;
    } else {
        (input_index as u32).consensus_encode(&mut serialized_tx)?;
    }

    // If an annex is present (the lowest bit of spend_type is set):
    //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
    //      includes the mandatory 0x50 prefix.
    if let Some(annex) = annex {
        let mut enc = sha256::Hash::engine();
        annex.consensus_encode(&mut enc)?;
        let hash = sha256::Hash::from_engine(enc);
        hash.consensus_encode(&mut serialized_tx)?;
    }

    // * Data about this output:
    // If hash_type & 3 equals SIGHASH_SINGLE:
    //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
    if sighash == TapSighashType::Single {
        let mut enc = sha256::Hash::engine();
        tx
            .output
            .get(input_index)
            .ok_or(Error::SingleWithoutCorrespondingOutput {
                index: input_index,
                outputs_size: tx.output.len(),
            })?
            .consensus_encode(&mut enc)?;
        let hash = sha256::Hash::from_engine(enc);
        hash.consensus_encode(&mut serialized_tx)?;
    }

    //     if (scriptpath):
    //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
    //         ss += bytes([0])
    //         ss += struct.pack("<i", codeseparator_pos)

    let KEY_VERSION_0 = 0u8;

    if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
        hash.as_byte_array().consensus_encode(&mut serialized_tx)?;
        KEY_VERSION_0.consensus_encode(&mut serialized_tx)?;
        code_separator_pos.consensus_encode(&mut serialized_tx)?;
    }

    let tagged_hash = sha256::Hash::from_engine(serialized_tx);

    Ok(tagged_hash.into_32())
}

fn compute_challenge(sigmsg: &[u8;32]) -> [u8;32] {
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice())
}

fn make_signature(challenge: &[u8;32]) -> [u8; 64] {
    let mut signature: [u8; 64] = [0; 64];
    signature[0..32].copy_from_slice(&G_X.as_slice());
    signature[32..64].copy_from_slice(challenge);
    signature
}

fn make_tagged_hash(tag: &[u8], data: &[u8]) -> [u8;32] {

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

fn get_rpc_client(network: Network, auth: Auth) -> Result<Client> {
    let url = match network {
        Network::Bitcoin => "http://localhost:8332",
        Network::Testnet => "http://localhost:18332",
        Network::Regtest => "http://localhost:18443",
        Network::Signet => "http://localhost:38332",
        _ => {unreachable!("Network not supported")}
    };
    Ok(Client::new(url, auth)?)
}