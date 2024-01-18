use std::str::FromStr;
use bitcoin::{Address, Amount, OutPoint, Script, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::key::{UntweakedKeypair};
use bitcoin::Network::Regtest;
use bitcoin::opcodes::all::{OP_CAT, OP_CHECKSIG, OP_EQUAL, OP_SHA256};

use bitcoin::secp256k1::{Secp256k1, ThirtyTwoByteHash};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use schnorr_fun::{Message, Signature};
use secp256kfun::G;
use secp256kfun::marker::Public;

fn main() {
    println!("lets do something with cat... or something");

    let secp = Secp256k1::new();

    let key_pair = UntweakedKeypair::from_seckey_slice(&secp, &[0x01; 32]).unwrap();

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
            txid: "7acaf065eea092ec4fd88309570f2dc462711db952b1d14a57f5747f0e61c2a9".parse().expect("txid should be valid"),
            vout: 0,
        },
        script_sig: Default::default(),
        sequence: Default::default(),
        witness: Default::default(),
    };

    // txin.witness.push("hello".as_bytes().to_vec());
    // txin.witness.push("world".as_bytes().to_vec());
    txin.witness.push(script.clone().to_bytes());
    txin.witness.push(&taproot_spend_info.control_block(&(script.clone(), LeafVersion::TapScript)).expect("control block should work").serialize());


    let amount = 99_900_000;
    let mut locktime = 0;
    let mut spend_tx;

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
                    script_pubkey: Address::from_str("bcrt1pjjnkdu03tdrc6zejsyljxn58wh5q4qsrmahvl20vryz29p39ka8q39wpwc").expect("address should be valid").assume_checked().script_pubkey(),
                }
            ],
        };

        let mut sighash_cache = SighashCache::new(&spend_tx);
        let txout = TxOut {
            script_pubkey: taproot_address.script_pubkey(),
            value: Amount::from_sat(100_000_000), // we're always testing with 1 BTC.
        };
        let sighash = sighash_cache.taproot_script_spend_signature_hash(0, &Prevouts::All(&[txout]), TapLeafHash::from_script(&script, LeafVersion::TapScript), TapSighashType::Default).unwrap();
        let schnorr = schnorr_fun::test_instance!();
        let R = G.into_point_with_even_y().0;
        let P = G.into_point_with_even_y().0;
        let sighash_bytes = sighash.clone().into_32();
        let message: Message<Public> = Message::raw(&sighash_bytes);
        let challenge = schnorr.challenge(&R, &P, message);

        let signature = Signature {
            s: challenge.into(),
            R,
        };
        // println!("challenge: {}", challenge.to_string());
        if challenge.to_bytes()[31] == 0x01 {
            println!("Found a challenge with a 1 at the end!");
            println!("locktime is {}", locktime);
            println!("Here's the challenge: {}", challenge.to_string());
            println!("Here's the signature: {}", signature.to_string());
            break;
        }
        locktime += 1;
    }




    let mut serialized_tx = Vec::new();
    spend_tx.consensus_encode(&mut serialized_tx).unwrap();

    println!("Serialized transaction (hex): {}", hex::encode(serialized_tx));
}



fn hello_world_script() -> ScriptBuf {
    let hashed_data = hex::decode("936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af").unwrap();
    let hash_bytes: [u8;32] = hashed_data.try_into().unwrap();

    let mut builder = Script::builder();
    builder = builder.push_opcode(OP_CAT)
        .push_opcode(OP_SHA256)
        .push_slice(hash_bytes)
        .push_opcode(OP_EQUAL);
    builder.into_script()
}

fn checksig_script() -> ScriptBuf {
    let mut builder = Script::builder();
    builder = builder.push_opcode(OP_CHECKSIG);
    builder.into_script()
}