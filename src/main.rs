use std::str::FromStr;
use bitcoin::{Address, Amount, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::key::{UntweakedKeypair};
use bitcoin::Network::Regtest;
use bitcoin::opcodes::all::{OP_CAT, OP_EQUAL, OP_SHA256};

use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;

fn main() {
    println!("lets do something with cat... or something");

    let secp = Secp256k1::new();

    let key_pair = UntweakedKeypair::from_seckey_slice(&secp, &[0x01; 32]).unwrap();

    let script = hello_world_script();

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
            txid: "be66b28a6137b456b241890de35ba61c9e86c235c277c8f0f262df923dfa55b6".parse().expect("txid should be valid"),
            vout: 0,
        },
        script_sig: Default::default(),
        sequence: Default::default(),
        witness: Default::default(),
    };

    txin.witness.push("hello".as_bytes().to_vec());
    txin.witness.push("world".as_bytes().to_vec());
    txin.witness.push(script.clone().to_bytes());
    txin.witness.push(&taproot_spend_info.control_block(&(script, LeafVersion::TapScript)).expect("control block should work").serialize());


    let spend_tx = Transaction {
        lock_time: LockTime::ZERO,
        version: Version::TWO,
        input: vec![
            txin
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(99_900_000),
                script_pubkey: Address::from_str("bcrt1qhdzevd9wzu7egy3l0jpmthmz3dkj72062uchsg").expect("address should be valid").assume_checked().script_pubkey(),
            }
        ],
    };

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