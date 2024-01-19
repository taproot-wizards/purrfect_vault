use bitcoin::{Script, ScriptBuf};
use bitcoin::opcodes::all::{OP_2DUP, OP_CAT, OP_CHECKSIGVERIFY, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_ROT, OP_SHA256};
use crate::G_X;

pub(crate) fn hello_world_script() -> ScriptBuf {
    let hashed_data = hex::decode("936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af").unwrap();
    let hash_bytes: [u8; 32] = hashed_data.try_into().unwrap();

    let mut builder = Script::builder();
    builder = builder.push_opcode(OP_CAT)
        .push_opcode(OP_SHA256)
        .push_slice(hash_bytes)
        .push_opcode(OP_EQUAL);
    builder.into_script()
}


pub(crate) fn basic_sig_assert() -> ScriptBuf {
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