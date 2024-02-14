use crate::{G_X, vault};
use bitcoin::opcodes::all::{OP_2DUP, OP_CAT, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_HASH256, OP_ROLL, OP_ROT, OP_SHA256, OP_SWAP, OP_TOALTSTACK};
use bitcoin::{Script, ScriptBuf, Sequence};
use bitcoin::script::Builder;
use crate::vault::contract::{BIP0340_CHALLENGE_TAG, DUST_AMOUNT, TAPSIGHASH_TAG};
use lazy_static::lazy_static;

pub(crate) fn vault_trigger_withdrawal() -> ScriptBuf {
    let mut builder = Script::builder();
    // The witness program needs to have the signature components except the outputs and the pre_scriptpubkeys and pre_amounts,
    // followed by the target scriptpubkey (the amount for that output will be fixed)
    // followed by the vault output amount, then the vault scriptpubkey,
    // followed by the fee amount, then the fee-paying scriptpubkey
    // and finally the mangled signature
    builder = builder
        .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
        .push_opcode(OP_TOALTSTACK) // push the fee-paying scriptpubkey to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the fee amount to the alt stack
        .push_opcode(OP_2DUP) // make a second copy of the vault scriptpubkey and amount so we can check input = output
        .push_opcode(OP_TOALTSTACK)// push the first copy of the vault scriptpubkey to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the first copy of the vault amount to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the second copy of the vault scriptpubkey to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the second copy of the vault amount to the alt stack
        .push_opcode(OP_TOALTSTACK) // move the target scriptpubkey to the alt stack
        // start with encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // input index
        .push_opcode(OP_CAT) // spend type
        .push_slice(*DUST_AMOUNT) // push the dust amount for the target output
        .push_opcode(OP_FROMALTSTACK)// get the target scriptpubkey
        .push_opcode(OP_CAT) // cat the dust amount and the target scriptpubkey
        .push_opcode(OP_FROMALTSTACK)// get the output amount
        .push_opcode(OP_FROMALTSTACK) // get the second copy of the scriptpubkey
        .push_opcode(OP_CAT) // cat the output amount and the second copy of the scriptpubkey
        .push_opcode(OP_SWAP)// put the outputs in the right order (vault then target)
        .push_opcode(OP_CAT) // cat the vault output and target output together
        .push_opcode(OP_SHA256) // hash the output
        .push_opcode(OP_SWAP) // move the hashed encoded outputs below our working sigmsg
        .push_opcode(OP_CAT) // outputs
        .push_opcode(OP_CAT) // prev sequences
        .push_opcode(OP_FROMALTSTACK) // get the other copy of the vault amount
        .push_opcode(OP_FROMALTSTACK) // get the other copy of the vault scriptpubkey
        .push_opcode(OP_FROMALTSTACK)// get the fee amount
        .push_opcode(OP_FROMALTSTACK) // get the fee-paying scriptpubkey
        .push_opcode(OP_SWAP) // move the fee-paying scriptpubkey below the fee amount
        .push_opcode(OP_TOALTSTACK)// move fee amount to alt stack
        .push_opcode(OP_CAT) // cat the vault scriptpubkey fee-paying scriptpubkey
        .push_opcode(OP_SWAP)// move the vault amount to the top of the stack
        .push_opcode(OP_TOALTSTACK) // move the vault amount to the alt stack
        .push_opcode(OP_SHA256) // hash the scriptpubkeys, should now be consensus encoding
        .push_opcode(OP_SWAP) // move the hashed encoded scriptpubkeys below our working sigmsg
        .push_opcode(OP_CAT) // prev scriptpubkeys
        .push_opcode(OP_FROMALTSTACK)// get the vault amount
        .push_opcode(OP_FROMALTSTACK) // get the fee amount
        .push_opcode(OP_CAT) // cat the vault amount and the fee amount
        .push_opcode(OP_SHA256) // hash the amounts
        .push_opcode(OP_SWAP) // move the hashed encoded amounts below our working sigmsg
        .push_opcode(OP_CAT) // prev amounts
        .push_opcode(OP_CAT) // prevouts
        .push_opcode(OP_CAT) // lock time
        .push_opcode(OP_CAT) // version
        .push_opcode(OP_CAT) // control
        .push_opcode(OP_CAT); // epoch

    builder = add_signature_construction_and_check(builder);
    builder.into_script()
}

pub(crate) fn vault_complete_withdrawal(timelock_in_blocks: u16) -> ScriptBuf {

    // things that need to be checked:
    // timelock
    // previous transaction had the second output as a 546 sat output, address is the destination of this transaction
    // amount of the first output of that transaction is the same as the amount of the first output of this transaction



    let mut builder = Script::builder();
    // The witness program needs to have the signature components except the outputs, prevouts,
    // followed by the previous transaction version, inputs, and locktime
    // followed by vault SPK, the vault amount, and the target SPK
    // followed by the fee-paying txout
    // and finally the mangled signature
    builder = builder
//        .push_sequence(Sequence::from_height(timelock_in_blocks))
//        .push_opcode(OP_CSV) // check relative timelock on withdrawal
//        .push_opcode(OP_DROP) // drop the result
        .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
        .push_opcode(OP_TOALTSTACK) // move the fee-paying txout to the alt stack
        .push_opcode(OP_DUP) // make a second copy of the target scriptpubkey so we can use it later
        .push_opcode(OP_TOALTSTACK) // push the target scriptpubkey to the alt stack
        .push_slice(*DUST_AMOUNT) // push the dust amount for the previous tx second output
        .push_opcode(OP_SWAP) // swap the dust amount to the top of the stack
        .push_opcode(OP_CAT) // consensus-encode the second output for the previous TX
        .push_opcode(OP_SWAP) // get the vault amount to the top of the stack
        .push_opcode(OP_DUP)// make a second copy of the vault amount so we can use it later
        .push_opcode(OP_FROMALTSTACK) // get the target scriptpubkey
        .push_opcode(OP_CAT) // cat the target scriptpubkey and the vault amount.
        .push_opcode(OP_SHA256) // hash the target SPK + vault amount, this is our encoded output commitment
        .push_opcode(OP_TOALTSTACK) // move the output commitment to the alt stack
        .push_opcode(OP_SWAP) // get the vault amount to the second position on the stack
        .push_opcode(OP_ROT) // move the vault address to the top of the stack
        .push_opcode(OP_SWAP) // move the second output from the previous TX to the top of the stack
        .push_opcode(OP_CAT) // cat the vault amount and the second output from the previous TX
        .push_opcode(OP_CAT) // cat the vault address, now have all the outputs from the previous TX
        .push_int(2) // add the number of outputs from the previous TX
        .push_opcode(OP_SWAP)
        .push_opcode(OP_CAT) // cat the outputs with their count from the previous TX
        .push_opcode(OP_SWAP)// move the outputs down, and the previous TX locktime to the top of the stack
        .push_opcode(OP_CAT) // cat the previous TX locktime with the outputs
        .push_opcode(OP_CAT)// we had to split the input into two chunks
        .push_opcode(OP_CAT) // add the inputs
        .push_opcode(OP_CAT) // add the previous TX version
        .push_opcode(OP_HASH256)// hash the whole thing twice to get the TXID
        .push_opcode(OP_DUP) // make a second copy of the TXID so we can check it
        .push_opcode(OP_EQUALVERIFY) // check the TXID
        .push_opcode(OP_FROMALTSTACK) // get the output commitment
        .push_opcode(OP_SWAP) // move the output commitment below the TXID
        .push_opcode(OP_TOALTSTACK)// move the TXID to the alt stack
        .push_opcode(OP_TOALTSTACK)// move the output commitment to the alt stack

        // start with encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // input index
        .push_opcode(OP_CAT) // spend type
        .push_opcode(OP_FROMALTSTACK)// get the output commitment
        .push_opcode(OP_SWAP) // move the output commitment below our working sigmsg
        .push_opcode(OP_CAT) // outputs
        .push_opcode(OP_CAT) // prev sequences
        .push_opcode(OP_CAT) // prev scriptpubkeys
        .push_opcode(OP_CAT) // prev amounts
        .push_opcode(OP_FROMALTSTACK)// get the previous TXID from the alt stack
        .push_slice([0x00u8, 0x00u8, 0x00u8, 0x00u8]) // add the output index for the previous TX
        .push_opcode(OP_FROMALTSTACK) // get the fee-paying txout
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT) // smoosh the fee-paying txout with the previous TXID and output index
        .push_opcode(OP_SHA256)// hash the whole thing to get the prevout commitment
        .push_opcode(OP_SWAP) // move the hashed prevout commitment below our working sigmsg
        .push_opcode(OP_CAT) // prevouts
        .push_opcode(OP_CAT) // lock time
        .push_opcode(OP_CAT) // version
        .push_opcode(OP_CAT) // control
        .push_opcode(OP_CAT); // epoch
    builder = add_signature_construction_and_check(builder);
    builder.into_script()
}

pub(crate) fn vault_cancel_withdrawal() -> ScriptBuf {
    let mut builder = Script::builder();
    // The witness program needs to have the signature components except the outputs and the pre_scriptpubkeys and pre_amounts,
    // followed by the output amount, then the script pubkey,
    // followed by the fee amount, then the fee-paying scriptpubkey
    // and finally the mangled signature
    builder = builder
        .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
        .push_opcode(OP_TOALTSTACK) // push the fee-paying scriptpubkey to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the fee amount to the alt stack
        .push_opcode(OP_2DUP) // make a second copy of the vault scriptpubkey and amount so we can check input = output
        .push_opcode(OP_TOALTSTACK)// push the first copy of the vault scriptpubkey to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the first copy of the vault amount to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the second copy of the vault scriptpubkey to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the second copy of the vault amount to the alt stack
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
        .push_opcode(OP_FROMALTSTACK) // get the other copy of the vault amount
        .push_opcode(OP_FROMALTSTACK) // get the other copy of the vault scriptpubkey
        .push_opcode(OP_FROMALTSTACK)// get the fee amount
        .push_opcode(OP_FROMALTSTACK) // get the fee-paying scriptpubkey
        .push_opcode(OP_SWAP) // move the fee-paying scriptpubkey below the fee amount
        .push_opcode(OP_TOALTSTACK)// move fee amount to alt stack
        .push_opcode(OP_CAT) // cat the vault scriptpubkey fee-paying scriptpubkey
        .push_opcode(OP_SWAP)// move the vault amount to the top of the stack
        .push_opcode(OP_TOALTSTACK) // move the vault amount to the alt stack
        .push_opcode(OP_SHA256) // hash the scriptpubkeys, should now be consensus encoding
        .push_opcode(OP_SWAP) // move the hashed encoded scriptpubkeys below our working sigmsg
        .push_opcode(OP_CAT) // prev scriptpubkeys
        .push_opcode(OP_FROMALTSTACK)// get the vault amount
        .push_opcode(OP_FROMALTSTACK) // get the fee amount
        .push_opcode(OP_CAT) // cat the vault amount and the fee amount
        .push_opcode(OP_SHA256) // hash the amounts
        .push_opcode(OP_SWAP) // move the hashed encoded amounts below our working sigmsg
        .push_opcode(OP_CAT) // prev amounts
        .push_opcode(OP_CAT) // prevouts
        .push_opcode(OP_CAT) // lock time
        .push_opcode(OP_CAT) // version
        .push_opcode(OP_CAT) // control
        .push_opcode(OP_CAT); // epoch
    builder = add_signature_construction_and_check(builder);
    builder.into_script()
}

/// Assumes that the builder has the sigmsg on the stack, and the pre-computed mangled signature on top of the alt stack.
/// will construct the tagged hash and the signature and do the verification
/// Call this after you've CAT'd the epoch onto the sigmsg
pub(crate) fn add_signature_construction_and_check(builder: Builder) -> Builder {
    builder
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
        .push_opcode(OP_CHECKSIG)
}