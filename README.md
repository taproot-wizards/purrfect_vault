# A Prototype Vault using CAT

## What?

This repo contains a demo of an onchain Bitcoin Vault using OP_CAT to create a covenant that allows for a multi-step withdrawal process to be validated onchain.

Basically, you will have a special addressed called the vault. Coins from his address can **only** be spent in the following way:

- You can initiate a withdrawal from the vault by creating a transaction with 2 inputs (the vault as the first input, and a fee-paying second input), and two outputs (the vault with the amount to be withdrawn, and the target address with a dust amount).
- Once the vault is in the Triggered state, you can either:
  - Cancel the withdrawal by creating a transaction with 2 inputs (the vault as the first input, and a fee-paying second input), and one output (the vault with the amount that was previously withdrawn).
  - Complete the withdrawal after a relative timelock of 20 blocks by creating a transaction with 2 inputs (the withdrawal as the first input, and a fee-paying second input), and one output (the target address with the amount that was previously withdrawn).

There is no other way to spend these coins. If you try to spend them in any other way, the transaction will be invalid.

## Vault Contract Construction

[BIP341 signature validation has us create a message called a `SigMsg`](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message) that contains commitments to the fields of a transaction. That SigMsg is then used as the message in constructing a Schnorr signature. 
[Andrew Polestra observed](https://medium.com/blockstream/cat-and-schnorr-tricks-i-faf1b59bd298) that if you set the Public Key (P) and Public Nonce Commitment (R) to the generator point (G), then the s value of the resulting Schnorr signature will be equal to the SigMsg + 1. 
We are using that technique in order to allow for transaction introspection by passing in the SigMsg components as witness data, and then using OP_CAT to construct the SigMsg on the stack. 
We then construct the tagged hashes specified in BIP341, and eventually CAT on an extra G to serve as the R component of the signature. Then we call CHECKSIG to validate the signature. 
If it is valid, then it means we've constructed the SigMsg correctly, and the transaction is valid.

We use that in a few different ways in this demo.

All the scripts are commented and in the `src/vault/script.rs` file.


### Trigger Withdrawal
- Inputs
  1. contract input
  2. fee-paying input
- Outputs
  1. Contract output with amount to be withdrawn
  2. Target address with dust amount

We use the CAT-checksig technique to validate that the amount and scriptpubkey of the first input and first output are the same.
We enforce that the second output is amount is exactly 546 sats, but we do not place any restrictions on the scriptpubkey. 
We also enforce that there are two inputs and two outputs.


### Complete Withdrawal
- Inputs
  1. Withdrawal input
  2. Fee-paying input
- Outputs
  1. Destination output with contract amount

This is probably the most interesting transaction. We want to enforce that the first output has the scriptpubkey that matches the second output of the **trigger** transaction.
To validate this, we pass in the serialized transaction data (version, inputs, outputs, locktime) as witness data, do some manipulation of the outputs, and then hash this previous-transaction
data twice to get the TXID. We then validate that the first input of the current transaction is the same as the TXID of the previous transaction with vout=0. This 
ensures that the first input of the current transaction is the same as the first output of the previous transaction, and lets us *inspect the state of the previous transaction*.

The first output of this transaction is enforced to be the scriptpubkey of the second output of the trigger, and the amount is enforced to be the same as the amount of the first output of the trigger.
The second input is unencumbered and used for change. 

There is also a plain-old CSV relative timelock of 20 blocks on the first input.


### Cancel Withdrawal
- Inputs
  1. Any contract input
  2. Fee-paying input
- Outputs
  1. Contract output

This is the simplest transaction. We just enforce that there are two inputs and one output, and that the first input is the same as the first output.

## Limitations and Considerations

All the vault operations spend one vault input and create one vault output. This is a limitation of the current implementation. 
If you naively allow spending multiple vault inputs (to batch withdrawals or to consolidate vaults) or outputs (to allow partial withdrawals), 
you open yourself up to attacks where an adversary can spend vault inputs to fees. What you want is to be able to validate that all the vault 
input amounts add up to the vault output amounts. For that we need either 64-bit arithmetic (which should be doable with CAT 
by doing a mini big-num implementation), or you need to have different tapscripts with pre-defined amounts, or you just only use vaults with 32-bit amounts. 
I think doing 64-bit add in CAT is the most interesting, but I haven't done it yet.

There are not currently any (normal) signature checks in the vault scripts. There isn't a reason they can't be there. It would actually be very easy:
commit to a pubkey, push a signature in the witness, checksig. I just didn't do it. The point of the demo was to play with transaction introspection.
If you want to add signature checking, I'm more than happy to review the PR!

Right now the vault always spends back to itself when you cancel. In real life you might want to have it go to a different script with different keys. 
That would be an easy change to make, but was elided for simplicity in this demo.

The Schnorr signature that you create on the stack is equal to SigMsg + 1. You need to grind the transaction data to get the right last bytes of the signature.
I use a combination of grinding the low-order bits of the Locktime and the Sequence number of the last input in order to get a signature with the last byte. For my construction,
that was fine. For other constructions, you might need to grind the last byte of the signature in a different way.

Re-building a TXID on the stack to introspect previous transactions was actually easier than I expected. Two wrinkles I ran into were:
- There is a standardness rule on witness stack items (80 bytes). I had to split the outputs of the previous transaction into two chunks in order to get them on the stack and then glue it together with OP_CAT.
- There is a consensus limit on stack item size (520 bytes). I had to be careful to not exceed that limit when I was building the TXID. Because my trigger transaction is tightly constrained, it was ok. If I wanted to inspect the previous state of an arbitrary transaction, I would have to be more careful.

## How to run it

You will need to be able to build bitcoin-core. Go get set up with a C++ compiler for your platform. Those directions are outside the scope of this document.

From there, there are some scripts and helpers in this project to build a copy of bitcoin-core that has OP_CAT enabled, and then you can use [Just](https://github.com/casey/just) as a command runner to build and run the vault demo.

If you have a rust toolchain installed, and don't want to use `just`, you can also just poke around yourself. Choose your own adventure!

### Have nothing installed?
This project can use [Hermit](https://cashapp.github.io/hermit/) to provide a copy of [Just](https://github.com/casey/just) and the rust toolchain. So you don't have to install anything.

To activate the hermit environment, run `source bin/activate-hermit` and it will set up a shell environment with the tools you need. 

Run `just bootstrap` to checkout and build a copy of bitcoin-core with OP_CAT enabled. It will be placed in a directory called `bitcoin-core-cat` in the root of the project.
It will also build the `purrfect_vault` binary, which is the demo.

Proceed to the "Running the demo" section.

### Have `just` and `cargo` already installed?
You're all set!

Run `just bootstrap` to checkout and build a copy of bitcoin-core with OP_CAT enabled. It will be placed in a directory called `bitcoin-core-cat` in the root of the project.
It will also build the `purrfect_vault` binary, which is the demo. 

Proceed to the "Running the demo" section.

### Running the demo

Follow these steps to create a vault that is configured to allow a withdrawal after 20 blocks. You will try to "steal" from this vault, see that a theft is in-progress and foil the theft. Then you will trigger a new withdrawal and complete it.

These steps use `just` as a command wrapper around the `purrfect_vault` binary to set the log level. If you don't want to use `just`, you can run the `purrfect_vault` binary directly from the `target/release/` directory with the same arguments, or pass `-h` to see options.

1. Run a CAT-enabled bitcoind in regtest mode. This will be done either using `just bootstrap`, or you can run it with `just run-bitcoind`, or run it yourself with the `bitcoin-core-cat` binary that was built.
2. Start by running `just deposit`. This will create a miner wallet, mine some coins, and then create a new vault and deposit some coins into it.
3. Run `just status` to see the status of the vault.
4. Try to steal from the vault with `just steal`. This will generate an address from the miner wallet and initiate a withdrawal to it. Alternatively you can execute the `purrfect_vault` binary with the `steal` subcommand and pass an address of your choosing. It will also mine a block to confirm the transaction
5. Run `just status` to see the status of the vault and see that the on-chain state of the vault is that it's in a withdrawal-triggered state, but that the internal state of the wallet is that no withdrawal is in-progress, so it looks like a theft is happening! oh no!
6. Foil the theft with `just cancel`. This will send the coins back to the vault and mine a block to confirm the transaction.
4. Initiate a withdrawal from the vault with `just trigger`. This will generate an address from the miner wallet and initiate a withdrawal to it. Alternatively you can execute the `purrfect_vault` binary with the `trigger` subcommand and pass an address of your choosing. It will also mine a block to confirm the transaction
5. Run `just status` to see the status of the vault and see that the vault is in the Triggered state.
6. Complete the withdrawal with `just complete`. This will mine 20 blocks to satisfy the timelock, send the withdrawal-completion transaction, and then a block to confirm the transaction.


## FAQ

### Wow. This is a lot of spaghetti.

That's not a question. Also, yes. This was hacked together and then I released it. It needs some good honest refactoring. PR's welcome. 

### Why doesn't this support [feature]?

I wanted to see if I could get a vault working with CAT. I didn't want to get bogged down in the details of a full-featured vault. I'm sure there are many features that are missing.
The things that I wanted to explore were:
- Can you do input/output validation with CAT?
- Can you partially validate inputs/outputs with CAT (i.e. check the amount, but not the scriptpubkey)?
- Can you do a multi-step process with CAT (i.e. deposit, then withdrawal)? Either by inspecting the transaction history, or by having a multi-step process in a single transaction.

We're able to do all of these things with CAT, so I'm happy with the results.

### How big are these transactions? These script look gnarly!
- Trigger: 321.75 vB, 1.29 kWU
- Cancel: 289.25 vB, 1.16 kWU
- Complete: 320 vB, 1.28 kWU

They'd get a little bigger with a signature check, but not much.

### Seems like we could get rid of some of these CATs by just concatenating elements before they go into the witness. Why don't we do that?
Yep! There is quite a bit of script optimization that could be done. I have a generic function for getting the SigMsg components and I just use that everywhere.

### Can I contribute?
Yes! PR's welcome. I'm happy to review and help you get your PR merged. I'm also happy to help you get set up with the project if you're having trouble. Just ask!