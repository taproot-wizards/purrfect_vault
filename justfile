#################
# Demo Commands #
#################

status:
    RUST_LOG=info ./target/release/purrfect_vault status

deposit:
    RUST_LOG=info ./target/release/purrfect_vault deposit

trigger:
    RUST_LOG=info ./target/release/purrfect_vault trigger $({{ bcli }} -rpcwallet=miner getnewaddress)

steal:
    RUST_LOG=info ./target/release/purrfect_vault steal $({{ bcli }} -rpcwallet=miner getnewaddress)

cancel:
    RUST_LOG=info ./target/release/purrfect_vault cancel

complete:
    RUST_LOG=info ./target/release/purrfect_vault complete


###################################
# Build and boostrapping commands #
###################################

bitcoin_datadir := "./bitcoin-data"
bcli := "./bitcoin-core-cat/src/bitcoin-cli -regtest -rpcuser=user -rpcpassword=password"

start-bitcoind *ARGS:
    mkdir -p {{ bitcoin_datadir }}
    ./bitcoin-core-cat/src/bitcoind -regtest -timeout=15000 -server=1 -txindex=1 -rpcuser=user -rpcpassword=password -datadir={{bitcoin_datadir}} {{ ARGS }}

stop-bitcoind:
    {{ bcli }} stop

clean-bitcoin-data:
    rm -rf {{ bitcoin_datadir }}

build:
    cargo build --release

bootstrap:
    bash ./scripts/build_bitcoincore.sh
    just build
    just clean-bitcoin-data
    just start-bitcoind


