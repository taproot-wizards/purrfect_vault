#!/usr/bin/env bash

set -e


echo "Building a copy of Bitcoin Core with a OP_CAT active..."

git clone --depth 1 --branch dont-success-cat git@github.com:rot13maxi/bitcoin.git bitcoin-core-cat || true

pushd bitcoin-core-cat
./autogen.sh
./configure --without-tests --disable-bench
make -j4
popd