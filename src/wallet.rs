use anyhow::{anyhow, Result};
use bitcoin::{Address, Amount, Network, OutPoint, Transaction, Txid};
use bitcoincore_rpc::{Client, RawTx, RpcApi};
use bitcoincore_rpc::jsonrpc::serde_json;
use bitcoincore_rpc::jsonrpc::serde_json::{json, Value};
use log::info;
use serde::Deserialize;

use crate::settings::Settings;

pub(crate) struct Wallet {
    pub name: String,
    client: Client,
    network: Network,
}

impl Wallet {
    pub(crate) fn new(name: &str, settings: &Settings) -> Self {
        let name = name.to_string();
        let port = match settings.network {
            Network::Bitcoin => 8332,
            Network::Testnet => 18332,
            Network::Regtest => 18443,
            Network::Signet => 38332,
            _ => {
                unreachable!("unsupported network")
            }
        };
        // TODO: allow for other authentication
        let auth = bitcoincore_rpc::Auth::UserPass(
            settings.bitcoin_rpc_username.clone(),
            settings.bitcoin_rpc_password.clone(),
        );

        //let auth = bitcoincore_rpc::Auth::CookieFile("/Users/alex/Library/Application Support/Bitcoin/regtest/.cookie".to_string().parse().unwrap());

        let client = Client::new(&format!("http://127.0.0.1:{port}"), auth.clone()).unwrap();
        if client
            .list_wallet_dir()
            .expect("Could not list wallet dir")
            .contains(&name)
        {
            if !client
                .list_wallets()
                .expect("Could not list wallets")
                .contains(&name)
            {
                info!("loading wallet {}", name);
                client.load_wallet(&name).unwrap();
            } else {
                info!("wallet {} already loaded", name);
            }
        } else {
            if !settings.create_wallets {
                panic!(
                    "wallet {} does not exist and the tool is configured to not create new wallets",
                    name
                );
            }
            info!("creating wallet {}", name);
            client
                .create_wallet(&name, None, None, None, None)
                .expect("Could not create wallet");
        }

        let url = format!("http://127.0.0.1:{}/wallet/{name}", port);
        Wallet {
            name,
            client: Client::new(&url, auth).unwrap(),
            network: settings.network,
        }
    }

    /// broadcast a raw bitcoin transaction (needs to already be network serialized)
    /// optionally specify a max fee rate in sat/vB. This function will automatically convert it to BTC/kB that bitcoin core expects
    /// returns the txid of the broadcast transaction
    pub(crate) fn broadcast_tx(&self, tx: &Vec<u8>, max_fee_rate: Option<u64>) -> Result<Txid> {
        // convert fee rate from sat/vb to btc/kb
        let max_fee_rate = match max_fee_rate {
            Some(fee_rate) => {
                let fee_rate = fee_rate as f64 / 100_000_000.0 * 1000.0;
                format!("{:.8}", fee_rate).parse::<f64>().unwrap()
            }
            None => 0.1, // the default fee rate is 0.1 BTC/kB
        };
        let txid = self.client.call(
            "sendrawtransaction",
            &[
                json!(tx.raw_hex()),
                json!(max_fee_rate),
            ],
        )?;
        Ok(txid)
    }

    pub(crate) fn get_new_address(&self) -> Result<Address> {
        let address = self
            .client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))?;
        Ok(address.require_network(self.network)?)
    }

    pub(crate) fn mine_blocks(&self, blocks: Option<u64>) -> Result<()> {
        info!("Mining {} blocks", blocks.unwrap_or(1));
        let address = self.get_new_address()?;
        self.client
            .generate_to_address(blocks.unwrap_or(1), &address)?;
        Ok(())
    }

    pub(crate) fn get_balance(&self) -> Result<Amount> {
        let balance = self.client.get_balance(None, None)?;
        Ok(balance)
    }

    pub(crate) fn send(&self, address: &Address, amount: Amount) -> Result<OutPoint> {
        let output = json!([{
            address.to_string(): amount.to_float_in(Denomination::Bitcoin)
        }]);
        let send_result: SendResult = self
            .client
            .call("send", &[output, Value::Null, "unset".into(), 1.into()])?;
        let txid = send_result.txid;

        info!("sent txid: {}", txid);
        let transaction_info = self.client.get_transaction(&txid, None)?;
        let mut target_vout = 0;
        for (i, details) in transaction_info.details.iter().enumerate() {
            if &details.address.clone().unwrap().assume_checked() == address {
                target_vout = details.vout;
                break;
            }
        }
        Ok(OutPoint {
            txid,
            vout: target_vout,
        })
    }

    pub(crate) fn sign_tx(&self, tx: &Transaction) -> Result<Transaction> {
        let signed = self.client.sign_raw_transaction_with_wallet(tx, None, None)?;
        signed.transaction().map_err(|e| anyhow!("signing failed: {}", e))
    }
}

#[derive(Deserialize)]
struct SendResult {
    txid: Txid,
}
