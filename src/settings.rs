use anyhow::Result;
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Settings {
    pub network: Network,
    pub bitcoin_rpc_username: String,
    pub bitcoin_rpc_password: String,
    pub create_wallets: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            network: Network::Regtest,
            bitcoin_rpc_username: "user".to_string(),
            bitcoin_rpc_password: "password".to_string(),
            create_wallets: false,
        }
    }
}

impl Settings {
    pub(crate) fn from_toml_file(path: &PathBuf) -> Result<Self> {
        let toml = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&toml)?)
    }
}
