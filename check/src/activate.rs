// Copyright 2023-2024, Offchain Labs, Inc.
// For licensing, see https://github.com/OffchainLabs/cargo-stylus/blob/main/licenses/COPYRIGHT.md

#![allow(clippy::println_empty_string)]

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use alloy_primitives::{Address, U256 as AU256};
use alloy_sol_macro::sol;
use alloy_sol_types::SolCall;
use ethers::{
    core::k256::ecdsa::SigningKey,
    middleware::SignerMiddleware,
    prelude::*,
    providers::{Middleware, Provider},
    types::{H160, U256, U64},
};
use eyre::{eyre, Result};

use cargo_stylus_util::color::Color;

use crate::macros::greyln;
use crate::ActivateConfig;

pub enum TxKind {
    Deployment,
    Activation,
}

impl std::fmt::Display for TxKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            TxKind::Deployment => write!(f, "deployment"),
            TxKind::Activation => write!(f, "activation"),
        }
    }
}

sol! {
    interface ArbWasm {
        function activateProgram(address program)
            external
            payable
            returns (uint16 version, uint256 dataFee);
    }


}

type SignerClient = SignerMiddleware<Provider<Http>, Wallet<SigningKey>>;

/// Deploys a stylus program, activating if needed.
pub async fn activate(cfg: ActivateConfig) -> Result<()> {
    greyln!("@@@ activate");
    let contract = cfg.contract_address.unwrap();
    let program: Address = contract.to_fixed_bytes().into();
    let data = ArbWasm::activateProgramCall { program }.abi_encode();
    write_tx_data(TxKind::Activation, &data)?;
    Ok(())
}

fn write_tx_data(tx_kind: TxKind, data: &[u8]) -> eyre::Result<()> {
    let file_name = format!("{tx_kind}_tx_data");
    let mut path = PathBuf::new();
    path.push("./output");
    if !path.exists() {
        fs::create_dir_all(&path).map_err(|e| eyre!("could not create output directory: {e}"))?;
    }
    
    path = path.join(file_name);
    let path_str = path.as_os_str().to_string_lossy();
    let hex: String = data
        .to_vec()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();
    println!(
        "Writing {tx_kind} tx data bytes of size {} to path {} hex={}",
        data.len().mint(),
        path_str.grey(),
        hex
    );
    let mut f = std::fs::File::create(&path)
        .map_err(|e| eyre!("could not create file to write tx data to path {path_str}: {e}",))?;
    f.write_all(data)
        .map_err(|e| eyre!("could not write tx data as bytes to file to path {path_str}: {e}"))
}
