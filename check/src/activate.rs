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
    types::{Eip1559TransactionRequest, H160, TypedTransaction, U256, U64},
    utils::format_units,
};
use eyre::{bail, eyre, Context, Result, WrapErr};

use cargo_stylus_util::color::{Color, DebugColor};
use cargo_stylus_util::sys;

use crate::macros::greyln;
use crate::check::check_activate;
use crate::constants::ARB_WASM_H160;
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

/// Activates an already deployed Stylus program by address.
pub async fn activate_program(cfg: &ActivateConfig) -> Result<()> {
    let provider = sys::new_provider(&cfg.common_cfg.endpoint)?;
    let chain_id = provider
        .get_chainid()
        .await
        .wrap_err("failed to get chain id")?;

    let wallet = cfg.auth.wallet().wrap_err("failed to load wallet")?;
    let wallet = wallet.with_chain_id(chain_id.as_u64());
    let client = SignerMiddleware::new(provider.clone(), wallet);

    let code = client.get_code(cfg.address, None).await?;
    let data_fee = check_activate(code, cfg.address, &provider).await?;
    let mut data_fee = alloy_ethers_typecast::alloy_u256_to_ethers(data_fee);

    greyln!(
        "obtained estimated activation data fee {}",
        format_units(data_fee, "ether")?.debug_lavender()
    );
    greyln!(
        "bumping estimated activation data fee by {}%",
        cfg.data_fee_bump_percent.debug_lavender()
    );
    data_fee = bump_data_fee(data_fee, cfg.data_fee_bump_percent);

    let program: Address = cfg.address.to_fixed_bytes().into();
    let data = ArbWasm::activateProgramCall { program }.abi_encode();
    let tx = Eip1559TransactionRequest::new()
        .from(client.address())
        .to(*ARB_WASM_H160)
        .value(data_fee)
        .data(data);
    let tx = TypedTransaction::Eip1559(tx);
    let tx = client.send_transaction(tx, None).await?;
    match tx.await? {
        Some(receipt) => {
            greyln!(
                "successfully activated program 0x{} with tx {}",
                hex::encode(cfg.address),
                hex::encode(receipt.transaction_hash).debug_lavender()
            );
        }
        None => {
            bail!(
                "failed to fetch receipt for program activation {}",
                cfg.address
            );
        }
    }
    Ok(())
}

fn bump_data_fee(fee: U256, pct: u64) -> U256 {
    let num = 100 + pct;
    fee * U256::from(num) / U256::from(100)
}
