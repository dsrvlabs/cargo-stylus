// Copyright 2023-2024, Offchain Labs, Inc.
// 라이선스 정보는 https://github.com/OffchainLabs/cargo-stylus/blob/main/licenses/COPYRIGHT.md에서 확인할 수 있습니다.

#![allow(clippy::println_empty_string)] // 빈 문자열을 println에 사용해도 Clippy 경고를 무시합니다.

use std::fs; // 파일 시스템 작업을 위한 표준 라이브러리 사용
use std::io::Write; // 파일에 데이터를 쓰기 위한 표준 라이브러리 사용
use std::path::PathBuf; // 파일 경로를 처리하기 위한 표준 라이브러리 사용

use alloy_primitives::Address; // Ethereum 주소를 처리하기 위한 라이브러리
use alloy_sol_macro::sol; // Solidity 인터페이스를 정의하기 위한 매크로
use alloy_sol_types::SolCall; // Solidity 함수 호출을 처리하기 위한 타입
use ethers::{
    core::k256::ecdsa::SigningKey,
    middleware::SignerMiddleware,
    prelude::*,
    providers::{Middleware, Provider},
    types::transaction::eip2718::TypedTransaction,
    types::{Eip1559TransactionRequest, H160, U256},
    utils::format_units,
};
use eyre::{bail, eyre, Context, Result, WrapErr}; // 에러 핸들링을 위한 라이브러리

use cargo_stylus_util::color::{Color, DebugColor}; // 컬러 출력을 위한 유틸리티
use cargo_stylus_util::sys; // 시스템 관련 유틸리티

use crate::check::check_activate; // 계약 활성화 체크 함수를 가져옵니다.
use crate::constants::ARB_WASM_H160; // Arbitrum WASM 주소 상수를 가져옵니다.
use crate::macros::greyln; // 컬러와 함께 로그를 출력하는 매크로를 가져옵니다.
use crate::ActivateConfig; // 활성화 구성 구조체를 가져옵니다.
use crate::ActivateWithoutPrivateKeyConfig; // 활성화 구성 구조체를 가져옵니다.

pub enum TxKind {
    Deployment, // 배포 트랜잭션
    Activation, // 활성화 트랜잭션
}

impl std::fmt::Display for TxKind {
    // TxKind를 문자열로 출력하는 방법을 정의합니다.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            TxKind::Deployment => write!(f, "deployment"), // 배포 트랜잭션
            TxKind::Activation => write!(f, "activation"), // 활성화 트랜잭션
        }
    }
}

sol! {
    interface ArbWasm {
        // Arbitrum WASM 프로그램을 활성화하는 Solidity 함수 정의
        function activateProgram(address program)
            external
            payable
            returns (uint16 version, uint256 dataFee);
    }
}

type SignerClient = SignerMiddleware<Provider<Http>, Wallet<SigningKey>>; // 서명된 트랜잭션을 보내기 위한 클라이언트 타입

fn write_tx_data(tx_kind: TxKind, data: &[u8]) -> eyre::Result<()> {
    // 트랜잭션 데이터를 파일로 작성하는 함수
    let file_name = format!("{tx_kind}_tx_data");
    let mut path = PathBuf::new();
    path.push("./output");
    if !path.exists() {
        fs::create_dir_all(&path).map_err(|e| eyre!("could not create output directory: {e}"))?;
        // 출력 디렉토리를 생성합니다.
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
        .map_err(|e| eyre!("could not create file to write tx data to path {path_str}: {e}",))?; // 파일을 생성합니다.
    f.write_all(data)
        .map_err(|e| eyre!("could not write tx data as bytes to file to path {path_str}: {e}"))
    // 데이터를 파일에 씁니다.
}

/// 이미 배포된 Stylus 계약을 주소를 통해 활성화합니다.
pub async fn activate_contract(cfg: &ActivateConfig) -> Result<()> {
    let provider = sys::new_provider(&cfg.common_cfg.endpoint)?; // 프로바이더를 생성합니다.
    let chain_id = provider
        .get_chainid()
        .await
        .wrap_err("failed to get chain id")?; // 체인 ID를 가져옵니다.

    let wallet = cfg.auth.wallet().wrap_err("failed to load wallet")?; // 지갑을 로드합니다.
    let wallet = wallet.with_chain_id(chain_id.as_u64());
    let client = SignerMiddleware::new(provider.clone(), wallet); // 서명된 트랜잭션 클라이언트를 생성합니다.

    let code = client.get_code(cfg.address, None).await?; // 계약의 코드를 가져옵니다.
    let data_fee = check_activate(code, cfg.address, &provider).await?; // 활성화에 필요한 데이터 수수료를 계산합니다.
    let mut data_fee = alloy_ethers_typecast::alloy_u256_to_ethers(data_fee);

    greyln!(
        "obtained estimated activation data fee {}",
        format_units(data_fee, "ether")?.debug_lavender()
    );
    greyln!(
        "bumping estimated activation data fee by {}%",
        cfg.data_fee_bump_percent.debug_lavender()
    );
    data_fee = bump_data_fee(data_fee, cfg.data_fee_bump_percent); // 데이터 수수료를 조정합니다.

    let contract: Address = cfg.address.to_fixed_bytes().into();
    let data = ArbWasm::activateProgramCall { program: contract }.abi_encode(); // 프로그램 활성화 트랜잭션을 생성합니다.
    let tx = Eip1559TransactionRequest::new()
        .from(client.address())
        .to(*ARB_WASM_H160)
        .value(data_fee)
        .data(data);
    let tx = TypedTransaction::Eip1559(tx);
    let tx = client.send_transaction(tx, None).await?; // 트랜잭션을 전송합니다.
    match tx.await? {
        Some(receipt) => {
            greyln!(
                "successfully activated contract 0x{} with tx {}",
                hex::encode(cfg.address),
                hex::encode(receipt.transaction_hash).debug_lavender()
            );
            let program: Address = cfg.address.to_fixed_bytes().into();
            let data = ArbWasm::activateProgramCall { program }.abi_encode();
            write_tx_data(TxKind::Activation, &data)?; // 트랜잭션 데이터를 파일로 작성합니다.
        }
        None => {
            bail!(
                "failed to fetch receipt for contract activation {}",
                cfg.address
            ); // 트랜잭션 영수증을 가져오지 못한 경우 오류를 발생시킵니다.
        }
    }
    Ok(())
}

/// Deploys a stylus program, activating if needed.
pub async fn activate(cfg: &ActivateWithoutPrivateKeyConfig) -> Result<()> {
    greyln!("@@@ activate");
    let contract: Address = cfg.address.to_fixed_bytes().into();
    let data = ArbWasm::activateProgramCall { program: contract }.abi_encode(); // 프로그램 활성화 트랜잭션을 생성합니다.
    write_tx_data(TxKind::Activation, &data)?;
    Ok(())
}

fn bump_data_fee(fee: U256, pct: u64) -> U256 {
    // 데이터 수수료를 지정된 퍼센트만큼 증가시킵니다.
    let num = 100 + pct;
    fee * U256::from(num) / U256::from(100)
}
