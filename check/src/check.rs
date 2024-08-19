// Copyright 2023-2024, Offchain Labs, Inc.
// 라이선스 정보는 https://github.com/OffchainLabs/cargo-stylus/blob/main/licenses/COPYRIGHT.md에서 확인할 수 있습니다.

use crate::deploy::TxKind;
use crate::{
    check::ArbWasm::ArbWasmErrors,
    constants::{ARB_WASM_H160, ONE_ETH, TOOLCHAIN_FILE_NAME},
    macros::*,
    project::{self, extract_toolchain_channel, BuildConfig},
    CheckConfig,
};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_macro::sol;
use alloy_sol_types::{SolCall, SolInterface};
use bytesize::ByteSize;
use cargo_stylus_util::{color::Color, sys, text};
use ethers::{
    core::types::spoof,
    prelude::*,
    providers::RawCall,
    types::{spoof::State, transaction::eip2718::TypedTransaction, Eip1559TransactionRequest},
};
use eyre::{bail, eyre, ErrReport, Result, WrapErr};
use serde_json::Value;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

sol! {
    interface ArbWasm {
        // ArbWasm 인터페이스 정의: 프로그램 활성화, Stylus 버전 확인, 코드 해시 버전 확인 및 오류 처리 함수들.
        function activateProgram(address program)
            external
            payable
            returns (uint16 version, uint256 dataFee);

        function stylusVersion() external view returns (uint16 version);

        function codehashVersion(bytes32 codehash) external view returns (uint16 version);

        error ProgramNotWasm();
        error ProgramNotActivated();
        error ProgramNeedsUpgrade(uint16 version, uint16 stylusVersion);
        error ProgramExpired(uint64 ageInSeconds);
        error ProgramUpToDate();
        error ProgramKeepaliveTooSoon(uint64 ageInSeconds);
        error ProgramInsufficientValue(uint256 have, uint256 want);
    }
}

/// 계약이 유효하며 체인에 배포될 수 있는지 확인합니다.
/// 이더리움 WASM이 최신 상태로 이미 체인에서 활성화되었는지 여부와 데이터 수수료를 반환합니다.
pub async fn check(cfg: &CheckConfig) -> Result<ContractCheck> {
    if cfg.common_cfg.endpoint == "https://stylus-testnet.arbitrum.io/rpc" {
        let version = "cargo stylus version 0.2.1".to_string().red();
        bail!("The old Stylus testnet is no longer supported.\nPlease downgrade to {version}",);
    }

    let verbose = cfg.common_cfg.verbose;
    let (wasm, project_hash) = cfg.build_wasm().wrap_err("failed to build wasm")?; // WASM 파일을 빌드합니다.

    if verbose {
        greyln!("reading wasm file at {}", wasm.to_string_lossy().lavender());
    }


    // 다음으로, 사용자의 WASM(웹어셈블리) 파일에 프로젝트의 해시를 커스텀 섹션으로 포함시킵니다.
    // 이 해시는 Cargo stylus의 재현 가능한 검증(reproducible verification)에 의해 검증될 수 있도록 추가됩니다.
    // 이 해시는 WASM 런타임에서 무시되는 섹션으로 추가되기 때문에, 파일에는 메타데이터 용도로만 존재하게 됩니다.
    let (wasm_file_bytes, code) =
        project::compress_wasm(&wasm, project_hash).wrap_err("failed to compress WASM")?; // WASM 파일을 압축합니다.

    let code_copied = code.clone();
    let mut code_len = [0u8; 32];
    ethers::prelude::U256::from(code_copied.len()).to_big_endian(&mut code_len);
    let mut tx_code: Vec<u8> = vec![];
    tx_code.push(0x7f); // PUSH32
    tx_code.extend(code_len);
    tx_code.push(0x80); // DUP1
    tx_code.push(0x60); // PUSH1
    tx_code.push(42 + 1 + 32); // prelude + version + hash
    tx_code.push(0x60); // PUSH1
    tx_code.push(0x00);
    tx_code.push(0x39); // CODECOPY
    tx_code.push(0x60); // PUSH1
    tx_code.push(0x00);
    tx_code.push(0xf3); // RETURN
    tx_code.push(0x00); // version
    tx_code.extend(project_hash);
    tx_code.extend(code_copied);
    write_tx_data(TxKind::Deployment, &tx_code)?; // 트랜잭션 데이터를 작성하여 파일로 저장합니다.

    greyln!("contract size: {}", format_file_size(code.len(), 16, 24)); // 계약 크기를 출력합니다.

    if verbose {
        greyln!(
            "wasm size: {}",
            format_file_size(wasm_file_bytes.len(), 96, 128)
        );
        greyln!("connecting to RPC: {}", &cfg.common_cfg.endpoint.lavender());
    }

    // 계약이 이미 존재하는지 확인합니다.
    let provider = sys::new_provider(&cfg.common_cfg.endpoint)?;
    let codehash = alloy_primitives::keccak256(&code);

    if contract_exists(codehash, &provider).await? {
        return Ok(ContractCheck::Active { code }); // 계약이 이미 활성화된 경우.
    }

    let address = cfg.contract_address.unwrap_or(H160::random()); // 계약 주소를 설정하거나 새로 생성합니다.
    let fee = check_activate(code.clone().into(), address, &provider).await?; // 계약 활성화를 위한 데이터 수수료를 계산합니다.
    let visual_fee = format_data_fee(fee).unwrap_or("???".red());
    greyln!("wasm data fee: {visual_fee}"); // 데이터 수수료를 출력합니다.
    Ok(ContractCheck::Ready { code, fee }) // 계약이 활성화 준비가 된 경우.
}

/// 계약이 활성화되었는지, 아니면 활성화가 필요한지 확인하는 열거형.
#[derive(PartialEq)]
pub enum ContractCheck {
    /// 계약이 이미 체인에 존재합니다.
    Active { code: Vec<u8> },
    /// 계약을 데이터 수수료와 함께 활성화할 수 있습니다.
    Ready { code: Vec<u8>, fee: U256 },
}

impl ContractCheck {
    pub fn code(&self) -> &[u8] {
        match self {
            Self::Active { code, .. } => code, // 활성화된 경우 코드 반환
            Self::Ready { code, .. } => code, // 준비된 경우 코드 반환
        }
    }
    pub fn suggest_fee(&self) -> U256 {
        match self {
            Self::Active { .. } => U256::default(), // 활성화된 경우 기본 수수료 반환
            Self::Ready { fee, .. } => fee * U256::from(120) / U256::from(100), // 준비된 경우 수수료를 조정하여 반환
        }
    }
}

impl CheckConfig {
    fn build_wasm(&self) -> Result<(PathBuf, [u8; 32])> {
        if let Some(wasm) = self.wasm_file.clone() {
            return Ok((wasm, [0u8; 32])); // 기존 WASM 파일이 있으면 사용
        }
        let toolchain_file_path = PathBuf::from(".").as_path().join(TOOLCHAIN_FILE_NAME);
        let toolchain_channel = extract_toolchain_channel(&toolchain_file_path)?; // 도구 체인 채널을 추출합니다.
        let rust_stable = !toolchain_channel.contains("nightly");
        let cfg = BuildConfig::new(rust_stable);
        let wasm = project::build_dylib(cfg.clone())?; // 동적 라이브러리(Dylib)를 빌드합니다.
        let project_hash =
            project::hash_files(self.common_cfg.source_files_for_project_hash.clone(), cfg)?; // 프로젝트 파일 해시를 계산합니다.
        Ok((wasm, project_hash))
    }
}

/// 파일 크기를 포맷하여 예쁘게 출력합니다.
pub fn format_file_size(len: usize, mid: u64, max: u64) -> String {
    let len = ByteSize::b(len as u64);
    let mid = ByteSize::kib(mid);
    let max = ByteSize::kib(max);
    if len <= mid {
        len.mint()
    } else if len <= max {
        len.yellow()
    } else {
        len.pink()
    }
}

/// 데이터 수수료를 포맷하여 출력합니다.
fn format_data_fee(fee: U256) -> Result<String> {
    let fee: u64 = (fee / U256::from(1e9)).try_into()?;
    let fee: f64 = fee as f64 / 1e9;
    let text = format!("Ξ{fee:.6}");
    Ok(if fee <= 5e14 {
        text.mint()
    } else if fee <= 5e15 {
        text.yellow()
    } else {
        text.pink()
    })
}

pub struct EthCallError {
    pub data: Vec<u8>,
    pub msg: String,
}

impl From<EthCallError> for ErrReport {
    fn from(value: EthCallError) -> Self {
        eyre!(value.msg) // EthCallError를 ErrReport로 변환
    }
}

/// 자금이 충당된 eth_call을 실행합니다.
pub async fn eth_call(
    tx: Eip1559TransactionRequest,
    mut state: State,
    provider: &Provider<Http>,
) -> Result<Result<Vec<u8>, EthCallError>> {
    let tx = TypedTransaction::Eip1559(tx);
    state.account(Default::default()).balance = Some(ethers::types::U256::MAX); // 무한한 잔고를 설정하여 가스 제한을 회피합니다.

    match provider.call_raw(&tx).state(&state).await {
        Ok(bytes) => Ok(Ok(bytes.to_vec())), // 호출이 성공하면 결과를 바이트 배열로 반환
        Err(ProviderError::JsonRpcClientError(error)) => {
            let error = error
                .as_error_response()
                .ok_or_else(|| eyre!("json RPC failure: {error}"))?; // JSON RPC 실패 시 처리

            let msg = error.message.clone();
            let data = match &error.data {
                Some(Value::String(data)) => text::decode0x(data)?.to_vec(), // 에러 데이터를 디코딩
                Some(value) => bail!("failed to decode RPC failure: {value}"),
                None => vec![], // 데이터가 없는 경우 빈 벡터 반환
            };
            Ok(Err(EthCallError { data, msg })) // EthCallError로 반환
        }
        Err(error) => Err(error.into()), // 기타 에러 처리
    }
}

/// 계약이 최신 Stylus 버전으로 이미 활성화되어 있는지 확인합니다.
async fn contract_exists(codehash: B256, provider: &Provider<Http>) -> Result<bool> {
    let data = ArbWasm::codehashVersionCall { codehash }.abi_encode(); // 코드 해시 버전을 확인하는 호출 데이터 생성
    let tx = Eip1559TransactionRequest::new()
        .to(*ARB_WASM_H160)
        .data(data);
    let outs = eth_call(tx, State::default(), provider).await?;

    let program_version = match outs {
        Ok(outs) => {
            if outs.is_empty() {
                bail!(
                    r#"No data returned from the ArbWasm precompile when checking if your Stylus contract exists.
Perhaps the Arbitrum node for the endpoint you are connecting to has not yet upgraded to Stylus"#
                );
            }
            let ArbWasm::codehashVersionReturn { version } =
                ArbWasm::codehashVersionCall::abi_decode_returns(&outs, true)?;
            version
        }
        Err(EthCallError { data, msg }) => {
            let Ok(error) = ArbWasmErrors::abi_decode(&data, true) else {
                bail!("unknown ArbWasm error: {msg}");
            };
            use ArbWasmErrors as A;
            match error {
                A::ProgramNotWasm(_) => bail!("not a Stylus contract"), // Stylus 계약이 아닌 경우
                A::ProgramNotActivated(_) | A::ProgramNeedsUpgrade(_) | A::ProgramExpired(_) => {
                    return Ok(false); // 프로그램이 활성화되지 않았거나 업그레이드가 필요한 경우
                }
                _ => bail!("unexpected ArbWasm error: {msg}"), // 예기치 않은 오류 처리
            }
        }
    };

    let data = ArbWasm::stylusVersionCall {}.abi_encode(); // Stylus 버전을 확인하는 호출 데이터 생성
    let tx = Eip1559TransactionRequest::new()
        .to(*ARB_WASM_H160)
        .data(data);
    let outs = eth_call(tx, State::default(), provider).await??;
    let ArbWasm::stylusVersionReturn { version } =
        ArbWasm::stylusVersionCall::abi_decode_returns(&outs, true)?;

    Ok(program_version == version) // 프로그램 버전이 최신 버전인지 확인
}

/// 계약 활성화를 확인하고, 데이터 수수료를 반환합니다.
pub async fn check_activate(code: Bytes, address: H160, provider: &Provider<Http>) -> Result<U256> {
    let contract = Address::from(address.to_fixed_bytes());
    let data = ArbWasm::activateProgramCall { program: contract }.abi_encode(); // 프로그램 활성화 호출 데이터 생성
    let tx = Eip1559TransactionRequest::new()
        .to(*ARB_WASM_H160)
        .data(data)
        .value(ONE_ETH); // 활성화 트랜잭션을 위해 1 ETH를 설정
    let state = spoof::code(address, code); // 계약 코드와 주소를 기반으로 상태를 스푸핑(spoofing)
    let outs = eth_call(tx, state, provider).await??;
    let ArbWasm::activateProgramReturn { dataFee, .. } =
        ArbWasm::activateProgramCall::abi_decode_returns(&outs, true)?;

    Ok(dataFee) // 활성화에 필요한 데이터 수수료 반환
}

fn write_tx_data(tx_kind: TxKind, data: &[u8]) -> eyre::Result<()> {
    let file_name = format!("{tx_kind}_tx_data"); // 트랜잭션 종류에 따라 파일 이름 설정
    let mut path = PathBuf::new();
    path.push("./output");
    if !path.exists() {
        fs::create_dir_all(&path).map_err(|e| eyre!("could not create output directory: {e}"))?; // 출력 디렉토리 생성
    }

    path = path.join(file_name);
    let path_str = path.as_os_str().to_string_lossy();
    println!(
        "Writing {tx_kind} tx data bytes of size {} to path {}",
        data.len().mint(),
        path_str.grey(),
    );
    let mut f = std::fs::File::create(&path)
        .map_err(|e| eyre!("could not create file to write tx data to path {path_str}: {e}",))?; // 파일 생성
    f.write_all(data)
        .map_err(|e| eyre!("could not write tx data as bytes to file to path {path_str}: {e}")) // 데이터를 파일에 씁니다.
}
