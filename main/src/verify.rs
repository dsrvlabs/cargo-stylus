/// `verify` 함수는 이더리움 네트워크에서 특정 트랜잭션을 조회하고 로컬 파일 시스템에서 생성된 데이터와 비교하여
/// 배포된 계약이 로컬 상태와 일치하는지 검증하는 역할을 수행합니다. 만약 일치하지 않는다면, 배포된 계약과 로컬 프로젝트의 차이점을 출력합니다.
/// 이 과정은 계약의 무결성을 보장하고 신뢰성을 높이는 데 유용합니다.
/// 
/// # Arguments
/// * `cfg` - VerifyConfig 구조체를 받아와 검증에 필요한 설정 정보를 제공합니다.
/// 
/// # Return Type
/// * `eyre::Result<()>` - 함수가 성공적으로 완료되면 `()`(유닛)을 반환하고, 오류 발생 시 eyre 라이브러리의 에러 정보를 반환합니다.
pub async fn verify(cfg: VerifyConfig) -> eyre::Result<()> {
    // RPC 프로바이더를 생성합니다. 네트워크 상의 노드와 연결하기 위해 사용됩니다.
    let provider = sys::new_provider(&cfg.common_cfg.endpoint)?;
    
    // 입력된 배포 트랜잭션 해시를 디코딩합니다. 잘못된 길이의 해시는 오류를 반환합니다.
    let hash = crate::util::text::decode0x(cfg.deployment_tx)?;
    if hash.len() != 32 {
        bail!("Invalid hash");
    }
    
    // 로컬 프로젝트의 도구체인 파일 경로를 설정하고 도구체인 채널을 추출합니다. 안정적인(rust_stable) 빌드를 확인합니다.
    let toolchain_file_path = PathBuf::from(".").as_path().join(TOOLCHAIN_FILE_NAME);
    let toolchain_channel = extract_toolchain_channel(&toolchain_file_path)?;
    let rust_stable = !toolchain_channel.contains("nightly");
    
    // 트랜잭션 정보를 RPC를 통해 조회합니다. 해당 트랜잭션이 존재하지 않을 경우 오류를 반환합니다.
    let Some(result) = provider
        .get_transaction(H256::from_slice(&hash))
        .await
        .map_err(|e| eyre!("RPC failed: {e}"))?
    else {
        bail!("No code at address");
    };

    // 로컬에서 `cargo clean` 명령어를 실행하여 이전 빌드 파일들을 정리합니다.
    let output = sys::new_command("cargo")
        .arg("clean")
        .output()
        .map_err(|e| eyre!("failed to execute cargo clean: {e}"))?;
    if !output.status.success() {
        bail!("cargo clean command failed");
    }
    
    // 프로젝트 검증 구성 설정을 사용하여 로컬에서 스타일러스 체크를 수행합니다.
    let check_cfg = CheckConfig {
        common_cfg: cfg.common_cfg.clone(),
        wasm_file: None,
        contract_address: None,
        output: None,
    };
    let _ = check::check(&check_cfg)
        .await
        .map_err(|e| eyre!("Stylus checks failed: {e}"))?;
    
    // 빌드 구성 설정을 정의하고, 프로젝트를 빌드하여 웹어셈블리(WASM) 파일을 생성합니다.
    let build_cfg = project::BuildConfig {
        opt_level: project::OptLevel::default(),
        stable: rust_stable,
    };
    let wasm_file: PathBuf = project::build_dylib(build_cfg.clone())
        .map_err(|e| eyre!("could not build project to WASM: {e}"))?;
    
    // 프로젝트의 해시 값을 계산하여 WASM 파일을 압축하고 초기화 코드를 생성합니다.
    let project_hash =
        project::hash_files(cfg.common_cfg.source_files_for_project_hash, build_cfg)?;
    let (_, init_code) = project::compress_wasm(&wasm_file, project_hash)?;
    
    // 스마트 계약 배포 데이터와 로컬에서 생성된 데이터를 비교합니다.
    let deployment_data = deploy::contract_deployment_calldata(&init_code);
    if deployment_data == *result.input {
        // 만약 일치한다면 검증 성공 메시지를 출력합니다.
        println!("Verified - contract matches local project's file hashes");
    } else {
        // 일치하지 않는 경우 추가적인 디버깅 정보를 출력합니다.
        let tx_prelude = extract_contract_evm_deployment_prelude(&result.input);
        let reconstructed_prelude = extract_contract_evm_deployment_prelude(&deployment_data);
        println!(
            "{} - contract deployment did not verify against local project's file hashes",
            "FAILED".red()
        );
        if tx_prelude != reconstructed_prelude {
            // 트랜잭션 서문이 일치하지 않는 경우
            println!("Prelude mismatch");
            println!("Deployment tx prelude {}", hex::encode(tx_prelude));
            println!(
                "Reconstructed prelude {}",
                hex::encode(reconstructed_prelude)
            );
        } else {
            // 압축된 WASM 바이트코드가 일치하지 않는 경우
            println!("Compressed WASM bytecode mismatch");
        }
        println!(
            "Compressed code length of locally reconstructed {}",
            init_code.len()
        );
        println!(
            "Compressed code length of deployment tx {}",
            extract_compressed_wasm(&result.input).len()
        );
    }
    Ok(())
}
