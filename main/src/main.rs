// Copyright 2023-2024, Offchain Labs, Inc.
// 라이선스 정보는 https://github.com/OffchainLabs/cargo-stylus/blob/main/licenses/COPYRIGHT.md에서 확인할 수 있습니다.

use cargo_stylus_util::{color::Color, sys}; // 색상 및 시스템 명령어 관련 유틸리티 모듈을 가져옴
use clap::{CommandFactory, Parser}; // CLI 명령어 파싱을 위한 clap 라이브러리 가져옴
use eyre::{bail, Result}; // 오류 처리 및 결과 반환을 위한 eyre 라이브러리 가져옴

// Unix 계열 운영체제에서만 사용되는 `CommandExt`를 조건부로 가져옴
#[cfg(unix)]
use std::{env, os::unix::process::CommandExt};

// Windows에서만 사용되는 모듈을 조건부로 가져옴
#[cfg(windows)]
use std::env;

#[derive(Parser, Debug)] // 명령어 파서를 정의하고 디버그 모드 활성화
#[command(name = "stylus")] // 명령어 이름을 설정
#[command(bin_name = "cargo stylus")] // 이 바이너리가 실행될 때 사용할 명령어 이름
#[command(author = "Offchain Labs, Inc.")] // 작성자 정보
#[command(about = "Stylus 프로젝트를 개발하기 위한 Cargo 서브 명령어", long_about = None)] // 프로그램 설명
#[command(propagate_version = true)] // 버전 정보를 전파하도록 설정
#[command(version)] // 버전 정보를 포함하도록 설정
struct Opts {
    #[command(subcommand)]
    command: Subcommands, // 서브커맨드를 정의
}

#[derive(Parser, Debug, Clone)] // 서브커맨드의 파서를 정의하고 디버그 모드 및 복제 가능 설정
enum Subcommands {
    #[command(alias = "n")]
    /// 새로운 Stylus 프로젝트를 생성합니다.
    New, // 새로운 프로젝트를 생성하는 서브커맨드
    #[command(alias = "i")]
    /// 현재 디렉토리에 Stylus 프로젝트를 초기화합니다.
    Init, // 현재 디렉토리에 프로젝트를 초기화하는 서브커맨드
    #[command(alias = "x")]
    /// Solidity ABI를 내보냅니다.
    ExportAbi, // Solidity ABI를 내보내는 서브커맨드
    /// 계약을 캐시합니다.
    Cache, // 계약을 캐시하는 서브커맨드
    /// 계약을 검사합니다.
    #[command(alias = "c")]
    Check, // 계약을 검사하는 서브커맨드
    /// 이미 배포된 계약을 활성화합니다.
    #[command(alias = "a")]
    Activate, // 이미 배포된 계약을 활성화하는 서브커맨드
    /// 계약을 배포합니다.
    #[command(alias = "d")]
    Deploy, // 계약을 배포하는 서브커맨드
    /// gdb에서 트랜잭션을 재실행합니다.
    #[command(alias = "r")]
    Replay, // 트랜잭션을 gdb에서 재실행하는 서브커맨드
    /// 트랜잭션을 추적합니다.
    #[command()]
    Trace, // 트랜잭션을 추적하는 서브커맨드
    /// Stylus 계약의 배포를 로컬 프로젝트와 검증합니다.
    #[command(alias = "v")]
    Verify, // Stylus 계약의 배포를 검증하는 서브커맨드
    /// C 코드를 생성합니다.
    #[command()]
    CGen, // C 코드를 생성하는 서브커맨드
}

// 명령어 정보 구조체
struct Binary<'a> {
    name: &'a str,               // 바이너리 이름
    apis: &'a [&'a str],         // API 명령어 목록
    rust_flags: Option<&'a str>, // Rust 플래그 옵션
}

// 명령어 목록을 상수로 정의
const COMMANDS: &[Binary] = &[
    Binary {
        name: "cargo-stylus-check",
        apis: &[
            "new",
            "init",
            "activate",
            "export-abi",
            "cache",
            "check",
            "deploy",
            "verify",
            "a",
            "i",
            "n",
            "x",
            "c",
            "d",
            "v",
            "a",
        ],
        rust_flags: None,
    },
    Binary {
        name: "cargo-stylus-cgen",
        apis: &["cgen"],
        rust_flags: None,
    },
    Binary {
        name: "cargo-stylus-replay",
        apis: &["trace", "replay", "r"],
        rust_flags: None,
    },
    Binary {
        name: "cargo-stylus-test",
        apis: &["test", "t"],
        rust_flags: Some(r#"RUSTFLAGS="-C link-args=-rdynamic""#),
    },
];

// 도움말 메시지를 출력하고 프로그램을 종료
fn exit_with_help_msg() -> ! {
    Opts::command().print_help().unwrap();
    std::process::exit(0);
}

// 버전 정보를 출력하고 프로그램을 종료
fn exit_with_version() -> ! {
    println!("{}", Opts::command().render_version());
    std::process::exit(0);
}

// 메인 함수
fn main() -> Result<()> {
    // 운영체제와 Cargo에서 전달된 시작 인수를 건너뜁니다.
    let mut args =
        env::args().skip_while(|x| x == "cargo" || x == "stylus" || x.contains("cargo-stylus"));

    // 첫 번째 명령어 인수를 가져옵니다. 없다면 도움말 메시지를 출력
    let Some(arg) = args.next() else {
        exit_with_help_msg();
    };

    // 내장된 명령어를 처리합니다.
    match arg.as_str() {
        "--help" | "-h" => exit_with_help_msg(),
        "--version" | "-V" => exit_with_version(),
        _ => {}
    };

    // 명령어가 COMMANDS 목록에 있는지 확인합니다. 없다면 커스텀 명령어를 확인
    let Some(bin) = COMMANDS.iter().find(|x| x.apis.contains(&arg.as_str())) else {
        // 커스텀 확장이 존재하는지 확인
        let custom = format!("cargo-stylus-{arg}");
        if sys::command_exists(&custom) {
            let mut command = sys::new_command(&custom);
            command.arg(arg).args(args);

            // 플랫폼에 따라 명령어 실행
            #[cfg(unix)]
            let err = command.exec(); // Unix 전용 실행 방식
            #[cfg(windows)]
            let err = command.status(); // Windows 전용 실행 방식
            bail!("failed to invoke {:?}: {:?}", custom.red(), err); // 오류 발생 시 메시지 출력
        }

        eprintln!("Unknown subcommand {}.", arg.red());
        eprintln!();
        exit_with_help_msg(); // 알 수 없는 서브커맨드일 경우 도움말 메시지를 출력하고 종료
    };

    let name = bin.name;

    // 해당 서브커맨드가 설치되지 않은 경우 설치 방법을 안내
    if !sys::command_exists(name) {
        let flags = bin.rust_flags.map(|x| format!("{x} ")).unwrap_or_default();
        let install = format!("    {flags}cargo install --force {name}");

        eprintln!("{} {}{}", "missing".grey(), name.red(), ".".grey());
        eprintln!();
        eprintln!("{}", "to install it, run".grey());
        eprintln!("{}", install.yellow());
        return Ok(());
    }

    // 명령어를 생성하고 인수를 추가
    let mut command = sys::new_command(name);
    command.arg(arg).args(args);

    // 플랫폼에 따라 명령어 실행
    #[cfg(unix)]
    let err = command.exec(); // Unix 전용 실행 방식
    #[cfg(windows)]
    let err = command.status(); // Windows 전용 실행 방식
    bail!("failed to invoke {:?}: {:?}", name.red(), err); // 오류 발생 시 메시지 출력
}
