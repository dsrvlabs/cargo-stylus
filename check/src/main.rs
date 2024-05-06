// Copyright 2023-2024, Offchain Labs, Inc.
// For licensing, see https://github.com/OffchainLabs/cargo-stylus/blob/main/licenses/COPYRIGHT.md

use clap::{Args, Parser, ValueEnum};
use ethers::types::H160;
use eyre::{eyre, Context, Result};
use std::path::PathBuf;
use tokio::runtime::Builder;

mod check;
mod constants;
mod deploy;
mod export_abi;
mod new;
mod project;
mod tx;
mod wallet;

#[derive(Parser, Debug)]
#[command(name = "check")]
#[command(bin_name = "cargo stylus")]
#[command(author = "Offchain Labs, Inc.")]
#[command(about = "Generate C code for Stylus ABI bindings.", long_about = None)]
#[command(propagate_version = true)]
#[command(version)]
struct Opts {
    #[command(subcommand)]
    command: Apis,
}

#[derive(Parser, Debug, Clone)]
enum Apis {
    /// Create a new Rust project.
    New {
        /// Project name.
        name: PathBuf,
        /// Create a minimal program.
        #[arg(long)]
        minimal: bool,
    },
    /// Export a Solidity ABI.
    ExportAbi {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
        /// The Output file (defaults to stdout).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Output a JSON ABI instead using solc. Requires solc.
        /// See https://docs.soliditylang.org/en/latest/installing-solidity.html
        #[arg(long)]
        json: bool,
    },
    /// Check a contract.
    #[command(alias = "c")]
    Check(CheckConfig),
    /// Deploy a contract.
    #[command(alias = "d")]
    Deploy(DeployConfig),
}

#[derive(Args, Clone, Debug)]
struct CheckConfig {
    /// RPC endpoint of the Stylus node to connect to.
    #[arg(short, long, default_value = "https://stylus-testnet.arbitrum.io/rpc")]
    endpoint: String,
    /// Specifies a WASM file instead of looking for one in the current directory.
    #[arg(long)]
    wasm_file_path: Option<String>,
    /// Specify the program address we want to check activation for. If unspecified, it will
    /// compute the next program address from the user's wallet address and nonce, which will require
    /// wallet-related flags to be specified.
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
    expected_program_address: H160,
    /// File path to a text file containing a private key.
    #[arg(long)]
    private_key_path: Option<String>,
    /// Private key 0x-prefixed hex string to use with the cargo stylus plugin. Warning: this exposes
    /// your private key secret in plaintext in your CLI history. We instead recommend using the
    /// --private-key-path flag or account keystore options.
    #[arg(long)]
    private_key: Option<String>,
    /// Wallet source to use with the cargo stylus plugin.
    #[command(flatten)]
    keystore_opts: KeystoreOpts,
    /// Whether to use Rust nightly.
    #[arg(long)]
    nightly: bool,
}

#[derive(Args, Clone, Debug)]
struct DeployConfig {
    #[command(flatten)]
    check_cfg: CheckConfig,
    /// Estimates deployment gas costs.
    #[arg(long)]
    estimate_gas_only: bool,
    /// By default, submits two transactions to deploy and activate the program to Arbitrum.
    /// Otherwise, a user could choose to split up the deploy and activate steps into individual transactions.
    #[arg(long, value_enum)]
    mode: Option<DeployMode>,
    /// If only activating an already-deployed, onchain program, the address of the program to send an activation tx for.
    #[arg(long)]
    activate_program_address: Option<H160>,
    /// Configuration options for sending the deployment / activation txs through the Cargo stylus deploy command.
    #[command(flatten)]
    tx_sending_opts: TxSendingOpts,
}

#[derive(Debug, Clone, ValueEnum)]
enum DeployMode {
    DeployOnly,
    ActivateOnly,
}

#[derive(Clone, Debug, Args)]
#[group(multiple = true)]
pub struct KeystoreOpts {
    /// Path to an Ethereum wallet keystore file, such as the one produced by wallets such as clef.
    #[arg(long)]
    keystore_path: Option<String>,
    /// Path to a text file containing a password to the specified wallet keystore file.
    #[arg(long)]
    keystore_password_path: Option<String>,
}

#[derive(Clone, Debug, Args)]
struct TxSendingOpts {
    /// Prepares transactions to send onchain for deploying and activating a Stylus program,
    /// but does not send them. Instead, outputs the prepared tx data hex bytes to files in the directory
    /// specified by the --output-tx-data-to-dir flag. Useful for sending the deployment / activation
    /// txs via a user's preferred means instead of via the Cargo stylus tool. For example, Foundry's
    /// https://book.getfoundry.sh/cast/ CLI tool.
    #[arg(long)]
    dry_run: bool,
    /// Outputs the deployment / activation tx data as bytes to a specified directory.
    #[arg(long)]
    output_tx_data_to_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Opts::parse();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(main_impl(args))
}

async fn main_impl(args: Opts) -> Result<()> {
    macro_rules! run {
        ($expr:expr, $($msg:expr),+) => {
            $expr.wrap_err_with(|| eyre!($($msg),+))?
        };
    }

    match args.command {
        Apis::New { name, minimal } => {
            run!(
                new::new_stylus_project(&name, minimal),
                "failed to create project"
            );
        }
        Apis::ExportAbi {
            release,
            json,
            output,
        } => match json {
            true => run!(
                export_abi::export_json_abi(release, output),
                "failed to export json"
            ),
            false => run!(
                export_abi::export_solidity_abi(release, output),
                "failed to export abi"
            ),
        },
        Apis::Check(config) => {
            run!(check::run_checks(config).await, "stylus checks failed");
        }
        Apis::Deploy(config) => {
            run!(deploy::deploy(config).await, "failed to deploy");
        }
    }
    Ok(())
}