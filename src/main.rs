#![allow(dead_code)]
mod app;
mod export;
mod identify;
mod model;
mod net;
mod scanner;
mod sniffer;
mod ui;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "netscan", about = "Network security scanner with TUI", version)]
struct Cli {
    /// Target network (CIDR) or IP. Defaults to local subnet.
    target: Option<String>,

    /// Network interface to use
    #[arg(short, long)]
    interface: Option<String>,

    /// Disable passive sniffer
    #[arg(long)]
    no_sniff: bool,

    /// Auto-export results to JSON file on exit
    #[arg(long, value_name = "FILE")]
    export: Option<PathBuf>,

    /// Use the `llm` CLI to fill missing vendor/model/type guesses after the scan
    #[arg(long)]
    llm_best_guess: bool,

    /// Model alias or name to pass to `llm -m`
    #[arg(long, default_value = "flash")]
    llm_model: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let privilege = net::raw::detect_privilege();

    let iface = match net::interface::pick_interface(cli.interface.as_deref()) {
        Some(i) => i,
        None => {
            eprintln!("No suitable network interface found.");
            if let Some(ref name) = cli.interface {
                eprintln!("Interface '{}' not found. Available:", name);
            } else {
                eprintln!("Available interfaces:");
            }
            for i in net::interface::list_interfaces() {
                eprintln!("  {} ({})", i.name, i.ip);
            }
            std::process::exit(1);
        }
    };

    let app = app::App::new(
        iface,
        privilege,
        cli.target,
        cli.export,
        cli.no_sniff,
        identify::llm::LlmGuessConfig {
            enabled: cli.llm_best_guess,
            model: cli.llm_model,
        },
    );

    if let Err(e) = app.run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
