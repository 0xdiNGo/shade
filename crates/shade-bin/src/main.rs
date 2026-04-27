use std::process::ExitCode;

use clap::Parser;

mod admin_tls;
mod cli;
mod commands;
mod config;
mod daemon;
mod op_observer;
mod pki;
mod shadectl;
mod shutdown;
mod telemetry;

fn main() -> ExitCode {
    // rustls 0.23 requires an explicit crypto provider when no
    // default-feature one is selected. Pick `ring` once at startup so
    // every later `ServerConfig::builder()` / `ClientConfig::builder()`
    // call resolves without panicking.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        // Already installed (only happens in a hot-reload test harness).
    }

    let cli = cli::Cli::parse();
    match commands::dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
