use std::process::ExitCode;

use clap::Parser;

mod cli;
mod commands;
mod config;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    match commands::dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
