use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Shade IRC bot daemon and operator CLI.
#[derive(Parser, Debug)]
#[command(name = "shade", version, about, long_about = None)]
pub struct Cli {
    /// Path to the Shade configuration file.
    #[arg(
        long,
        short,
        env = "SHADE_CONFIG",
        default_value = "/etc/shade/shade.toml",
        global = true
    )]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the Shade daemon.
    Run,

    /// Generate a new botnet certificate authority.
    InitCa {
        /// Directory to write the new CA bundle, key, and metadata.
        #[arg(long)]
        out_dir: PathBuf,
    },

    /// Issue a node certificate signed by the botnet CA.
    IssueCert {
        /// Stable identifier for the node (used as Subject CN and SAN).
        #[arg(long)]
        node_id: String,
        /// Directory containing the botnet CA created by `init-ca`.
        #[arg(long)]
        ca_dir: PathBuf,
        /// Directory to write the issued cert and key.
        #[arg(long)]
        out_dir: PathBuf,
    },

    /// Run pending database migrations against the configured data directory.
    Migrate,

    /// Parse the config file and print the normalized result as JSON.
    CheckConfig,

    /// Dump the current SQLite state as JSON.
    DumpState,
}
