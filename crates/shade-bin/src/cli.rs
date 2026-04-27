use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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

    /// Issue an admin client certificate signed by the botnet CA.
    ///
    /// Used to authenticate operators and `shadectl` to the admin
    /// listener. Subject CN equals the user handle, with EKU=clientAuth
    /// (and no SAN — these certs must never serve as a server identity).
    IssueAdminCert {
        /// User handle. Becomes the cert Subject CN and the audit
        /// `actor` for every request issued with this cert.
        #[arg(long)]
        handle: String,
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

    /// Manage users via the admin API.
    #[command(subcommand)]
    Users(UsersCommand),

    /// Manage channels via the admin API.
    #[command(subcommand)]
    Channels(ChannelsCommand),

    /// Manage per-channel chanset settings.
    #[command(subcommand)]
    Chanset(ChansetCommand),

    /// Apply a flag diff to a user's per-channel privileges (Wraith chattr).
    Chattr {
        /// User handle.
        handle: String,
        /// Channel name (e.g. `#shade-test`).
        channel: String,
        /// Flag diff (`+ov-d`).
        diff: String,
        #[command(flatten)]
        client: ClientArgs,
    },

    /// Manage masks (bans / exempts / invites) on a channel.
    #[command(subcommand)]
    Mask(MaskCommand),

    /// Show recent audit log entries.
    Audit {
        /// Maximum number of entries to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Filter to entries whose actor contains this substring.
        #[arg(long)]
        actor: Option<String>,
        #[command(flatten)]
        client: ClientArgs,
    },

    /// Exchange a handle + password for a bearer token.
    ///
    /// Reads the password from stdin (no echo) unless `--password-stdin`
    /// makes it explicit. Prints `{ "token": "...", "expires_at": ms }`
    /// to stdout — pipe through `jq -r .token` to extract the token
    /// string for `SHADECTL_TOKEN`.
    Login {
        /// Handle to authenticate as.
        #[arg(long)]
        handle: String,
        /// Read the password as the entire first line of stdin.
        /// Without this flag the CLI prompts on the controlling tty.
        #[arg(long)]
        password_stdin: bool,
        #[command(flatten)]
        client: ClientArgs,
    },
}

/// Common options for any subcommand that talks to the admin API.
#[derive(Args, Debug, Clone)]
pub struct ClientArgs {
    /// Admin API base URL (e.g. `https://127.0.0.1:8443`). Defaults to
    /// the admin listener from the config file. Scheme defaults to
    /// `https` when `--cert` is supplied, `http` otherwise.
    #[arg(long, env = "SHADECTL_BASE")]
    pub base: Option<String>,

    /// Actor identifier sent in the `X-Actor` header for audit purposes.
    /// Ignored when the daemon is running with mTLS enforced — the
    /// audit actor is taken from the verified client cert subject CN.
    /// Defaults to `cli:$USER` when neither flag nor env is set.
    #[arg(long, env = "SHADECTL_ACTOR")]
    pub actor: Option<String>,

    /// PEM-encoded admin client certificate (issued by
    /// `shade issue-admin-cert`). Required to talk to a daemon with
    /// `admin.require_mtls = true`.
    #[arg(long, env = "SHADECTL_CERT")]
    pub cert: Option<PathBuf>,

    /// PEM-encoded private key matching `--cert`.
    #[arg(long, env = "SHADECTL_KEY")]
    pub key: Option<PathBuf>,

    /// PEM bundle of CAs trusted for the admin listener's server cert.
    /// Defaults to the botnet CA at `node.tls.ca_bundle` from the config
    /// file (the same root that signs admin client certs).
    #[arg(long, env = "SHADECTL_CA_BUNDLE")]
    pub ca_bundle: Option<PathBuf>,

    /// Bearer token issued by `shade login` or the in-channel TOKEN
    /// flow. Sent as `Authorization: Bearer <token>` and used to
    /// authenticate when the daemon does not have an mTLS client cert
    /// for this operator.
    #[arg(long, env = "SHADECTL_TOKEN")]
    pub token: Option<String>,

    /// Pretty-print JSON output (multi-line, indented).
    #[arg(long)]
    pub pretty: bool,
}

#[derive(Subcommand, Debug)]
pub enum UsersCommand {
    /// List all users.
    List {
        #[command(flatten)]
        client: ClientArgs,
    },
    /// Show one user.
    Show {
        handle: String,
        #[command(flatten)]
        client: ClientArgs,
    },
    /// Create or update a user. Idempotent on handle.
    Upsert {
        handle: String,
        /// Absolute global flag set (e.g. `+a`).
        #[arg(long)]
        flags: Option<String>,
        /// Mark as a bot account.
        #[arg(long)]
        bot: bool,
        /// Free-form comment.
        #[arg(long)]
        comment: Option<String>,
        /// Hostmasks for passive identification (repeatable).
        #[arg(long = "host", value_name = "MASK")]
        hosts: Vec<String>,
        #[command(flatten)]
        client: ClientArgs,
    },
    /// Delete a user.
    Delete {
        handle: String,
        #[command(flatten)]
        client: ClientArgs,
    },
    /// Apply a flag diff to the user's *global* flag set (`+a-x`).
    Chattr {
        handle: String,
        diff: String,
        #[command(flatten)]
        client: ClientArgs,
    },
}

#[derive(Subcommand, Debug)]
pub enum ChannelsCommand {
    List {
        #[command(flatten)]
        client: ClientArgs,
    },
    Show {
        name: String,
        #[command(flatten)]
        client: ClientArgs,
    },
    Upsert {
        name: String,
        #[command(flatten)]
        client: ClientArgs,
    },
    Delete {
        name: String,
        #[command(flatten)]
        client: ClientArgs,
    },
}

#[derive(Subcommand, Debug)]
pub enum ChansetCommand {
    Get {
        name: String,
        #[command(flatten)]
        client: ClientArgs,
    },
    /// Update one or more chanset fields.
    Put {
        name: String,
        #[arg(long)]
        flags: Option<String>,
        #[arg(long = "mode-pls")]
        mode_pls: Option<String>,
        #[arg(long = "mode-mns")]
        mode_mns: Option<String>,
        /// Channel limit to enforce. Use `--no-limit` to clear.
        #[arg(long)]
        limit: Option<i32>,
        #[arg(long, conflicts_with = "limit")]
        no_limit: bool,
        #[arg(long)]
        key: Option<String>,
        #[arg(long, conflicts_with = "key")]
        no_key: bool,
        #[arg(long)]
        topic: Option<String>,
        #[arg(long, conflicts_with = "topic")]
        no_topic: bool,
        #[command(flatten)]
        client: ClientArgs,
    },
}

#[derive(Subcommand, Debug)]
pub enum MaskCommand {
    /// List masks on a channel.
    List {
        channel: String,
        /// Mask kind: `ban`, `exempt`, `invite`.
        #[arg(long, default_value = "ban")]
        kind: String,
        #[command(flatten)]
        client: ClientArgs,
    },
    /// Add a mask.
    Add {
        channel: String,
        mask: String,
        #[arg(long, default_value = "ban")]
        kind: String,
        #[arg(long)]
        reason: Option<String>,
        /// Expiry in Unix milliseconds.
        #[arg(long)]
        expires_at: Option<i64>,
        #[arg(long)]
        sticky: bool,
        #[command(flatten)]
        client: ClientArgs,
    },
    /// Remove a mask by ULID.
    Remove {
        id: String,
        #[command(flatten)]
        client: ClientArgs,
    },
}
