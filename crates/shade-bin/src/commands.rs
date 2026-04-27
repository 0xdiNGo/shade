use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::cli::{Cli, Command};
use crate::config::Config;
use crate::daemon;
use crate::pki;
use crate::shadectl;

pub fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Run => run(&cli.config),
        Command::InitCa { out_dir } => init_ca(out_dir),
        Command::IssueCert {
            node_id,
            ca_dir,
            out_dir,
        } => issue_cert(node_id, ca_dir, out_dir),
        Command::IssueAdminCert {
            handle,
            ca_dir,
            out_dir,
        } => issue_admin_cert(handle, ca_dir, out_dir),
        Command::Migrate => migrate(&cli.config),
        Command::CheckConfig => check_config(&cli.config),
        Command::DumpState => dump_state(&cli.config),
        Command::Users(sub) => shadectl::users(sub, &cli.config),
        Command::Channels(sub) => shadectl::channels(sub, &cli.config),
        Command::Chanset(sub) => shadectl::chanset(sub, &cli.config),
        Command::Chattr {
            handle,
            channel,
            diff,
            client,
        } => shadectl::chattr_channel(handle, channel, diff, client, &cli.config),
        Command::Mask(sub) => shadectl::mask(sub, &cli.config),
        Command::Audit {
            limit,
            actor,
            client,
        } => shadectl::audit(*limit, actor.as_deref(), client, &cli.config),
    }
}

fn run(config_path: &Path) -> Result<()> {
    let cfg =
        Config::load(config_path).with_context(|| format!("loading {}", config_path.display()))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?;
    runtime.block_on(daemon::run(cfg))
}

fn init_ca(out_dir: &Path) -> Result<()> {
    pki::init_ca(out_dir)
}

fn issue_cert(node_id: &str, ca_dir: &Path, out_dir: &Path) -> Result<()> {
    pki::issue_cert(node_id, ca_dir, out_dir)
}

fn issue_admin_cert(handle: &str, ca_dir: &Path, out_dir: &Path) -> Result<()> {
    pki::issue_admin_cert(handle, ca_dir, out_dir)
}

fn migrate(config_path: &Path) -> Result<()> {
    let cfg =
        Config::load(config_path).with_context(|| format!("loading {}", config_path.display()))?;
    std::fs::create_dir_all(&cfg.node.data_dir)
        .with_context(|| format!("creating {}", cfg.node.data_dir.display()))?;
    let db_path = shade_store::db_path_in(&cfg.node.data_dir);
    let store = shade_store::Store::open(&db_path)
        .with_context(|| format!("opening {}", db_path.display()))?;
    let report = store
        .migrate()
        .with_context(|| format!("running migrations on {}", db_path.display()))?;
    println!(
        "applied {} pending migration(s) to {}",
        report.applied,
        db_path.display()
    );
    Ok(())
}

fn check_config(config_path: &Path) -> Result<()> {
    let cfg =
        Config::load(config_path).with_context(|| format!("loading {}", config_path.display()))?;
    let json = serde_json::to_string_pretty(&cfg).context("serializing config to json")?;
    println!("{json}");
    Ok(())
}

fn dump_state(_config: &Path) -> Result<()> {
    bail!("`shade dump-state` is not yet implemented")
}
