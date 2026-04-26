//! Process-wide tracing initialization.

use anyhow::Context;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LoggingConfig;

/// Initialize the global tracing subscriber from the parsed [`LoggingConfig`].
///
/// `format = "json"` emits ndjson to stdout (the default; what systemd /
/// journald / container log collectors expect). `format = "text"` emits a
/// human-readable colored format for local dev.
///
/// The `level` field is parsed as a `tracing-subscriber` `EnvFilter`
/// directive, so values like `info`, `shade=debug`, or
/// `shade=trace,hyper=warn` all work.
pub fn init(cfg: &LoggingConfig) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_new(&cfg.level)
        .with_context(|| format!("parsing log filter `{}`", cfg.level))?;

    let registry = tracing_subscriber::registry().with(env_filter);

    match cfg.format.as_str() {
        "json" => registry
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true),
            )
            .try_init()
            .context("initializing tracing (json)")?,
        "text" => registry
            .with(fmt::layer())
            .try_init()
            .context("initializing tracing (text)")?,
        other => anyhow::bail!("unknown log format `{other}`; expected `json` or `text`"),
    }

    Ok(())
}
