//! handsd library. `state` is the pure protocol state machine; the rest is wiring (see docs/protocol.md).
pub mod config;
pub mod daemon;
pub mod host;
pub mod luks;
pub mod server;
pub mod state;
pub mod store;
pub mod sysinfo;
pub mod system;
pub mod unlock;

use std::path::PathBuf;
use std::sync::Arc;

/// Runs the daemon until killed.
pub async fn run(
    cfg: config::Config,
    host: Arc<dyn host::Host>,
    listener: Option<std::net::TcpListener>,
) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    let store = store::Store::open(&cfg.state_dir).map_err(io)?;
    let identity = store.identity().map_err(io)?;
    let tls = store.tls().map_err(io)?;
    let acceptor = server::tls_acceptor(&tls).map_err(io)?;
    std::fs::create_dir_all(&cfg.run_dir).map_err(io)?;

    let listener = match listener {
        Some(l) => tokio::net::TcpListener::from_std(l).map_err(io)?,
        None => tokio::net::TcpListener::bind(&cfg.listen)
            .await
            .map_err(io)?,
    };
    let ctx = daemon::Ctx::new(cfg, identity, tls.spki_sha256, store, host);
    let control = server::bind_control(&ctx).map_err(io)?;

    let c = ctx.clone();
    let _ = tokio::task::spawn_blocking(move || c.startup_sync()).await;
    eprintln!("handsd: ready");
    tokio::join!(
        server::serve_http(ctx.clone(), listener, acceptor),
        server::serve_control(ctx, control)
    );
    Ok(())
}

pub fn config_path_from_args(args: &[String]) -> PathBuf {
    args.iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| "/etc/server-hands/config.toml".into())
}
