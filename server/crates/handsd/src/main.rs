//! handsd: creates unlock requests at boot and unlocks LUKS drives when a paired phone approves.

use std::sync::Arc;

use handsd::{config::Config, host::LinuxHost, luks::Cryptsetup, server, system, unlock};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--unlock-child") {
        system::harden(true);
        let code = match Cryptsetup::open() {
            Ok(b) => unlock::child_main(&b),
            Err(_) => 3,
        };
        std::process::exit(code);
    }

    // Before any secret can exist in this process.
    system::harden(true);

    let cfg = match Config::load(&handsd::config_path_from_args(&args)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("handsd: {e}");
            std::process::exit(1);
        }
    };
    let host = Arc::new(LinuxHost {
        cfg: cfg.clone(),
        exe: std::env::current_exe().unwrap_or_else(|_| "/usr/sbin/handsd".into()),
    });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    if let Err(e) = rt.block_on(handsd::run(cfg, host, server::inherited_listener())) {
        eprintln!("handsd: {e}");
        std::process::exit(1);
    }
}
