//! The unlock child: a short-lived process that receives passphrases on stdin (the normative plaintext
//! format, never argv/env/files), activates the containers and reports one result per drive on stdout.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use hands_proto::codec::{uuid_format, uuid_parse};
use hands_proto::seal::{decode_plaintext, encode_plaintext};
use hands_proto::Passphrase;
use zeroize::Zeroizing;

use crate::luks::{self, LuksBackend, UnlockResult};

/// Parent side: runs the child (optionally inside a transient systemd scope with a larger memory cap).
pub fn run_child(
    wrapper: &[String],
    exe: &std::path::Path,
    entries: &[([u8; 16], Passphrase)],
) -> Vec<([u8; 16], UnlockResult)> {
    let failed = || {
        entries
            .iter()
            .map(|(u, _)| (*u, UnlockResult::Error))
            .collect::<Vec<_>>()
    };
    let refs: Vec<([u8; 16], &[u8])> = entries.iter().map(|(u, p)| (*u, p.expose())).collect();
    let Ok(plain) = encode_plaintext(&refs) else {
        return failed();
    };

    let mut cmd = match wrapper.split_first() {
        Some((prog, rest)) => {
            let mut c = Command::new(prog);
            c.args(rest).arg(exe);
            c
        }
        None => Command::new(exe),
    };
    cmd.arg("--unlock-child")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let Ok(mut child) = cmd.spawn() else {
        return failed();
    };
    {
        let mut stdin = child.stdin.take().expect("piped");
        if stdin.write_all(&plain).is_err() {
            let _ = child.kill();
            return failed();
        }
    }
    drop(plain);
    let mut out = String::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    let _ = child.wait();
    let mut results: Vec<([u8; 16], UnlockResult)> = out
        .lines()
        .filter_map(|l| {
            let (u, r) = l.split_once(' ')?;
            Some((uuid_parse(u).ok()?, UnlockResult::parse(r)))
        })
        .collect();
    // Anything the child did not report counts as failed.
    for (u, _) in entries {
        if !results.iter().any(|(r, _)| r == u) {
            results.push((*u, UnlockResult::Error));
        }
    }
    results.retain(|(u, _)| entries.iter().any(|(e, _)| e == u));
    results
}

/// Child side. Returns the process exit code.
pub fn child_main(backend: &dyn LuksBackend) -> i32 {
    let mut buf = Zeroizing::new(Vec::new());
    if std::io::stdin().lock().read_to_end(&mut buf).is_err() {
        return 2;
    }
    let Ok(entries) = decode_plaintext(&buf) else {
        return 2;
    };
    drop(buf);
    let mut out = std::io::stdout().lock();
    for (uuid, pass) in &entries {
        let r = unlock_one(backend, uuid, pass);
        let _ = writeln!(out, "{} {}", uuid_format(uuid), r.as_str());
    }
    0
}

pub fn unlock_one(backend: &dyn LuksBackend, uuid: &[u8; 16], pass: &Passphrase) -> UnlockResult {
    let Some(kernel) = luks::kernel_name(uuid) else {
        return UnlockResult::Error;
    };
    if luks::is_active(&kernel) {
        return UnlockResult::AlreadyOpen;
    }
    backend.activate(
        &luks::by_uuid(uuid),
        &luks::mapper_name(&kernel),
        pass.expose(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn child_protocol_round_trip_and_missing_results_fail_closed() {
        let (a, b) = ([1u8; 16], [2u8; 16]);
        let dir = std::env::temp_dir().join(format!("hk-child-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("fake-child");
        // Reads the plaintext, reports only the first drive: the second must be treated as failed.
        std::fs::write(
            &exe,
            format!(
                "#!/bin/sh\ncat >/dev/null\necho '{} bad_passphrase'\n",
                uuid_format(&a)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let entries = vec![
            (a, Passphrase::from_bytes(b"x".to_vec())),
            (b, Passphrase::from_bytes(b"y".to_vec())),
        ];
        let r = run_child(&[], &exe, &entries);
        assert_eq!(
            r,
            vec![(a, UnlockResult::BadPassphrase), (b, UnlockResult::Error)]
        );

        let r = run_child(&[], &dir.join("does-not-exist"), &entries);
        assert!(r.iter().all(|(_, x)| *x == UnlockResult::Error));
        std::fs::remove_dir_all(dir).ok();
    }
}
