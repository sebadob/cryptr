// F-34 regression: shell I/O (stdin/stdout) must be multi-line and binary-safe.

use std::io::Write;
use std::process::{Command, Stdio};

fn setup_home(home: &str) {
    let key_bytes = cryptr::utils::secure_random_vec(32).unwrap();
    let key_b64 = cryptr::utils::b64_encode(&key_bytes);
    let config = format!("ENC_KEY_ACTIVE=testKey1\nENC_KEYS=\"\ntestKey1/{key_b64}\n\"\n");

    std::fs::create_dir_all(format!("{home}/.cryptr")).unwrap();
    std::fs::write(format!("{home}/.cryptr/config"), config).unwrap();
}

fn run_cryptr(home: &str, subcommand: &str, stdin_data: &[u8]) -> Vec<u8> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cryptr"))
        .arg(subcommand)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(stdin_data).unwrap();
        stdin.flush().unwrap();
    } // drop the write end -> EOF for the child

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "cryptr {subcommand} exited with {}: {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn extract_after(stdout: &[u8], marker: &[u8]) -> Vec<u8> {
    let pos = stdout
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap_or_else(|| panic!("marker {marker:?} not found in output"));
    stdout[pos + marker.len()..].to_vec()
}

#[test]
fn test_shell_io_multiline_and_binary_roundtrip() {
    let home = "./test_files/f34_home";
    let _ = std::fs::remove_dir_all(home);
    setup_home(home);

    // 1) multi-line text: internal newlines are preserved, the trailing newline
    // added by the pipe/paste is stripped (previously only the first line was read)
    let stdout = run_cryptr(home, "encrypt", b"hello\nworld\n");
    let mut b64 = extract_after(&stdout, b"Base64 encoded encrypted secret:\n");
    while matches!(b64.last(), Some(b'\n') | Some(b'\r')) {
        b64.pop();
    }

    let stdout = run_cryptr(home, "decrypt", &b64);
    let decrypted = extract_after(&stdout, b"Decrypted plain text secret:\n");
    assert_eq!(decrypted, b"hello\nworld");

    // 2) binary: all 256 byte values must round-trip exactly (previously mangled
    // by String / from_utf8_lossy in both directions)
    let binary: Vec<u8> = (0u8..=255u8).collect();
    let stdout = run_cryptr(home, "encrypt", &binary);
    let mut b64 = extract_after(&stdout, b"Base64 encoded encrypted secret:\n");
    while matches!(b64.last(), Some(b'\n') | Some(b'\r')) {
        b64.pop();
    }

    let stdout = run_cryptr(home, "decrypt", &b64);
    let decrypted = extract_after(&stdout, b"Decrypted plain text secret:\n");
    assert_eq!(decrypted, binary);

    let _ = std::fs::remove_dir_all(home);
}
