//! THE CHECK PROGRAM: reproduces the live vectors with no network and no
//! arguments. Only the fixed result lines go to stdout; everything else is a
//! diagnostic on stderr.

use serde_json::Value;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use verifyum::{
    checkpoint_document, checkpoint_hash, document_digest, jcs, parse_json, path_root,
    proof_leaf_hash, sigsum_checksum_hex, verify_service_signature, Error,
};

const DEFAULT_VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../checks/vectors");

/// Kept as JSON text so the probe exercises the parser as well as the encoder.
const PROBE: &str = r#"{"b":1,"a":"x<y&z/\u00e9","n":null,"t":true,"arr":[2,"s",{"z":0,"y":[]}]}"#;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("check: {e}");
            ExitCode::from(2)
        }
    }
}

fn load(dir: &Path, name: &str) -> Result<(Vec<u8>, Value), Error> {
    let path = dir.join(name);
    let bytes = fs::read(&path).map_err(|e| Error(format!("{}: {e}", path.display())))?;
    let value = parse_json(&bytes).map_err(|e| Error(format!("{name}: {e}")))?;
    Ok((bytes, value))
}

fn declared<'a>(doc: &'a Value, pointer: &str) -> Result<&'a str, Error> {
    doc.pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| Error(format!("missing string at {pointer}")))
}

/// R3 over a checkpoint file plus the byte-identity diagnostic of R4.
fn checkpoint_lines(name: &str, bytes: &[u8], doc: &Value) -> Result<(String, bool), Error> {
    let computed = checkpoint_hash(doc)?;
    let matches = computed == declared(doc, "/checkpoint_hash")?;
    match checkpoint_document(doc) {
        Ok(canonical) if canonical == bytes => {}
        Ok(_) => eprintln!("warning: {name} bytes differ from the canonical checkpoint document"),
        Err(e) => eprintln!("warning: {name}: {e}"),
    }
    Ok((computed, matches))
}

fn run() -> Result<bool, Error> {
    let dir = PathBuf::from(env::var_os("VERIFYUM_VECTORS").unwrap_or_else(|| DEFAULT_VECTORS.into()));
    let (_, metadata) = load(&dir, "metadata.json")?;
    let (_, witnesses) = load(&dir, "witnesses.json")?;
    let (hourly_bytes, hourly) = load(&dir, "hourly.json")?;
    let (daily_bytes, daily) = load(&dir, "daily.json")?;
    let (_, keys) = load(&dir, "keys.json")?;

    let leaf = proof_leaf_hash(&metadata)?;
    if declared(&witnesses, "/membership/leaf_hash")? != leaf {
        eprintln!("warning: membership.leaf_hash differs from the recomputed proof leaf hash");
    }
    let path = witnesses
        .pointer("/membership/path")
        .ok_or_else(|| Error("witnesses.json has no membership.path".into()))?;
    let root = path_root(&leaf, path)?;
    let path_matches = root == declared(&witnesses, "/checkpoint/merkle_root")?;

    let (hourly_hash, hourly_matches) = checkpoint_lines("hourly.json", &hourly_bytes, &hourly)?;
    let (daily_hash, daily_matches) = checkpoint_lines("daily.json", &daily_bytes, &daily)?;

    // Both R4 values are only defined when the daily checkpoint_hash is the R3 value.
    let (daily_doc_digest, daily_sigsum) = match (document_digest(&daily), sigsum_checksum_hex(&daily)) {
        (Ok(d), Ok(s)) => (d, s),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("warning: daily.json: {e}");
            ("invalid".to_string(), "invalid".to_string())
        }
    };

    let signature_valid = match verify_service_signature(&metadata, &keys) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: service signature: {e}");
            false
        }
    };

    let probe = String::from_utf8(jcs(&parse_json(PROBE.as_bytes())?)?)
        .map_err(|e| Error(format!("probe is not UTF-8: {e}")))?;

    let lines = [
        format!("proof_leaf_hash={leaf}"),
        format!("path_root={root}"),
        format!("path_matches_checkpoint={path_matches}"),
        format!("hourly_checkpoint_hash={hourly_hash}"),
        format!("hourly_matches={hourly_matches}"),
        format!("daily_checkpoint_hash={daily_hash}"),
        format!("daily_matches={daily_matches}"),
        format!("daily_document_digest={daily_doc_digest}"),
        format!("daily_sigsum_checksum={daily_sigsum}"),
        format!("service_signature_valid={signature_valid}"),
        format!("jcs_probe={probe}"),
    ];
    let mut text = lines.join("\n");
    text.push('\n');
    // Written as raw bytes so the probe's non-ASCII reaches stdout as UTF-8 on every platform.
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(text.as_bytes())
        .and_then(|()| handle.flush())
        .map_err(|e| Error(format!("stdout: {e}")))?;

    Ok(path_matches && hourly_matches && daily_matches && signature_valid)
}
