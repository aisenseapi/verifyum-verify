//! Section 13 of PROTOCOL.md, reproduced from the vector files. Reads the same
//! directory as the check program so both stay in step.

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use verifyum::*;

const DEFAULT_VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../checks/vectors");

fn load(name: &str) -> (Vec<u8>, Value) {
    let dir = PathBuf::from(std::env::var_os("VERIFYUM_VECTORS").unwrap_or_else(|| DEFAULT_VECTORS.into()));
    let bytes = std::fs::read(dir.join(name)).expect(name);
    let value = parse_json(&bytes).expect(name);
    (bytes, value)
}

#[test]
fn section_13() {
    let (_, metadata) = load("metadata.json");
    let (_, witnesses) = load("witnesses.json");
    let (hourly_bytes, hourly) = load("hourly.json");
    let (daily_bytes, daily) = load("daily.json");
    let (_, keys) = load("keys.json");

    let leaf = proof_leaf_hash(&metadata).unwrap();
    assert_eq!(leaf, "sha256:4daa8b55d67b55edaa111c2b76e184cccc2fedc88a034b023ea91170ef6c871d");

    let path = witnesses.pointer("/membership/path").unwrap();
    let root = "sha256:dbde1e168a15113d88b12c28192ed236d85b23ae5479812d930888e9c6664e54";
    assert!(verify_path(&leaf, path, root).unwrap());
    let steps = path.as_array().unwrap();
    assert_eq!(
        path_root(&leaf, &Value::Array(steps[..1].to_vec())).unwrap(),
        "sha256:09bb6980c97f13a5d28e52392351559acb23c54cee6973e398e4ed5a7d2859e4"
    );
    assert_eq!(
        path_root(&leaf, &Value::Array(steps[..2].to_vec())).unwrap(),
        "sha256:7e13f4a12603f1cdc229fa9a564e943b8a51bfda0bc12686c449a12ad95805da"
    );

    assert_eq!(checkpoint_hash(&hourly).unwrap(), "sha256:bc3653e93164e62d0bc1272b2d76eace51df7951d692a3138991c144c631728c");
    assert_eq!(checkpoint_document(&hourly).unwrap(), hourly_bytes);
    assert_eq!(hourly_bytes.len(), 549);
    assert_eq!(document_digest(&hourly).unwrap(), "sha256:b5e06851e4416d04f3911eddd593a5db1e0a1635d3f6f7f9304181c72d93e245");
    assert_eq!(checkpoint_leaf_hash(&hourly).unwrap(), "sha256:e2f07dde10fb52ba49842ed9b41679583d22e58def885753ab3ac83eb56c3e8d");
    assert_eq!(batch_id(&hourly).unwrap(), "20260831T180000Z-bc3653e93164e62d0bc1272b2d76eace51df7951d692a3138991c144c631728c");

    assert_eq!(checkpoint_hash(&daily).unwrap(), "sha256:6237cfaafaf4ad6ed3f54a4f6de7f758b7368ac1ff8bedd3e9b1f3aef0cee93a");
    assert_eq!(checkpoint_document(&daily).unwrap(), daily_bytes);
    assert_eq!(daily_bytes.len(), 560);
    assert_eq!(document_digest(&daily).unwrap(), "sha256:5b223a804f25dcb863893182f1236360b837900db628766837427c8595caff90");
    assert_eq!(sigsum_checksum_hex(&daily).unwrap(), "6c0271f184d4a8ec991edca7298e0328469749192f7067a4b9dfb3ee3847a658");
    assert_eq!(ct_hostname(&daily).unwrap(), "v1-g4mgckwi6xbzif2qrjo5pyhn65y6hxtluvqng677onzrpgcy5fgq.ct.verifyum.com");
    assert_eq!(batch_id(&daily).unwrap(), "20260831T000000Z-6237cfaafaf4ad6ed3f54a4f6de7f758b7368ac1ff8bedd3e9b1f3aef0cee93a");
    assert!(checkpoint_leaf_hash(&daily).is_err());

    let message = signing_message(&metadata).unwrap();
    assert_eq!(message.len(), 700);
    assert_eq!(hex::encode(Sha256::digest(&message)), "53d70085810193e03b114a7ba81ae7d341f22de53e622d997bda9e1efff834b3");
    assert_eq!(verify_service_signature(&metadata, &keys), Ok(true));

    // A one-byte tamper of the signed body must fail, and a devnet-only key must be unavailable.
    let mut tampered = metadata.clone();
    tampered["submitted_at"] = Value::String("2026-08-30T16:01:02Z".into());
    assert_eq!(verify_service_signature(&tampered, &keys), Ok(false));
    let mut wrong_key = metadata.clone();
    wrong_key["service_signature"]["key_id"] = Value::String("verifyum-devnet-2026-02".into());
    assert!(verify_service_signature(&wrong_key, &keys).is_err());
}
