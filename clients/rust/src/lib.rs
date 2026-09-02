//! Verifyum verification primitives, byte-exact with the PHP reference.
//!
//! Rule numbers (R1..R11) refer to PROTOCOL.md next to this crate. Every
//! function hashes the canonical JCS form of a parsed document, never the
//! bytes as received, except `checkpoint_document` which is the one place the
//! protocol defines a whole-file byte layout.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn fail<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

pub const DIGEST_PREFIX: &str = "sha256:";

/// The reference has no cap; 64 steps covers any tree with fewer than 2^64 leaves.
pub const MAX_PATH_LEN: usize = 64;

// ---------------------------------------------------------------------------
// R1: digest

pub fn digest(payload: &[u8]) -> String {
    format!("{DIGEST_PREFIX}{}", hex::encode(Sha256::digest(payload)))
}

pub fn is_digest(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == DIGEST_PREFIX.len() + 64
        && s.starts_with(DIGEST_PREFIX)
        && b[DIGEST_PREFIX.len()..]
            .iter()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn digest_bytes(s: &str) -> Result<[u8; 32], Error> {
    if !is_digest(s) {
        return fail(format!("not a digest string: {s:?}"));
    }
    let raw = hex::decode(&s[DIGEST_PREFIX.len()..]).map_err(|e| Error(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

// ---------------------------------------------------------------------------
// R2: JCS

pub fn parse_json(bytes: &[u8]) -> Result<Value, Error> {
    serde_json::from_slice(bytes).map_err(|e| Error(format!("json parse: {e}")))
}

/// Canonical JSON bytes for `value`.
///
/// serde_json's compact encoder already matches RFC 8785 on this value subset:
/// no whitespace, BTreeMap-ordered keys, short escapes for the five named
/// controls, lowercase `\u00xx` for the rest, raw `/`, raw DEL, raw non-ASCII.
/// Only the two Unicode line terminators differ from the PHP reference, which
/// escapes them; they are patched after encoding because inside serialized
/// JSON those code points can only occur raw inside strings, so the textual
/// replacement is exact.
pub fn jcs(value: &Value) -> Result<Vec<u8>, Error> {
    check_jcs_value(value)?;
    let text = serde_json::to_string(value).map_err(|e| Error(format!("json encode: {e}")))?;
    Ok(text
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        .into_bytes())
}

fn check_jcs_value(value: &Value) -> Result<(), Error> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => {
            // The reference throws on floats; serde_json also lands here for
            // `-0`, exponents and integers outside the 64-bit range.
            if n.is_f64() {
                fail(format!("non-integer number {n}"))
            } else {
                Ok(())
            }
        }
        Value::Array(items) => items.iter().try_for_each(check_jcs_value),
        Value::Object(map) => {
            // The reference cannot tell {} from [] and no protocol document has {}.
            if map.is_empty() {
                return fail("empty object has no canonical form");
            }
            for (key, item) in map {
                if key.is_empty() || !key.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                    return fail(format!("object key is not printable ASCII: {key:?}"));
                }
                check_jcs_value(item)?;
            }
            Ok(())
        }
    }
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, Error> {
    value
        .as_object()
        .ok_or_else(|| Error(format!("{what} is not a JSON object")))
}

fn str_field<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, Error> {
    map.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error(format!("missing or non-string field {key:?}")))
}

fn digest_field<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, Error> {
    let s = str_field(map, key)?;
    if !is_digest(s) {
        return fail(format!("field {key:?} is not a digest string: {s:?}"));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// R3: checkpoint hash

pub fn checkpoint_hash(checkpoint: &Value) -> Result<String, Error> {
    let mut body = object(checkpoint, "checkpoint")?.clone();
    // Only this key is removed; previous_checkpoint_hash and merkle_root stay.
    body.remove("checkpoint_hash");
    let mut payload = b"verifyum:witness:checkpoint:v1\n".to_vec();
    payload.extend(jcs(&Value::Object(body))?);
    Ok(digest(&payload))
}

// ---------------------------------------------------------------------------
// R4: checkpoint document, document digest, external subjects

/// The exact bytes of a published checkpoint file: JCS plus one trailing LF.
/// Defined only when the declared checkpoint_hash is the R3 value.
pub fn checkpoint_document(checkpoint: &Value) -> Result<Vec<u8>, Error> {
    let map = object(checkpoint, "checkpoint")?;
    let declared = digest_field(map, "checkpoint_hash")?;
    let computed = checkpoint_hash(checkpoint)?;
    if declared != computed {
        return fail(format!("checkpoint_hash {declared} does not match recomputed {computed}"));
    }
    let mut doc = jcs(checkpoint)?;
    doc.push(b'\n');
    Ok(doc)
}

pub fn document_digest(checkpoint: &Value) -> Result<String, Error> {
    Ok(digest(&checkpoint_document(checkpoint)?))
}

fn require_kind<'a>(checkpoint: &'a Value, kind: &str) -> Result<&'a Map<String, Value>, Error> {
    let map = object(checkpoint, "checkpoint")?;
    let actual = str_field(map, "kind")?;
    if actual != kind {
        return fail(format!("expected a {kind} checkpoint, got kind {actual:?}"));
    }
    Ok(map)
}

/// Sigsum leaf checksum: sha256 over the 32 raw bytes of the daily document digest.
pub fn sigsum_checksum_hex(daily: &Value) -> Result<String, Error> {
    require_kind(daily, "daily")?;
    let message = digest_bytes(&document_digest(daily)?)?;
    Ok(hex::encode(Sha256::digest(message)))
}

/// Certificate Transparency subject: the daily merkle_root as a base32 DNS label.
pub fn ct_hostname(daily: &Value) -> Result<String, Error> {
    let map = require_kind(daily, "daily")?;
    let root = digest_bytes(digest_field(map, "merkle_root")?)?;
    Ok(format!("v1-{}.ct.verifyum.com", base32_lower_nopad(&root)))
}

fn base32_lower_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((bytes.len() * 8 + 4) / 5);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// `<period_start as YYYYMMDDTHHMMSSZ>-<hex64 of checkpoint_hash>`.
pub fn batch_id(checkpoint: &Value) -> Result<String, Error> {
    let map = object(checkpoint, "checkpoint")?;
    let start = str_field(map, "period_start")?;
    if start.len() != 20 || !start.ends_with('Z') || start.as_bytes()[10] != b'T' {
        return fail(format!("period_start is not canonical time: {start:?}"));
    }
    let compact: String = start.chars().filter(|c| *c != '-' && *c != ':').collect();
    let hash = digest_field(map, "checkpoint_hash")?;
    Ok(format!("{compact}-{}", &hash[DIGEST_PREFIX.len()..]))
}

// ---------------------------------------------------------------------------
// R5: proof leaf hash

/// Over the full metadata document, service_signature included.
pub fn proof_leaf_hash(metadata: &Value) -> Result<String, Error> {
    object(metadata, "metadata")?;
    let mut payload = b"\x00verifyum:witness:proof-leaf:v1\n".to_vec();
    payload.extend(jcs(metadata)?);
    Ok(digest(&payload))
}

// ---------------------------------------------------------------------------
// R6: checkpoint leaf hash

/// Over the 32 raw bytes of an hourly checkpoint's checkpoint_hash.
pub fn checkpoint_leaf_hash(hourly: &Value) -> Result<String, Error> {
    let map = require_kind(hourly, "hourly")?;
    let mut payload = b"\x00verifyum:witness:checkpoint-leaf:v1\n".to_vec();
    payload.extend_from_slice(&digest_bytes(digest_field(map, "checkpoint_hash")?)?);
    Ok(digest(&payload))
}

// ---------------------------------------------------------------------------
// R7: node hash

pub fn node_hash(left: &str, right: &str) -> Result<String, Error> {
    let mut payload = b"\x01verifyum:witness:node:v1\n".to_vec();
    payload.extend_from_slice(&digest_bytes(left)?);
    payload.extend_from_slice(&digest_bytes(right)?);
    Ok(digest(&payload))
}

// ---------------------------------------------------------------------------
// R8: Merkle tree construction

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Left => "left",
            Side::Right => "right",
        }
    }
}

/// `hash` is the sibling; `side` is where the sibling sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathStep {
    pub side: Side,
    pub hash: String,
}

impl PathStep {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("hash".into(), Value::String(self.hash.clone()));
        map.insert("side".into(), Value::String(self.side.as_str().into()));
        Value::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub id: String,
    pub leaf_hash: String,
    pub leaf_index: usize,
    pub path: Vec<PathStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub root: String,
    /// In id order, so `leaves[i].leaf_index == i`.
    pub leaves: Vec<Leaf>,
}

/// Builds the tree from `(id, leaf_hash)` subjects. Odd trailing nodes are
/// promoted unchanged, never hashed with themselves.
pub fn build_tree(subjects: &[(String, String)]) -> Result<Tree, Error> {
    if subjects.is_empty() {
        return fail("a tree needs at least one subject");
    }
    let mut leaves: Vec<Leaf> = Vec::with_capacity(subjects.len());
    for (id, leaf_hash) in subjects {
        if id.is_empty() {
            return fail("subject id must be non-empty");
        }
        if !is_digest(leaf_hash) {
            return fail(format!("leaf hash of {id:?} is not a digest string"));
        }
        leaves.push(Leaf {
            id: id.clone(),
            leaf_hash: leaf_hash.clone(),
            leaf_index: 0,
            path: Vec::new(),
        });
    }
    leaves.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
    if let Some(pair) = leaves.windows(2).find(|w| w[0].id == w[1].id) {
        return fail(format!("duplicate subject id {:?}", pair[0].id));
    }
    for (index, leaf) in leaves.iter_mut().enumerate() {
        leaf.leaf_index = index;
    }

    // Each level node carries the indexes of the leaves beneath it so their
    // paths can be extended as the node is paired.
    let mut level: Vec<(String, Vec<usize>)> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| (leaf.leaf_hash.clone(), vec![i]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut nodes = level.into_iter();
        while let Some((left, left_members)) = nodes.next() {
            match nodes.next() {
                Some((right, right_members)) => {
                    for &i in &left_members {
                        leaves[i].path.push(PathStep { side: Side::Right, hash: right.clone() });
                    }
                    for &i in &right_members {
                        leaves[i].path.push(PathStep { side: Side::Left, hash: left.clone() });
                    }
                    let mut members = left_members;
                    members.extend(right_members);
                    next.push((node_hash(&left, &right)?, members));
                }
                None => next.push((left, left_members)),
            }
        }
        level = next;
    }
    let root = level.pop().map(|(hash, _)| hash).unwrap_or_default();
    Ok(Tree { root, leaves })
}

// ---------------------------------------------------------------------------
// R9: path verification

/// Folds `path` (a JSON array of `{"hash","side"}` steps) from `leaf_hash`.
/// Any malformed step is an error, matching the reference, which returns
/// false rather than skipping the step.
pub fn path_root(leaf_hash: &str, path: &Value) -> Result<String, Error> {
    if !is_digest(leaf_hash) {
        return fail("leaf_hash must be a digest string");
    }
    let steps = path
        .as_array()
        .ok_or_else(|| Error("path must be a JSON array".into()))?;
    if steps.len() > MAX_PATH_LEN {
        return fail(format!("path has more than {MAX_PATH_LEN} steps"));
    }
    let mut current = leaf_hash.to_string();
    for (n, step) in steps.iter().enumerate() {
        let map = match step {
            Value::Object(map) if map.len() == 2 => map,
            _ => return fail(format!("path step {n} is not an object with exactly two keys")),
        };
        let (Some(side), Some(hash)) = (
            map.get("side").and_then(Value::as_str),
            map.get("hash").and_then(Value::as_str),
        ) else {
            return fail(format!("path step {n} lacks string side/hash"));
        };
        if !is_digest(hash) {
            return fail(format!("path step {n} hash is not a digest string"));
        }
        current = match side {
            "left" => node_hash(hash, &current)?,
            "right" => node_hash(&current, hash)?,
            other => return fail(format!("path step {n} side {other:?} is invalid")),
        };
    }
    Ok(current)
}

pub fn verify_path(leaf_hash: &str, path: &Value, root: &str) -> Result<bool, Error> {
    if !is_digest(root) {
        return fail("root must be a digest string");
    }
    Ok(path_root(leaf_hash, path)? == root)
}

// ---------------------------------------------------------------------------
// R10: service signature

/// Strict base64url per section 11.1: URL alphabet only, no padding,
/// length mod 4 != 1, and a re-encode round trip so non-zero unused
/// trailing bits are rejected.
pub fn base64url_decode_strict(input: &str) -> Result<Vec<u8>, Error> {
    if !input
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return fail("base64url: character outside the URL alphabet");
    }
    if input.len() % 4 == 1 {
        return fail("base64url: impossible length");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| Error(format!("base64url: {e}")))?;
    // The engine already rejects non-zero trailing bits; the round trip is
    // the reference's own definition of canonical and costs nothing.
    if URL_SAFE_NO_PAD.encode(&bytes) != input {
        return fail("base64url: non-canonical encoding");
    }
    Ok(bytes)
}

/// JCS of the metadata with service_signature removed; no prefix, no newline.
pub fn signing_message(metadata: &Value) -> Result<Vec<u8>, Error> {
    let mut body = object(metadata, "metadata")?.clone();
    if body.remove("service_signature").is_none() {
        return fail("metadata has no service_signature");
    }
    jcs(&Value::Object(body))
}

/// The registry public_key (still base64url) for exactly one matching entry.
pub fn select_service_key<'a>(
    registry: &'a Value,
    key_id: &str,
    network: &str,
) -> Result<&'a str, Error> {
    let keys = registry
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| Error("registry has no keys array".into()))?;
    let mut found: Option<&str> = None;
    for entry in keys {
        let Some(map) = entry.as_object() else { continue };
        let field = |k: &str| map.get(k).and_then(Value::as_str);
        let usable = field("key_id") == Some(key_id)
            && field("network") == Some(network)
            && matches!(field("status"), Some("active") | Some("retired"))
            && field("algorithm") == Some("ed25519");
        if !usable {
            continue;
        }
        let Some(public_key) = field("public_key") else { continue };
        if found.is_some() {
            return fail(format!("service key {key_id:?} on {network} is not unique"));
        }
        found = Some(public_key);
    }
    found.ok_or_else(|| Error(format!("service key {key_id:?} on {network} unavailable")))
}

/// Ok(true) only when the Ed25519 signature verifies. Decoding and length
/// problems are Ok(false); a malformed record or registry is an Err.
pub fn verify_service_signature(metadata: &Value, registry: &Value) -> Result<bool, Error> {
    let map = object(metadata, "metadata")?;
    let record = map
        .get("service_signature")
        .ok_or_else(|| Error("metadata has no service_signature".into()))?;
    let record = object(record, "service_signature")?;
    if record.len() != 3 {
        return fail("service_signature must have exactly algorithm, key_id, value");
    }
    if str_field(record, "algorithm")? != "ed25519" {
        return fail("service_signature.algorithm must be ed25519");
    }
    let key_id = str_field(record, "key_id")?;
    let value = str_field(record, "value")?;
    let network = map
        .get("anchor")
        .and_then(|a| a.get("network"))
        .and_then(Value::as_str)
        .ok_or_else(|| Error("metadata.anchor.network missing".into()))?;
    let public_key = select_service_key(registry, key_id, network)?;
    let message = signing_message(metadata)?;
    Ok(ed25519_verify(public_key, &message, value))
}

fn ed25519_verify(public_key_b64: &str, message: &[u8], signature_b64: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (
        base64url_decode_strict(public_key_b64),
        base64url_decode_strict(signature_b64),
    ) else {
        return false;
    };
    let (Ok(pk), Ok(sig)) = (
        <[u8; 32]>::try_from(pk.as_slice()),
        <[u8; 64]>::try_from(sig.as_slice()),
    ) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    // The reference verifies with libsodium, which rejects small-order keys
    // and non-canonical S; verify_strict is the matching dalek mode.
    key.verify_strict(message, &Signature::from_bytes(&sig)).is_ok()
}

// ---------------------------------------------------------------------------
// R11: commitment, memo, proof id

pub fn commitment(manifest: &Value) -> Result<String, Error> {
    let mut payload = b"verifyum:commitment:v2\n".to_vec();
    payload.extend(jcs(manifest)?);
    Ok(digest(&payload))
}

/// Lowercase Crockford base32 without i, l, o, u; first char 0..7.
pub fn is_proof_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 26
        && matches!(b[0], b'0'..=b'7')
        && b.iter().all(|c| {
            matches!(c, b'0'..=b'9' | b'a'..=b'h' | b'j' | b'k' | b'm' | b'n' | b'p'..=b't' | b'v'..=b'z')
        })
}

pub fn memo(proof_id: &str, commitment: &str) -> Result<String, Error> {
    if !is_proof_id(proof_id) {
        return fail(format!("invalid proof id {proof_id:?}"));
    }
    if !is_digest(commitment) {
        return fail(format!("invalid commitment {commitment:?}"));
    }
    Ok(format!(
        "verifyum:v2:id={proof_id};alg=sha256;commitment={}",
        &commitment[DIGEST_PREFIX.len()..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jcs_str(v: &Value) -> String {
        String::from_utf8(jcs(v).unwrap()).unwrap()
    }

    #[test]
    fn jcs_escaping_and_order() {
        let v = json!({" ":8,"B":3,"_":4,"a":6,"a0":5,"b":1,"~":7});
        assert_eq!(jcs_str(&v), r#"{" ":8,"B":3,"_":4,"a":6,"a0":5,"b":1,"~":7}"#);
        let v = json!({"s":"a/b<c>&'\"\\\u{0008}\t\n\u{000c}\r\u{001f}\u{000b}\u{0000}\u{007f}æøå 日本\u{2028}"});
        assert_eq!(
            jcs_str(&v),
            "{\"s\":\"a/b<c>&'\\\"\\\\\\b\\t\\n\\f\\r\\u001f\\u000b\\u0000\u{7f}æøå 日本\\u2028\"}"
        );
        assert_eq!(
            jcs_str(&json!([-5, 0, 9007199254740993u64, null, true])),
            "[-5,0,9007199254740993,null,true]"
        );
    }

    #[test]
    fn jcs_rejects() {
        assert!(jcs(&parse_json(b"{\"a\":1.0}").unwrap()).is_err());
        assert!(jcs(&parse_json(b"{\"a\":1e2}").unwrap()).is_err());
        assert!(jcs(&parse_json(b"{\"a\":-0}").unwrap()).is_err());
        assert!(jcs(&parse_json(b"{\"a\":{}}").unwrap()).is_err());
        assert!(jcs(&parse_json(b"{\"\":1}").unwrap()).is_err());
        assert!(jcs(&parse_json("{\"\u{e6}\":1}".as_bytes()).unwrap()).is_err());
        assert!(parse_json(b"{\"a\":\"\xff\"}").is_err());
        assert!(parse_json(b"{\"a\":01}").is_err());
    }

    #[test]
    fn r11_fixed_vector() {
        let manifest = json!({
            "file": {"hash": {"algorithm": "sha256",
                "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                "size": "1234"},
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "protocol": "verifyum",
            "version": 2
        });
        let c = commitment(&manifest).unwrap();
        assert_eq!(c, "sha256:8412d6863b2328c6a7ff94d49ec087b18b6fc2db0b60da8b8dea97d30ac0612b");
        let m = memo("0123456789abcdefghjkmnpqrs", &c).unwrap();
        assert_eq!(m.len(), 128);
        assert!(m.starts_with("verifyum:v2:id=0123456789abcdefghjkmnpqrs;alg=sha256;commitment=8412d686"));
        assert!(!is_proof_id("8123456789abcdefghjkmnpqrs"));
        assert!(!is_proof_id("0123456789abcdefghjkmnpqro"));
        assert!(!is_digest("SHA256:8412d6863b2328c6a7ff94d49ec087b18b6fc2db0b60da8b8dea97d30ac0612b"));
    }

    #[test]
    fn base64url_strictness() {
        assert_eq!(base64url_decode_strict("AA").unwrap(), vec![0]);
        assert_eq!(base64url_decode_strict("AQ").unwrap(), vec![1]);
        assert_eq!(base64url_decode_strict("-_8").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(base64url_decode_strict("").unwrap(), Vec::<u8>::new());
        for bad in ["AB", "Af", "-_", "-_9", "A", "AA==", "AA\n", "A+", "A/"] {
            assert!(base64url_decode_strict(bad).is_err(), "{bad:?} should be rejected");
        }
        let pk = base64url_decode_strict("ZFGf-9Iesp57Z4rPSsdIsO6izjs3sM4hsWwabfg_X5o").unwrap();
        assert_eq!(hex::encode(&pk), "64519ffbd21eb29e7b678acf4ac748b0eea2ce3b37b0ce21b16c1a6df83f5f9a");
    }

    #[test]
    fn five_leaf_tree_shape() {
        let subjects: Vec<(String, String)> = ["e", "c", "a", "d", "b"]
            .iter()
            .map(|id| (id.to_string(), digest(id.as_bytes())))
            .collect();
        let tree = build_tree(&subjects).unwrap();
        let h = |l: &str, r: &str| node_hash(l, r).unwrap();
        let [a, b, c, d, e]: [String; 5] = ["a", "b", "c", "d", "e"].map(|id| digest(id.as_bytes()));
        let ab = h(&a, &b);
        let cd = h(&c, &d);
        let abcd = h(&ab, &cd);
        assert_eq!(tree.root, h(&abcd, &e));
        let ids: Vec<&str> = tree.leaves.iter().map(|l| l.id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "c", "d", "e"]);
        let sides = |i: usize| tree.leaves[i].path.iter().map(|s| s.side).collect::<Vec<_>>();
        assert_eq!(sides(2), [Side::Right, Side::Left, Side::Right]);
        assert_eq!(sides(4), [Side::Left]);
        assert_eq!(tree.leaves[4].path[0].hash, abcd);
        for leaf in &tree.leaves {
            let path = Value::Array(leaf.path.iter().map(PathStep::to_value).collect());
            assert!(verify_path(&leaf.leaf_hash, &path, &tree.root).unwrap());
        }
        let single = build_tree(&subjects[..1]).unwrap();
        assert_eq!(single.root, subjects[0].1);
        assert!(single.leaves[0].path.is_empty());
        let dup = build_tree(&[subjects[0].clone(), subjects[0].clone()]);
        assert!(dup.is_err());
    }

    #[test]
    fn path_rejections() {
        let leaf = digest(b"leaf");
        let sib = digest(b"sib");
        assert!(verify_path(&leaf, &json!([]), &leaf).unwrap());
        assert!(verify_path(&leaf, &json!([{"side":"Left","hash":sib}]), &leaf).is_err());
        assert!(verify_path(&leaf, &json!([{"side":"left","hash":sib,"x":1}]), &leaf).is_err());
        assert!(verify_path(&leaf, &json!([{"side":"left"}]), &leaf).is_err());
        assert!(verify_path(&leaf, &json!([{"side":"left","hash":"abc"}]), &leaf).is_err());
        assert!(verify_path(&leaf, &json!({}), &leaf).is_err());
        assert!(verify_path("leaf", &json!([]), &leaf).is_err());
    }

    #[test]
    fn base32_label_length() {
        assert_eq!(base32_lower_nopad(&[0u8; 32]).len(), 52);
        assert_eq!(base32_lower_nopad(b"foobar"), "mzxw6ytboi");
    }
}
