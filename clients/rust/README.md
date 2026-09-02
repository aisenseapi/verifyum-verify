# Verifyum verification primitives, Rust port

Library `verifyum` (src/lib.rs) implements R1 to R11 of PROTOCOL.md; the binary
`check` (src/bin/check.rs) is THE CHECK PROGRAM.

Build and run, from this directory:

    cargo build --release
    target/release/check

`check` takes no arguments. It reads `metadata.json`, `witnesses.json`,
`hourly.json`, `daily.json` and `keys.json` from the directory named by the
environment variable `VERIFYUM_VECTORS` (default: the scratchpad `vectors`
directory baked into `src/bin/check.rs`), prints the eleven `name=value` result
lines to stdout and nothing else, and exits 0 only when every `*_matches` line,
`path_matches_checkpoint` and `service_signature_valid` are true. Diagnostics go
to stderr. Exit 1 means a value did not match, exit 2 means an input could not be
read or parsed.

`cargo test` runs the unit tests (R11 fixed vector, JCS escaping and
rejections, strict base64url, the five-leaf tree shape, R9 rejections) and
tests/live_vectors.rs, which pins every section 13 value against the vector
files, including R6, the CT hostname, both batch ids and the 700-byte signing
message.

No network is used anywhere. Section 3 field-level validation (exact key sets,
canonical time, period arithmetic) is not implemented; the hashes are defined
independently of it, and `checkpoint_document` still refuses a checkpoint whose
`checkpoint_hash` is not its R3 value.

JCS notes: serde_json is built without `preserve_order`, so objects serialize
with byte-ordered keys; `to_string` emits `/` and non-ASCII raw and `\u00xx`
lowercase for controls, which the `jcs_escaping_and_order` test pins. U+2028 and
U+2029 are escaped after encoding to match the PHP reference.
