# Verifyum verification primitives, byte-exact specification

Reviewed against the PHP reference on 2026-09-02:

- `code/php/libs/func_verifyum_witness.php` (witness digests, checkpoints, Merkle tree, path verification, validation)
- `code/php/libs/func_verifyum.php` (`verifyum_jcs_encode`, commitment, memo, proof id)
- `code/php/libs/func_verifyum_services.php` (base64url, Ed25519 signing and verification)
- `code/php/tools/check-protocol.php` (fixed commitment vector)
- `code/php/services/witness-publisher.php` (what is submitted to Sigsum)

Every rule below was executed with the real PHP functions against the live vectors in section 13, and the Ed25519 signature was additionally verified with an independent implementation (Python `cryptography`) over the exact message bytes produced by the PHP encoder. A port that reproduces section 13 is byte-compatible.

---

## 0. Notation

- `sha256(x)`: the raw 32-byte SHA-256 of the byte string `x`.
- `hex(b)`: lowercase hexadecimal, two characters per byte, no prefix.
- **digest string**: the ASCII string `"sha256:"` followed by exactly 64 lowercase hex characters. Regex: `^sha256:[0-9a-f]{64}$`. Uppercase hex is invalid. This is the only digest form that appears in documents.
- `bytes(d)`: the 32 raw bytes obtained by hex-decoding the 64 characters after `"sha256:"` of a digest string. Reject anything that is not a valid digest string.
- `||`: byte concatenation.
- All string literals are UTF-8 bytes. `\n` is the single byte 0x0A. `\x00` and `\x01` are single bytes. There is never a trailing newline unless the rule says so.
- "JSON value" means the parsed form of a document; hashing is always performed on the re-serialized canonical form (section 2), never on the bytes as received, except where a rule explicitly hashes a whole document (section 5).
- Comparison of hashes may be constant-time but need not be; the reference uses constant-time comparison for its own defence, it does not change results.

---

## 1. R1: digest

```
digest(payload) = "sha256:" || hex(sha256(payload))
```

`payload` is an arbitrary byte string. The output is a digest string.

---

## 2. R2: JCS, canonical JSON

`JCS(value)` is the RFC 8785 canonical serialization restricted to the value subset Verifyum uses. Output is a UTF-8 byte string with no whitespace and no trailing newline.

### 2.1 Value subset (what the encoder accepts)

| JSON type | Rendering | Notes |
|---|---|---|
| `null` | `null` | |
| boolean | `true` / `false` | |
| integer | shortest decimal, optional leading `-`, no `+`, no leading zeros, no exponent, no fraction | The reference uses a signed 64-bit integer. Every integer in these documents fits in 53 bits (slot, version, counts, indexes). A port MUST reject any number with a fraction or exponent and any non-integer; the reference throws on floats. |
| string | see 2.3 | Must be valid UTF-8; invalid UTF-8 is rejected. |
| array | `[` elements joined by `,` `]` | Order preserved. Empty array is `[]`. |
| object | `{` `"key":value` pairs joined by `,` `}` | Keys sorted per 2.2. Duplicate keys cannot exist after parsing; if your parser can surface duplicates, reject them. |

### 2.2 Object keys and their order

- Every key MUST match `^[\x20-\x7e]+$`: non-empty, printable ASCII only. The reference rejects any other key (including the empty string, and including keys that look like integers such as `"1"`, because its runtime converts them to integers). A port MAY reject such keys; it MUST NOT emit them.
- Keys are sorted in ascending **byte order** (`strcmp`, i.e. unsigned byte comparison, a shorter prefix sorts first). Because keys are restricted to ASCII, this is identical to RFC 8785's UTF-16 code unit order, to JavaScript's default `Array.prototype.sort()`, to Python's `sort_keys=True`, to Go's map key ordering in `encoding/json`, and to Rust's `BTreeMap<String, _>`.
- Example: `{" ":8,"B":3,"_":4,"a":6,"a0":5,"b":1,"~":7}` (space < uppercase < `_` < lowercase < `~`; `"a"` sorts before `"a0"`).

**Empty-object trap.** The reference cannot distinguish an empty object from an empty array and encodes both as `[]`. No hashed Verifyum document contains an empty object (every object has a fixed, non-empty field set), so a port never has to produce this. If a port ever meets an empty object in this protocol, treat it as invalid rather than guessing.

### 2.3 String escaping

Exactly RFC 8785 / ECMAScript `JSON.stringify` rules, with one documented deviation:

- `"` becomes `\"`, `\` becomes `\\`.
- Control characters U+0000..U+001F: `\b` (0x08), `\t` (0x09), `\n` (0x0A), `\f` (0x0C), `\r` (0x0D); all others as `\u00XX` with **lowercase** hex (`\u001f`, `\u000b`, `\u0000`).
- `/` is **NOT** escaped (`"a/b"`). This matters: every schema URL contains `https://`.
- `<`, `>`, `&`, `'` are NOT escaped.
- DEL (U+007F) is emitted raw (byte 0x7F).
- Non-ASCII characters are emitted raw as UTF-8 (`"æøå 日本"`), NOT as `\uXXXX`.
- **Deviation:** the reference (PHP `json_encode` without `JSON_UNESCAPED_LINE_TERMINATORS`) emits U+2028 as `\u2028` and U+2029 as `\u2029`. RFC 8785, Node `JSON.stringify` and Python `json.dumps` emit them raw. Go's `encoding/json` escapes them unconditionally, matching PHP. This is unreachable in practice: every string field in a hashed Verifyum document is constrained by validation (section 3) to ASCII, except `service_signature.key_id` and the registry `key_id`, which the signer restricts to `^[A-Za-z0-9._-]{1,64}$`. A port SHOULD reject any non-ASCII string in these documents; if it implements general JCS, it MUST follow PHP for U+2028/U+2029 to stay hash-compatible.

### 2.4 Per-language guidance

- **Go**: `enc := json.NewEncoder(&buf); enc.SetEscapeHTML(false); enc.Encode(v)`; strip the trailing `\n` the Encoder adds. Serialize from `map[string]any` (sorted keys) or from a deterministic struct with fields declared in sorted order; decode with `dec.UseNumber()` and reject any `json.Number` that is not an integer. Without `SetEscapeHTML(false)` you get `\u003c`, `\u003e`, `\u0026`, which breaks every hash even though no document currently contains those characters.
- **Rust**: `serde_json::Value` with the default (non-`preserve_order`) feature uses a `BTreeMap`, giving byte-ordered keys; `serde_json::to_string(&value)` produces no whitespace, raw non-ASCII, `\b \t \n \f \r` short escapes and lowercase `\u00XX` for other controls, raw `/` and raw DEL. Reject any `Value::Number` that is `is_f64()`. Do not enable `preserve_order`.
- **Python**: `json.dumps(v, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")` is byte-identical for this subset (verified against the live metadata document). Reject floats before encoding.
- **Node**: the `canonicalize()` in `static/client-verifyum.mjs` (recursive `Object.keys().sort()` with `JSON.stringify` for scalars, `undefined`-valued keys dropped) is the reference JavaScript implementation.

---

## 3. Documents and their validation

Hash rules do not depend on validation, but a verifier that skips validation can be fed nonsense. The reference validates before every hash it produces. Field sets are **exact**: an object with a missing or an extra field is invalid.

### 3.1 Shared primitives

- **proof id**: `^[0-7][0-9a-hjkmnp-tv-z]{25}$` (26 chars, lowercase Crockford base32 without `i l o u`, first char `0`-`7`).
- **canonical time**: `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$` AND parsing it as UTC then re-formatting as `YYYY-MM-DDTHH:MM:SSZ` must reproduce the same string (this rejects `2026-02-30T00:00:00Z`, `24:00:00`, etc.).
- **network**: `"devnet"` or `"mainnet-beta"`.
- **memo**: `"verifyum:v2:id=" || proof_id || ";alg=sha256;commitment=" || hex64` where `hex64` is the commitment digest string without its `sha256:` prefix. Always exactly 128 bytes.

### 3.2 Public proof metadata (`proof-v2`)

Exactly these top-level keys:

| key | constraint |
|---|---|
| `schema` | `"https://verifyum.com/schema/proof-v2.json"` |
| `protocol` | `"verifyum"` |
| `version` | integer `2` |
| `proof_id` | proof id |
| `commitment` | digest string (the reference trims and requires the trimmed value to equal the original; a port should require no surrounding whitespace) |
| `submitted_at` | canonical time |
| `anchor` | object, exactly the keys below |
| `service_signature` | object, exactly `algorithm`, `key_id`, `value` (see section 11) |

`anchor` keys: `provider` = `"solana"`; `network`; `transaction_signature` matches `^[1-9A-HJ-NP-Za-km-z]{80,90}$`; `slot` integer >= 0; `block_time` is `null` or canonical time; `anchor_address` matches `^[1-9A-HJ-NP-Za-km-z]{32,44}$`; `memo` equals the memo built from `proof_id` and `commitment`; `status` = `"finalized"`.

### 3.3 Witness checkpoint (`witness-checkpoint-v1`)

Exactly these keys (shown in canonical order):

`algorithm`, `checkpoint_hash`, `created_at`, `kind`, `merkle_root`, `network`, `period_end`, `period_start`, `previous_checkpoint_hash`, `protocol`, `schema`, `subject_count`, `subject_type`, `version`.

| key | constraint |
|---|---|
| `schema` | `"https://verifyum.com/schema/witness-checkpoint-v1.json"` |
| `protocol` | `"verifyum"` |
| `version` | integer `1` |
| `kind` | `"hourly"` or `"daily"` |
| `network` | network |
| `period_start`, `period_end`, `created_at` | canonical time |
| `algorithm` | `"verifyum-sha256-merkle-v1"` |
| `subject_type` | `"proof-v2"` when kind is hourly, `"hourly-checkpoint-v1"` when kind is daily |
| `subject_count` | integer >= 1 |
| `merkle_root` | digest string |
| `previous_checkpoint_hash` | `null` or digest string |
| `checkpoint_hash` | digest string, and must equal R3 recomputed over the document |

Period rules, with `duration` = 3600 (hourly) or 86400 (daily) and times as Unix seconds: `period_start mod duration == 0`; `period_end - period_start == duration`; `created_at >= period_end`.

### 3.4 Witness membership (`witness-membership-v1`)

Exactly: `schema` = `"https://verifyum.com/schema/witness-membership-v1.json"`, `protocol` = `"verifyum"`, `version` = `1`, `checkpoint_kind` (must equal the checkpoint's `kind`), `checkpoint_hash` (must equal the checkpoint's), `subject_type` (must equal the checkpoint's), `subject_id` (a proof id when subject_type is `proof-v2`, a digest string when it is `hourly-checkpoint-v1`), `leaf_hash` (digest string), `leaf_index` (integer, `0 <= leaf_index < leaf_count`), `leaf_count` (integer equal to the checkpoint's `subject_count`), `path` (array of steps, section 10). The membership is valid only if R9 reaches the checkpoint's `merkle_root`.

`leaf_index` is the position of the subject in the id-sorted leaf list (section 9); it is informational for verification, the path alone determines the root.

### 3.5 Public proof membership bundle (`witness-proof-membership-v1`)

The document served per proof (the `witnesses.json` vector). Exactly: `schema` = `"https://verifyum.com/schema/witness-proof-membership-v1.json"`, `protocol` = `"verifyum"`, `version` = `1`, `network`, `proof_id`, `checkpoint_url`, `checkpoint` (an hourly checkpoint, 3.3), `membership` (3.4). Consistency: `network == checkpoint.network`; `checkpoint.subject_type == "proof-v2"`; `membership.subject_type == "proof-v2"`; `proof_id == membership.subject_id`; `checkpoint_url == "https://verifyum.com/witness/checkpoints/" || kind || "/" || batch_id || ".json"` where `batch_id = period_start formatted as YYYYMMDDTHHMMSSZ || "-" || hex64 of checkpoint_hash`.

---

## 4. R3: checkpoint hash

```
checkpoint_hash(cp) = digest( "verifyum:witness:checkpoint:v1\n" || JCS(cp without the key "checkpoint_hash") )
```

- Remove **only** `checkpoint_hash`. Every other field, including `previous_checkpoint_hash` (which may be `null`) and `merkle_root`, stays.
- There is **no** leading `\x00` byte on this prefix. Compare with R5/R6/R7 which do have a domain-separation byte.
- The prefix is the 30 ASCII bytes `verifyum:witness:checkpoint:v1` followed by one `\n`.

---

## 5. R4: checkpoint document, document digest, external subjects

```
checkpoint_document(cp) = JCS(cp) || "\n"        (checkpoint_hash INCLUDED)
document_digest(cp)     = digest(checkpoint_document(cp))
```

- Exactly one trailing `0x0A` byte. The published checkpoint files at `https://verifyum.com/witness/checkpoints/<kind>/<batch_id>.json` are byte-for-byte this document (verified: `hourly.json` and `daily.json` in the vectors are identical to the recomputed document, 549 and 560 bytes, last byte 0x0A). A verifier therefore may either hash the file bytes as received, or re-encode; both must agree, and a mismatch means the file is not canonical and must be rejected.
- The document is only defined for a checkpoint that passes 3.3.

External witnesses use the document digest as the "subject" they witness:

- OpenTimestamps, GitHub, Wayback (hourly), eIDAS RFC 3161, Software Heritage and Sigsum (daily): subject = `document_digest(cp)`.
- Certificate Transparency (daily) is the exception: its subject is `cp.merkle_root`, encoded as the DNS label `"v1-" || base32lower_nopad(bytes(merkle_root)) || ".ct.verifyum.com"` (52-character RFC 4648 base32, lowercase alphabet `a-z2-7`, no padding).

**Sigsum leaf (daily checkpoints only).** The publisher submits `message = bytes(document_digest(daily_cp))` (32 raw bytes). Sigsum defines the leaf `checksum = sha256(message)`, so

```
sigsum_checksum_hex = hex( sha256( bytes(document_digest(daily_cp)) ) )
```

The Sigsum leaf hash (for locating the leaf in the log) is `sha256("\x00" || checksum || leaf_signature(64) || sha256(submit_public_key))` and the leaf signature is Ed25519 over `"sigsum.org/v1/tree-leaf\x00" || checksum`; those two are Sigsum's own rules and are stated here only so a port knows what the log holds.

---

## 6. R5: proof leaf hash

```
proof_leaf_hash(metadata) = digest( "\x00verifyum:witness:proof-leaf:v1\n" || JCS(metadata) )
```

- `metadata` is the **full** public proof metadata document (3.2) with `service_signature` **included**. Nothing is removed.
- The payload begins with the single byte 0x00, then the 30 ASCII bytes `verifyum:witness:proof-leaf:v1`, then 0x0A, then the canonical JSON.
- The reference validates the metadata (including the signature, section 11) before hashing; a verifier should do the same, but the hash itself is independent of validation.

---

## 7. R6: checkpoint leaf hash

```
checkpoint_leaf_hash(hourly_cp) = digest( "\x00verifyum:witness:checkpoint-leaf:v1\n" || bytes(hourly_cp.checkpoint_hash) )
```

- Payload: byte 0x00, the 35 ASCII bytes `verifyum:witness:checkpoint-leaf:v1`, 0x0A, then the **32 raw bytes** of the hourly checkpoint's `checkpoint_hash` (not the ASCII digest string, not the whole document).
- Only defined for `kind == "hourly"` checkpoints; these are the subjects of a daily tree.

---

## 8. R7: node hash

```
node_hash(left, right) = digest( "\x01verifyum:witness:node:v1\n" || bytes(left) || bytes(right) )
```

- Payload: byte 0x01, the 24 ASCII bytes `verifyum:witness:node:v1`, 0x0A, then 32 raw bytes of `left`, then 32 raw bytes of `right`. Total 1 + 24 + 1 + 64 = 90 bytes.
- `left` and `right` are digest strings; anything else is invalid.
- Leaves use prefix byte 0x00, interior nodes 0x01, so a leaf can never be presented as a node.

---

## 9. R8: Merkle tree construction

Input: a non-empty list of subjects `{id, leaf_hash}`.

1. Sort subjects by `id` ascending in byte order (`strcmp`). Ids must be non-empty strings and unique; duplicates and empty ids are rejected.
   - Hourly tree: `id` = the proof id, `leaf_hash` = R5 of that proof's metadata. All proofs in one checkpoint must share `anchor.network`, which becomes the checkpoint `network`.
   - Daily tree: `id` = the hourly checkpoint's `checkpoint_hash` **digest string** (so ids sort by the ASCII of `sha256:...`), `leaf_hash` = R6 of that hourly checkpoint. The builder also requires: every hourly checkpoint has the same network as the daily one, lies within `[daily.period_start, daily.period_end]`, no two share a `period_start`, and, taken in `period_start` order, each hourly's `previous_checkpoint_hash` equals the preceding hourly's `checkpoint_hash` (the first is unconstrained). The tree itself is still built in id order, not time order.
2. The sorted position of each subject is its `leaf_index` (0-based).
3. Level 0 is the list of leaf hashes in that order. While a level has more than one node, build the next level left to right: take nodes at positions `2k` (left) and `2k+1` (right). Parent = `node_hash(left, right)`. Every subject under `left` appends the path step `{side: "right", hash: right}`; every subject under `right` appends `{side: "left", hash: left}`. The step's `hash` is the **sibling**; `side` is the sibling's position.
4. If the level has an odd count, the last node is **promoted unchanged** to the next level: no duplication, no hashing with itself, no path step for the subjects beneath it at that level.
5. When one node remains it is the root. A single-subject tree has `root == leaf_hash` and an empty path.

Worked shape for five leaves `a b c d e` (already sorted):

```
level0: a b c d e
level1: h(a,b) h(c,d) e            (e promoted)
level2: h(h(a,b),h(c,d)) e         (e promoted)
root:   h( h(h(a,b),h(c,d)), e )
path[a] = [{right,b},{right,h(c,d)},{right,e}]
path[b] = [{left,a},{right,h(c,d)},{right,e}]
path[c] = [{right,d},{left,h(a,b)},{right,e}]
path[d] = [{left,c},{left,h(a,b)},{right,e}]
path[e] = [{left, h(h(a,b),h(c,d))}]
```

(`h` = R7. Confirmed by running the reference on five synthetic leaves; the root equalled the manual expression.) The live hourly vector is exactly this shape: 5 leaves, proof `1ns0c...` at `leaf_index` 2 (= `c` above) with path sides `right, left, right`.

When a path step is serialized inside a membership document it appears in canonical key order, `{"hash":"sha256:...","side":"right"}`.

---

## 10. R9: path verification

```
verify_path(leaf_hash, path, root):
    reject unless leaf_hash and root are digest strings
    current = leaf_hash
    for step in path (in order):
        reject unless step is an object with EXACTLY the two keys "side" and "hash"
        reject unless step.side is exactly "left" or "right"
        reject unless step.hash is a digest string
        if step.side == "left":  current = node_hash(step.hash, current)
        else:                    current = node_hash(current, step.hash)
    return current == root
```

- `side` names where the **sibling** sits: `"left"` means the sibling is the left input and the running value is the right input.
- A step with extra keys, a missing key, a non-string side, `"Left"`, or a non-digest hash is invalid (the reference returns false, it does not skip the step).
- An empty path is valid and means `root == leaf_hash`.
- There is no length limit in the reference; a port may cap the path length at 64 without affecting any real document.

---

## 11. R10: service signature

`metadata.service_signature` is exactly `{algorithm: "ed25519", key_id: string, value: string}`.

**Signed message** = `JCS(metadata with the key "service_signature" removed)`, as UTF-8 bytes, no prefix, no newline, no prehash. (For the live vector this message is 700 bytes with SHA-256 `53d70085810193e03b114a7ba81ae7d341f22de53e622d997bda9e1efff834b3`.)

**Signature bytes** = base64url-decode(`value`), which must be exactly 64 bytes.

**Public key**: from the service key registry document (`keys.json`), select the entry in `keys[]` for which ALL of the following hold:
- `key_id == service_signature.key_id`
- `network == metadata.anchor.network`
- `status` is `"active"` or `"retired"` (a revoked or unknown status never verifies)
- `algorithm == "ed25519"`
- `public_key` is a string

Exactly one entry may match: none means "key unavailable" (invalid), more than one means "key not unique" (invalid). `public_key` base64url-decodes to exactly 32 bytes.

**Verify** with Ed25519 per RFC 8032 (pure Ed25519, SHA-512 internally, no context, no prehash): `Ed25519.verify(pk32, message, sig64)`. Any decoding failure or length mismatch is a verification failure, not an error to be retried.

### 11.1 base64url, strict

The decoder used for both `value` and `public_key`:

1. The input must match `^[A-Za-z0-9_-]*$` (RFC 4648 URL alphabet). `+`, `/`, `=`, whitespace and anything else are rejected. Padding is never accepted.
2. `len(input) mod 4` must not be 1.
3. Decode after translating `-` to `+`, `_` to `/` and appending the implied `=` padding; any decoding error is rejected.
4. **Canonical check:** re-encode the decoded bytes (standard base64, translate `+/` to `-_`, strip `=`) and require byte equality with the input. This rejects encodings whose unused trailing bits are non-zero, e.g. `"AB"` (decodes to 0x00 but re-encodes as `"AA"`), `"Af"`, `"-_"`, `"-_9"`. Accepted examples: `"AA"` decodes to `00`, `"AQ"` to `01`, `"-_8"` to `fb ff`.
5. The empty string decodes to zero bytes (and is then rejected by the 32/64-byte length checks).

Go: `base64.RawURLEncoding.Strict().DecodeString` gives 1-4 (Strict enforces canonical trailing bits); still enforce the alphabet regex first because `Strict()` does not reject `\n`. Rust: `base64::engine::general_purpose::URL_SAFE_NO_PAD` with `DecodePaddingMode::RequireNone` and the default canonical-bits check. Python: `base64.urlsafe_b64decode` does NOT do step 4; re-encode and compare.

---

## 12. R11: Protocol v2 commitment, memo and proof id

Unchanged from the existing clients.

```
commitment = "sha256:" || hex( sha256( "verifyum:commitment:v2\n" || JCS(manifest) ) )
```

Fixed vector from `tools/check-protocol.php` (all 10 checks pass on the reviewed tree):

```
manifest = {
  "file": { "hash": { "algorithm": "sha256",
                      "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
            "size": "1234" },                      (size is a STRING)
  "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "protocol": "verifyum",
  "version": 2 }                                    (version is an INTEGER)

JCS(manifest) =
{"file":{"hash":{"algorithm":"sha256","value":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"size":"1234"},"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","protocol":"verifyum","version":2}

commitment = sha256:8412d6863b2328c6a7ff94d49ec087b18b6fc2db0b60da8b8dea97d30ac0612b
```

Memo for proof id `0123456789abcdefghjkmnpqrs` and that commitment:
`verifyum:v2:id=0123456789abcdefghjkmnpqrs;alg=sha256;commitment=8412d6863b2328c6a7ff94d49ec087b18b6fc2db0b60da8b8dea97d30ac0612b` (128 bytes).

Proof-id rejections pinned by the checker: first character `8` is invalid; the letter `o` is invalid.

---

## 13. Live test vectors (fetched 2026-09-02, all reproduced with the reference)

Vector files: `metadata.json`, `witnesses.json` (bundle with `checkpoint` + `membership`), `hourly.json`, `daily.json`, `keys.json`.

Proof `1ns0c79n4m0sy5es4wztcvrm1y`, mainnet-beta, key `verifyum-mainnet-2026-01`.

| quantity | expected |
|---|---|
| R5 `proof_leaf_hash(metadata.json)` | `sha256:4daa8b55d67b55edaa111c2b76e184cccc2fedc88a034b023ea91170ef6c871d` |
| R9 root reached from that leaf via `witnesses.membership.path` | `sha256:dbde1e168a15113d88b12c28192ed236d85b23ae5479812d930888e9c6664e54` |
| R9 intermediate after step 0 (`right`) | `sha256:09bb6980c97f13a5d28e52392351559acb23c54cee6973e398e4ed5a7d2859e4` |
| R9 intermediate after step 1 (`left`) | `sha256:7e13f4a12603f1cdc229fa9a564e943b8a51bfda0bc12686c449a12ad95805da` |
| R3 `checkpoint_hash(hourly.json)` | `sha256:bc3653e93164e62d0bc1272b2d76eace51df7951d692a3138991c144c631728c` |
| R4 `document_digest(hourly.json)` (549-byte document) | `sha256:b5e06851e4416d04f3911eddd593a5db1e0a1635d3f6f7f9304181c72d93e245` |
| R6 `checkpoint_leaf_hash(hourly.json)` | `sha256:e2f07dde10fb52ba49842ed9b41679583d22e58def885753ab3ac83eb56c3e8d` |
| R3 `checkpoint_hash(daily.json)` | `sha256:6237cfaafaf4ad6ed3f54a4f6de7f758b7368ac1ff8bedd3e9b1f3aef0cee93a` |
| R4 `document_digest(daily.json)` (560-byte document) | `sha256:5b223a804f25dcb863893182f1236360b837900db628766837427c8595caff90` |
| Sigsum checksum `hex(sha256(bytes(document_digest(daily))))` | `6c0271f184d4a8ec991edca7298e0328469749192f7067a4b9dfb3ee3847a658` (leaf index 63546 in seasalp.glasklar.is) |
| CT hostname for daily.json | `v1-g4mgckwi6xbzif2qrjo5pyhn65y6hxtluvqng677onzrpgcy5fgq.ct.verifyum.com` |
| hourly batch id | `20260831T180000Z-bc3653e93164e62d0bc1272b2d76eace51df7951d692a3138991c144c631728c` |
| daily batch id | `20260831T000000Z-6237cfaafaf4ad6ed3f54a4f6de7f758b7368ac1ff8bedd3e9b1f3aef0cee93a` |
| R10 signing message | 700 bytes, SHA-256 `53d70085810193e03b114a7ba81ae7d341f22de53e622d997bda9e1efff834b3` |
| R10 public key (`ZFGf-9Iesp57Z4rPSsdIsO6izjs3sM4hsWwabfg_X5o`) | 32 bytes, hex `64519ffbd21eb29e7b678acf4ac748b0eea2ce3b37b0ce21b16c1a6df83f5f9a` |
| R10 signature `value` | decodes to 64 bytes; **verifies** (confirmed with an independent Ed25519 implementation; a one-byte tamper fails) |
| R11 fixed vector | `sha256:8412d6863b2328c6a7ff94d49ec087b18b6fc2db0b60da8b8dea97d30ac0612b` |

Additional facts a port can assert: `hourly.json` and `daily.json` file bytes equal `checkpoint_document()` exactly (including the trailing newline); the hourly tree has 5 leaves and the proof sits at `leaf_index` 2 with path sides `right, left, right`; the daily tree has 2 leaves.

---

## 14. Corrections and clarifications to the draft

1. **R2, key order.** The draft said keys are sorted "by UTF-16 code units". The reference sorts by raw byte order (`ksort(..., SORT_STRING)`) and additionally rejects any key that is not non-empty printable ASCII (`^[\x20-\x7e]+$`), including numeric-looking keys such as `"1"`. Byte order and UTF-16 order coincide on that key set, so results are unchanged; a port should enforce the key restriction.
2. **R2, empty objects.** The reference encodes an empty object as `[]` (it cannot tell it apart from an empty array). No hashed document contains one; a port should reject rather than emit.
3. **R2, U+2028/U+2029.** The reference escapes these two characters as `\u2028`/`\u2029`, unlike RFC 8785, Node and Python. Unreachable given the field constraints; documented so a general-purpose JCS port does not silently diverge. Go's encoder happens to match PHP here.
4. **R2, Python claim.** Confirmed byte-exact on the live metadata document (Python bytes == PHP bytes, 700 bytes).
5. **R9.** Added: each step must be an object with exactly the two keys `side` and `hash` (extra keys invalidate the step); `leaf_hash` and `root` must themselves be digest strings; the empty path is valid and yields `root == leaf_hash`.
6. **R10, key selection.** The draft matched a registry key on `key_id` and `algorithm` only. The reference also requires `network == metadata.anchor.network`, `status` in `{active, retired}`, and that exactly one entry matches (zero or more than one is invalid).
7. **R10, base64url strictness.** "Strict" in the reference means: URL alphabet only, no padding, `len mod 4 != 1`, and a re-encode round-trip that rejects non-zero unused trailing bits (`"AB"`, `"-_"` are rejected). The draft mentioned only padding and alphabet.
8. **R10, signature record shape.** The record must have exactly the three keys `algorithm`, `key_id`, `value`; `key_id` in the record must equal the registry key's `key_id` (the reference passes it as `expected_key_id`).
9. **R4, external subjects.** Confirmed the Sigsum leaf checksum claim from the publisher source (message = 32 raw bytes of the daily document digest). Added the fact that all other non-CT channels witness the document digest and CT witnesses `merkle_root` as a base32 DNS label, and that the published checkpoint files are byte-identical to the canonical document.
10. **R8, subject ids.** Made explicit that daily-tree ids are the hourly `checkpoint_hash` digest strings (sorted as ASCII including the `sha256:` prefix), that ids must be unique and non-empty, that `leaf_index` is the sorted position, and the extra chain/period constraints the daily builder enforces.
11. **Validation (new section 3).** The draft had no field-level validation rules; a verifier port needs them to reject malformed input before hashing. All constraints were transcribed from `verifyum_witness_validate_proof_metadata`, `verifyum_witness_validate_checkpoint`, `verifyum_witness_validate_membership` and `verifyum_witness_validate_public_proof_membership`.

No rule in the draft produced a wrong byte: prefixes, the presence/absence of `\x00`/`\x01`, what is removed before hashing (only `checkpoint_hash` in R3, only `service_signature` in R10, nothing in R5), odd-node promotion, side semantics and the trailing newline in R4 were all confirmed exactly as drafted.
