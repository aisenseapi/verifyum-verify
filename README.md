# verifyum-verify

The verification half of [Verifyum](https://verifyum.com), published so that
a proof can be checked without trusting the operator, in the language you
already run.

A Verifyum proof says that a commitment to the exact bytes of a file existed
no later than the block time of a finalized Solana Mainnet transaction. The
file never leaves the machine that made the proof. Only a domain-separated
commitment, built from the file hash and a random nonce, is anchored. This
repository holds the rules that define that commitment, the checkpoint format
the witnesses receive, and implementations of the checks in four languages,
each verified against the same live records and against each other. It does
not hold the operational side: the signer, the queue, the publisher adapters
and the web tier stay private.

## The spec

`PROTOCOL.md` states every hashing rule byte for byte: the digest form, the
canonical JSON subset (RFC 8785 with the exact escaping and ordering the
reference uses), the checkpoint hash, the checkpoint document and its digest,
the proof leaf, the checkpoint leaf, the node hash, the tree, the path walk,
and the Ed25519 service signature. It was written from the PHP reference and
then checked against it line by line. A port in any language starts there.

## What is here

| Path | What it is |
|---|---|
| `PROTOCOL.md` | The byte-exact spec, with the expected values for the live vectors |
| `libs/func_verifyum.php` | Reference: protocol v2, canonical manifest, commitment, proof ID, key registry |
| `libs/func_verifyum_witness.php` | Reference: Witness Layer v1, checkpoints, Merkle trees, membership, receipts |
| `libs/func_verifyum_services.php` | The four helpers the witness library needs, copied verbatim from the private services library |
| `tools/check-protocol.php` | Deterministic checks of the protocol against fixed vectors |
| `clients/verifyum.py` | Python 3.10+, standard library only. A command and a library |
| `clients/verifyum.mjs` | Node 20+, no dependencies. A command and a library |
| `clients/python/`, `clients/node/` | The same two files, packaged for pip and npm |
| `action.yml` | A GitHub action that stamps files in a workflow |
| `clients/rust/` | Rust library and check binary, pinned crates |
| `clients/go/` | Go 1.22+, standard library only |
| `clients/verifyum-protocol.js` | The browser implementation of the commitment |
| `checks/check.sh` | A shell verifier: coreutils, xxd, jq and openssl, no language runtime |
| `checks/` | The check programs, the live vectors they must reproduce, and the PHP oracle |
| `schemas/` | JSON Schemas for proofs, manifests, checkpoints, memberships and receipts |

Every implementation here has been executed and compared with the reference.
Nothing is shipped from a desk check alone.

## Run the checks

Every program prints the same eleven lines, one value per line, and exits 0
only if every value matches the live records. Paths are resolved from the
files themselves, so the working directory does not matter.

    php tools/check-protocol.php
    php checks/oracle.php
    python checks/check.py
    node checks/check.mjs
    bash checks/check.sh
    cargo run --manifest-path clients/rust/Cargo.toml --release --bin check
    go run -C clients/go ./cmd/check

`checks/oracle.php` is the PHP reference computing the same values; the five
ports must be byte-identical to it. On publication all six agreed byte for
byte, and each rejected six separate corruptions of the vectors: an altered
path hash, a flipped path side, an altered hourly checkpoint hash, an altered
daily Merkle root, a tampered signature and altered proof metadata. `checks/vectors/EXPECTED.md` lists the
values. The vectors are a real public proof and the checkpoints it belongs
to, fetched from the live service, so a change in any rule shows up as a
mismatch against a record that also lives in Bitcoin, a qualified timestamp,
a Sigsum log and Certificate Transparency.

The Python check needs the `cryptography` package for the signature line;
without it that line reads `unchecked` and the rest still runs. The PHP
oracle needs the sodium extension. The shell verifier needs jq 1.6 or newer
and an OpenSSL with Ed25519 support, which means OpenSSL 1.1.1 or newer; on
macOS replace `sha256sum` with `shasum -a 256`.

## Install

    pip install verifyum
    npx verifyum --help

Both give the same command:

    verifyum stamp contract.pdf
    verifyum verify contract.pdf
    verifyum verify --offline --independent contract.pdf
    verifyum upgrade contract.pdf
    verifyum witness contract.pdf

`stamp` writes `contract.pdf.verifyum.json` beside the file, the way an
`.ots` file sits beside its subject, so `verify` needs nothing but the
original path. That receipt holds the nonce. It is the only thing tying your
file to its public proof, Verifyum never has it, and losing it loses the
link for good.

`verify --offline` checks using the receipt alone and contacts no one. The
receipt carries the signed metadata, the witness bundle with its Merkle path
and the service key registry, about three kilobytes, so the file, the receipt
and a SHA-256 implementation settle the question with this service gone. A
receipt written in the minutes before its hourly checkpoint is published is
thin; `verifyum upgrade` completes it, the way `ots upgrade` does, and says
so rather than checking less.

`verify --independent` additionally reads the anchor from a public Solana RPC
and compares the memo itself, so the ledger answers rather than the operator.
Set `VERIFYUM_SOLANA_RPC` to choose the endpoint.

Exit codes are meant for a pipeline: 0 all good, 1 a check failed, 2 usage
or file error, 3 the service was unavailable and it is worth retrying.
`--json` prints one machine-readable object per file.

To stamp what a release publishes, the action in this repository does it in
one step:

    - uses: aisenseapi/verifyum-verify@main
      with:
        files: SHA256SUMS

## Use them as libraries

The same two files are libraries as well as commands. Importing one starts
nothing.

Python, from the `clients` directory or with it on `sys.path`:

    from verifyum import anchor_file, verify, verify_witness

    proof = anchor_file("contract.pdf")
    print(proof["proof_url"])
    # keep proof["draft"], it holds the nonce

    verify(proof["proof_id"], open("contract.pdf", "rb").read(), proof["draft"])
    verify_witness(proof["proof_id"])

Node:

    import { anchorFile, verify, verifyWitness } from "./clients/verifyum.mjs";

    const proof = await anchorFile("contract.pdf");
    await verify(proof.proof_id, await readFile("contract.pdf"), proof.draft);
    await verifyWitness(proof.proof_id);

`anchorFile` creates a real proof on Solana Mainnet. `verify` recomputes the
commitment from the bytes and the draft and compares it with the public
record. The draft holds the nonce. Without it nobody, including Verifyum, can
link the file to the proof. `verifyWitness` fetches the membership record,
recomputes the leaf from the public metadata, walks the path to the hourly
checkpoint root and checks the service signature.

Both clients read `VERIFYUM_API_BASE` and `VERIFYUM_PROOF_DOMAIN` from the
environment, so they can be pointed at another deployment for testing.

## Verify a proof without Verifyum

A proof is public at `https://proof.verifyum.com/<proof-id>` and as JSON at
`https://api.verifyum.com/v2/proofs/<proof-id>`. Proof IDs are unguessable and
there is no listing, so you need the ID from whoever made the proof.

1. **The anchor.** The proof names a Solana Mainnet transaction. Read it from
   any RPC endpoint and confirm the Memo carries the commitment in the proof.
   The block time of that transaction is the timestamp.

2. **The file.** Recompute the commitment from the file bytes and the draft
   with `verify` in either client. If it matches, the file is the one that
   was anchored. The nonce is held by whoever made the proof, not by
   Verifyum.

3. **The service signature.** The proof carries an Ed25519 signature by
   Verifyum over its public metadata. The key registry is at
   `https://verifyum.com/.well-known/verifyum-service-keys.json`. This is
   Verifyum vouching for Verifyum. It detects a modified copy, and it is not
   independent evidence.

4. **The witnesses.** `https://api.verifyum.com/v2/proofs/<proof-id>/witnesses`
   returns the Merkle path from the proof to its hourly checkpoint. The
   checkpoint itself is at
   `https://verifyum.com/witness/checkpoints/hourly/<batch-id>.json` and the
   receipts at `https://verifyum.com/witness/receipts/<hourly|daily>/<batch-id>.json`.
   `verify_witness` recomputes the path. The receipts name what each channel
   confirmed, with artifact digests and provider references.

5. **The independent records.** Four can be checked with no help from
   Verifyum. OpenTimestamps anchors the hourly checkpoint in a Bitcoin block.
   The daily checkpoint is timestamped by a qualified timestamp authority on
   the EU Trusted List over RFC 3161. The same daily checkpoint is a leaf in
   the Sigsum log at `https://seasalp.glasklar.is`, cosigned by at least two
   of three pinned witnesses; `sigsum_checksum` in the clients computes the
   leaf checksum to look for. Each daily checkpoint gets one certificate
   whose hostname encodes its root, visible in Certificate Transparency logs.
   The GitHub checkpoint log, its Software Heritage mirror and the Internet
   Archive capture are Verifyum's own records. They add durability, not
   independence, and the site says so.

The records are not equal. A missing or delayed witness never weakens the
anchor. The qualified timestamp carries a statutory presumption under eIDAS
Article 41(2) for the checkpoint root only. The step from the root to a file
is shown by the Merkle path like any other technical fact, so a proof is
never itself a qualified timestamp.

## Known limitations of the ports

The ports implement the hash rules and the signature check. They do not
implement the reference's field-level validation of documents (exact key
sets, canonical time round-trips, period arithmetic); a document that hashes
correctly but is malformed in another way is caught by the reference, not by
a port. The Go parser rejects duplicate object keys at any depth, as the reference
does. The Rust parser still keeps the last of them, which is serde_json's
default; a reviewer rightly pointed out that "no published document has
duplicate keys" is an argument about today's data and not about an
adversary, and that two verifiers disagreeing on hostile input is the failure
class that matters here. The Rust fix is pending a toolchain to test it on.
The Python signature check depends on the optional `cryptography` package.
The shell verifier canonicalizes with `jq -cS`, which matches the reference
on the documents published here but is not a general RFC 8785 encoder: it
would differ on very large integers and on lone surrogates.

## What a proof does not show

It does not show authorship, ownership, signature validity, or whether any
claim in the file is true. It shows that the bytes existed, unchanged, no
later than the anchor.

## License

MIT. See `LICENSE`.
