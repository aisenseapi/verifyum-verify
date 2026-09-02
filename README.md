# verifyum-verify

The verification half of [Verifyum](https://verifyum.com), published so that
a proof can be checked without trusting the operator.

A Verifyum proof says that a commitment to the exact bytes of a file existed
no later than the block time of a finalized Solana Mainnet transaction. The
file never leaves the machine that made the proof. Only a domain-separated
commitment, built from the file hash and a random nonce, is anchored. This
repository holds the code that defines that commitment, the checkpoint
format the witnesses receive, and the checks a reader can run against the
public records. It does not hold the operational side: the signer, the
queue, the publisher adapters and the web tier stay private.

## What is here

| Path | What it is |
|---|---|
| `libs/func_verifyum.php` | Protocol v2: canonical manifest (RFC 8785), commitment, proof ID, service key registry |
| `libs/func_verifyum_witness.php` | Witness Layer v1: checkpoints, Merkle trees, membership proofs, channel receipts |
| `libs/func_verifyum_services.php` | The four helpers the witness library needs, copied verbatim from the private services library |
| `tools/check-protocol.php` | Deterministic checks of the protocol against fixed vectors |
| `clients/verifyum-protocol.js` | The browser implementation of the same protocol |
| `clients/verifyum.py` | A single-file library, standard library only, Python 3.10 or later |
| `clients/verifyum.mjs` | A single-file library for Node 20 or any runtime with Web Crypto and fetch |
| `schemas/` | JSON Schemas for proofs, manifests, checkpoints, memberships and receipts |

The two clients are libraries, not commands. Running them directly does
nothing. Import them.

## Run the checks

    php tools/check-protocol.php

Every line should read `ok`. The checks use fixed vectors and touch no
network.

## Use the clients

Python, from the `clients` directory or with it on `sys.path`:

    from verifyum import anchor_file, verify

    proof = anchor_file("contract.pdf")
    print(proof["proof_url"])
    # keep proof["draft"], it holds the nonce

    verify(proof["proof_id"], open("contract.pdf", "rb").read(), proof["draft"])

Node:

    import { anchorFile, verify } from "./clients/verifyum.mjs";

    const proof = await anchorFile("contract.pdf");
    await verify(proof.proof_id, await readFile("contract.pdf"), proof.draft);

`anchorFile` creates a real proof on Solana Mainnet. `verify` recomputes the
commitment from the bytes and the draft and compares it with the public
record. The draft holds the nonce. Without it nobody, including Verifyum, can
link the file to the proof.

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
   `https://verifyum.com/.well-known/verifyum-service-keys.json`.
   `verifyum_service_verify_metadata_signature` in the shim checks it. This
   is Verifyum vouching for Verifyum. It detects a modified copy, and it is
   not independent evidence.

4. **The witnesses.** `https://api.verifyum.com/v2/proofs/<proof-id>/witnesses`
   returns the Merkle path from the proof to its hourly checkpoint. The
   checkpoint itself is at
   `https://verifyum.com/witness/checkpoints/hourly/<batch-id>.json` and the
   receipts at `https://verifyum.com/witness/receipts/<hourly|daily>/<batch-id>.json`.
   The witness library recomputes the path. The receipts name what each
   channel confirmed, with artifact digests and provider references.

5. **The independent records.** Four can be checked with no help from
   Verifyum. OpenTimestamps anchors the hourly checkpoint in a Bitcoin block.
   The daily checkpoint is timestamped by a qualified timestamp authority on
   the EU Trusted List over RFC 3161. The same daily checkpoint is a leaf in
   the Sigsum log at `https://seasalp.glasklar.is`, cosigned by at least two
   of three pinned witnesses. Each daily checkpoint gets one certificate whose
   hostname encodes its root, visible in Certificate Transparency logs. The
   GitHub checkpoint log, its Software Heritage mirror and the Internet
   Archive capture are Verifyum's own records. They add durability, not
   independence, and the site says so.

The records are not equal. A missing or delayed witness never weakens the
anchor. The qualified timestamp carries a statutory presumption under eIDAS
Article 41(2) for the checkpoint root only. The step from the root to a file
is shown by the Merkle path like any other technical fact, so a proof is
never itself a qualified timestamp.

## What a proof does not show

It does not show authorship, ownership, signature validity, or whether any
claim in the file is true. It shows that the bytes existed, unchanged, no
later than the anchor.

## License

MIT. See `LICENSE`.
