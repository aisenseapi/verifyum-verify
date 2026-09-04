"""Verifyum client, single file, standard library only.

Creates a privacy-preserving proof that exact bytes existed at a point in
time. The data never leaves the machine: only a domain-separated commitment
is sent. No account, wallet or API key is required.

    from verifyum import anchor_bytes, anchor_file, anchor_record, verify

    proof = anchor_file("contract.pdf")
    print(proof["proof_url"])

Keep the returned draft. It holds the nonce, and without it nobody can link
the original data to the public proof.

The module also carries the Witness Layer primitives (canonical JSON,
checkpoint hashes, Merkle path verification, service signature check) so a
proof can be verified against the published witness checkpoints offline.

Reference: https://verifyum.com/agents
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request

__all__ = [
    "commitment_for",
    "anchor_bytes",
    "anchor_file",
    "anchor_record",
    "verify",
    "VerifyumError",
    "digest",
    "digest_bytes",
    "is_digest",
    "jcs",
    "checkpoint_hash",
    "checkpoint_document",
    "checkpoint_document_digest",
    "sigsum_checksum",
    "proof_leaf_hash",
    "checkpoint_leaf_hash",
    "node_hash",
    "build_tree",
    "verify_path",
    "base64url_decode",
    "verify_service_signature",
    "verify_witness",
    "verify_witness_documents",
]

API_BASE = os.environ.get("VERIFYUM_API_BASE", "https://api.verifyum.com")
PROOF_DOMAIN = os.environ.get("VERIFYUM_PROOF_DOMAIN", "verifyum.com")
USER_AGENT = "verifyum-python/1.1.0"

# Ed25519 is optional: without it the signature is reported as unchecked
# rather than failing, so the hash checks still work on a bare interpreter.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
except Exception:  # pragma: no cover
    _Ed25519PublicKey = None
    _InvalidSignature = None

# Always used with fullmatch(): with match() a trailing "$" still matches
# before a final newline, so "sha256:<hex>\n" would pass as a digest string.
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
PROOF_ID_RE = re.compile(r"[0-7][0-9a-hjkmnp-tv-z]{25}")
KEY_RE = re.compile(r"[\x20-\x7e]+")
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
BATCH_TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

CHECKPOINT_PREFIX = b"verifyum:witness:checkpoint:v1\n"
PROOF_LEAF_PREFIX = b"\x00verifyum:witness:proof-leaf:v1\n"
CHECKPOINT_LEAF_PREFIX = b"\x00verifyum:witness:checkpoint-leaf:v1\n"
NODE_PREFIX = b"\x01verifyum:witness:node:v1\n"


class VerifyumError(RuntimeError):
    """A Verifyum request failed. `retry_after` is set when it is worth retrying."""

    def __init__(self, message: str, *, status: int | None = None, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


# --- R1, R2: digest and canonical JSON -------------------------------------


def digest(payload: bytes) -> str:
    """R1: digest string over raw bytes."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("digest expects bytes")
    return "sha256:" + hashlib.sha256(bytes(payload)).hexdigest()


def is_digest(value) -> bool:
    """True only for "sha256:" plus exactly 64 lowercase hex characters."""
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def digest_bytes(value: str) -> bytes:
    """The 32 raw bytes behind a digest string. Rejects anything else."""
    if not is_digest(value):
        raise ValueError("not a digest string")
    return bytes.fromhex(value[7:])


def _check_jcs_value(value, path: str = "$") -> None:
    # Floats never appear in a Verifyum document; a float here means the
    # caller parsed something that was not canonical, so refuse to hash it.
    if value is None or isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise ValueError(f"float at {path} is not allowed in canonical JSON")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_jcs_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        if not value:
            # The reference cannot tell {} from [] and no document has one.
            raise ValueError(f"empty object at {path} is not allowed in canonical JSON")
        for key, item in value.items():
            if not isinstance(key, str) or not KEY_RE.fullmatch(key):
                raise ValueError(f"object key {key!r} at {path} is not printable ASCII")
            _check_jcs_value(item, f"{path}.{key}")
        return
    raise ValueError(f"unsupported value type {type(value).__name__} at {path}")


def jcs(value) -> bytes:
    """R2: canonical JSON bytes, matching the PHP reference byte for byte."""
    _check_jcs_value(value)
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    # The reference escapes the two Unicode line terminators; keys are ASCII
    # only, so a plain replace can only touch string contents.
    text = text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return text.encode("utf-8")


# --- R3 to R7: checkpoint and tree hashes -----------------------------------


def checkpoint_hash(checkpoint: dict) -> str:
    """R3: hash over the checkpoint with only `checkpoint_hash` removed."""
    body = {key: value for key, value in checkpoint.items() if key != "checkpoint_hash"}
    return digest(CHECKPOINT_PREFIX + jcs(body))


def checkpoint_document(checkpoint: dict) -> bytes:
    """R4: the published checkpoint file, canonical JSON plus one newline."""
    return jcs(checkpoint) + b"\n"


def checkpoint_document_digest(checkpoint: dict) -> str:
    """R4: what OpenTimestamps, Sigsum, eIDAS and the others witness."""
    return digest(checkpoint_document(checkpoint))


def sigsum_checksum(daily_checkpoint: dict) -> str:
    """Sigsum leaf checksum: sha256 over the 32 raw bytes of the document digest."""
    return hashlib.sha256(digest_bytes(checkpoint_document_digest(daily_checkpoint))).hexdigest()


def proof_leaf_hash(metadata: dict) -> str:
    """R5: hourly tree leaf over the full metadata, signature included."""
    return digest(PROOF_LEAF_PREFIX + jcs(metadata))


def checkpoint_leaf_hash(hourly_checkpoint: dict) -> str:
    """R6: daily tree leaf over the raw bytes of an hourly checkpoint hash."""
    if hourly_checkpoint.get("kind") != "hourly":
        raise ValueError("checkpoint leaves are only defined for hourly checkpoints")
    return digest(CHECKPOINT_LEAF_PREFIX + digest_bytes(hourly_checkpoint["checkpoint_hash"]))


def node_hash(left: str, right: str) -> str:
    """R7: interior node over two digest strings."""
    return digest(NODE_PREFIX + digest_bytes(left) + digest_bytes(right))


def build_tree(subjects) -> dict:
    """R8: Merkle tree over `[{id, leaf_hash}, ...]`, sorted by id.

    Returns `{"root", "leaves": [{"id", "leaf_hash", "leaf_index", "path"}]}`
    in sorted order. An odd trailing node is promoted unchanged to the next
    level (no duplication, no self-hash, no path step for the subjects
    beneath it at that level).
    """
    if not isinstance(subjects, (list, tuple)) or not subjects:
        raise ValueError("tree needs at least one subject")
    entries = []
    for subject in subjects:
        if not isinstance(subject, dict):
            raise ValueError("subject must be an object")
        subject_id = subject.get("id")
        leaf_hash = subject.get("leaf_hash")
        if not isinstance(subject_id, str) or subject_id == "":
            raise ValueError("subject id must be a non-empty string")
        if not is_digest(leaf_hash):
            raise ValueError(f"subject {subject_id!r} has no digest leaf_hash")
        entries.append((subject_id.encode("utf-8"), subject_id, leaf_hash))
    entries.sort(key=lambda entry: entry[0])
    for previous, current in zip(entries, entries[1:]):
        if previous[0] == current[0]:
            raise ValueError(f"duplicate subject id {current[1]!r}")
    leaves = [
        {"id": subject_id, "leaf_hash": leaf_hash, "leaf_index": index, "path": []}
        for index, (_, subject_id, leaf_hash) in enumerate(entries)
    ]
    # Each level node carries the list of leaf indexes beneath it.
    level = [(leaf["leaf_hash"], [index]) for index, leaf in enumerate(leaves)]
    while len(level) > 1:
        next_level = []
        for position in range(0, len(level) - 1, 2):
            left_hash, left_members = level[position]
            right_hash, right_members = level[position + 1]
            for index in left_members:
                leaves[index]["path"].append({"side": "right", "hash": right_hash})
            for index in right_members:
                leaves[index]["path"].append({"side": "left", "hash": left_hash})
            next_level.append((node_hash(left_hash, right_hash), left_members + right_members))
        if len(level) % 2 == 1:
            next_level.append(level[-1])
        level = next_level
    return {"root": level[0][0], "leaves": leaves}


def verify_path(leaf_hash: str, path, root: str) -> bool:
    """R9: walk the sibling path from the leaf and compare with the root."""
    if not is_digest(leaf_hash) or not is_digest(root):
        return False
    if not isinstance(path, list) or len(path) > 64:
        return False
    current = leaf_hash
    for step in path:
        if not isinstance(step, dict) or set(step.keys()) != {"side", "hash"}:
            return False
        side = step["side"]
        sibling = step["hash"]
        if side not in ("left", "right"):
            return False
        if not is_digest(sibling):
            return False
        current = node_hash(sibling, current) if side == "left" else node_hash(current, sibling)
    return current == root


# --- R10: service signature --------------------------------------------------


def base64url_decode(value: str) -> bytes:
    """Strict base64url: URL alphabet, no padding, canonical trailing bits."""
    if not isinstance(value, str) or not BASE64URL_RE.fullmatch(value):
        raise ValueError("base64url: invalid alphabet")
    if len(value) % 4 == 1:
        raise ValueError("base64url: invalid length")
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("base64url: decoding failed") from error
    # Python does not reject non-zero unused trailing bits; the round trip does.
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("base64url: non-canonical encoding")
    return raw


def _select_service_key(registry: dict, key_id: str, network: str) -> bytes:
    matches = []
    for entry in registry.get("keys") or []:
        if not isinstance(entry, dict):
            continue
        if (
            entry.get("key_id") == key_id
            and entry.get("network") == network
            and entry.get("status") in ("active", "retired")
            and entry.get("algorithm") == "ed25519"
            and isinstance(entry.get("public_key"), str)
        ):
            matches.append(entry)
    if len(matches) != 1:
        raise ValueError("service key unavailable" if not matches else "service key not unique")
    public_key = base64url_decode(matches[0]["public_key"])
    if len(public_key) != 32:
        raise ValueError("service key has wrong length")
    return public_key


def verify_service_signature(metadata: dict, registry: dict) -> bool | None:
    """R10: Ed25519 over JCS(metadata minus service_signature).

    Returns True or False when the check ran, None when no Ed25519
    implementation is available so the caller can report "unchecked".
    """
    if _Ed25519PublicKey is None:
        return None
    if not isinstance(metadata, dict) or not isinstance(registry, dict):
        return False
    signature = metadata.get("service_signature")
    if not isinstance(signature, dict) or set(signature.keys()) != {"algorithm", "key_id", "value"}:
        return False
    if signature["algorithm"] != "ed25519" or not isinstance(signature["key_id"], str):
        return False
    if not isinstance(signature["value"], str):
        return False
    anchor = metadata.get("anchor")
    if not isinstance(anchor, dict) or not isinstance(anchor.get("network"), str):
        return False
    try:
        public_key = _select_service_key(registry, signature["key_id"], anchor["network"])
        raw_signature = base64url_decode(signature["value"])
        if len(raw_signature) != 64:
            return False
        message = jcs({key: value for key, value in metadata.items() if key != "service_signature"})
        _Ed25519PublicKey.from_public_bytes(public_key).verify(raw_signature, message)
        return True
    except _InvalidSignature:
        return False
    except (ValueError, TypeError):
        return False


# --- HTTP helpers ------------------------------------------------------------


def _request(method: str, path: str, payload: dict | None = None) -> dict:
    url = path if path.startswith("https://") else API_BASE + path
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return {"status": response.status, "body": json.loads(response.read() or b"{}")}
    except urllib.error.HTTPError as error:
        retry_after = error.headers.get("Retry-After") if error.headers else None
        detail = {}
        try:
            detail = json.loads(error.read() or b"{}")
        except Exception:
            pass
        raise VerifyumError(
            detail.get("message") or detail.get("error") or f"HTTP {error.code}",
            status=error.code,
            retry_after=int(retry_after) if retry_after and retry_after.isdigit() else None,
        ) from None


# --- Protocol v2 client ------------------------------------------------------


def commitment_for(data: bytes) -> tuple[str, dict]:
    """Returns (commitment, private_draft). The draft must be kept locally."""
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    manifest = {
        "file": {
            "hash": {"algorithm": "sha256", "value": hashlib.sha256(data).hexdigest()},
            "size": str(len(data)),
        },
        "nonce": nonce,
        "protocol": "verifyum",
        "version": 2,
    }
    commitment = "sha256:" + hashlib.sha256(b"verifyum:commitment:v2\n" + jcs(manifest)).hexdigest()
    draft = {
        "format": "verifyum-private-draft",
        "version": 2,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "manifest": manifest,
        "commitment": commitment,
    }
    return commitment, draft


def anchor_bytes(data: bytes, *, idempotency_key: str | None = None, wait: bool = True, timeout: int = 180) -> dict:
    """Anchors a commitment over `data`. Returns the proof with its private draft."""
    commitment, draft = commitment_for(data)
    key = idempotency_key or "py-" + hashlib.sha256(commitment.encode()).hexdigest()[:32]

    health = _request("GET", "/health")["body"]
    if health.get("anchoring") != "enabled" or health.get("access") != "public":
        raise VerifyumError("Verifyum is not accepting public anchors right now", retry_after=300)

    result = _request("POST", "/v2/anchor", {"commitment": commitment, "idempotency_key": key})["body"]
    proof_id = result.get("proof_id")
    if wait and proof_id:
        deadline = time.time() + timeout
        while result.get("status") not in ("finalized", "failed") and time.time() < deadline:
            time.sleep(3)
            result = _request("GET", f"/v2/proofs/{proof_id}")["body"]

    draft["anchor_result"] = {k: result.get(k) for k in ("proof_id", "status", "network", "proof_url", "status_url")}
    return {**result, "commitment": commitment, "private_draft": draft}


def anchor_file(path: str, **kwargs) -> dict:
    """Anchors the exact bytes of a local file."""
    with open(path, "rb") as handle:
        return anchor_bytes(handle.read(), **kwargs)


def anchor_record(record: dict, **kwargs) -> dict:
    """Anchors a decision record or any JSON document, canonicalized first.

    See https://verifyum.com/schema/agent-decision-record-v1.json for the
    recommended shape. Store the returned private_draft with the record.
    """
    return anchor_bytes(jcs(record), **kwargs)


def verify(proof_id: str, data: bytes, draft: dict) -> dict:
    """Checks that `data` matches the draft and that the proof is finalized.

    This confirms the local binding and Verifyum's published metadata. For a
    fully independent result, also fetch the Solana transaction named in the
    metadata from any RPC endpoint and compare its memo.
    """
    manifest = draft["manifest"]
    checks = {
        "hash_matches": hashlib.sha256(data).hexdigest() == manifest["file"]["hash"]["value"],
        "size_matches": str(len(data)) == manifest["file"]["size"],
        "commitment_matches": "sha256:"
        + hashlib.sha256(b"verifyum:commitment:v2\n" + jcs(manifest)).hexdigest()
        == draft["commitment"],
    }
    metadata = _request("GET", f"https://{proof_id}.{PROOF_DOMAIN}/.well-known/verifyum.json")["body"]
    checks["public_commitment_matches"] = metadata.get("commitment") == draft["commitment"]
    checks["anchor_finalized"] = metadata.get("anchor", {}).get("status") == "finalized"
    return {
        "valid": all(checks.values()),
        "checks": checks,
        "transaction_signature": metadata.get("anchor", {}).get("transaction_signature"),
        "network": metadata.get("anchor", {}).get("network"),
        "boundary": "Shows that these exact bytes existed no later than the block time. "
        "Not authorship, ownership, or that the contents are true.",
    }


# --- Witness Layer verification ----------------------------------------------


def verify_witness(proof_id: str) -> dict:
    """Fetches the metadata, the witness bundle and the key registry, then
    recomputes the leaf, the Merkle path, the checkpoint hash and the
    service signature. Network access is limited to verifyum.com.
    """
    if not isinstance(proof_id, str) or not PROOF_ID_RE.fullmatch(proof_id):
        raise VerifyumError("invalid proof id")
    metadata = _request("GET", f"https://{proof_id}.{PROOF_DOMAIN}/.well-known/verifyum.json")["body"]
    bundle = _request("GET", f"/v2/proofs/{proof_id}/witnesses")["body"]
    registry = _request("GET", f"https://{PROOF_DOMAIN}/.well-known/verifyum-service-keys.json")["body"]
    result = verify_witness_documents(metadata, bundle, registry)
    if bundle.get("proof_id") != proof_id or result["checks"].get("subject_id") != proof_id:
        result["checks"]["subject_matches"] = False
        result["valid"] = False
    result["checks"].pop("subject_id", None)
    return result


def _batch_id(checkpoint: dict) -> str | None:
    period_start = checkpoint.get("period_start")
    if not isinstance(period_start, str) or not BATCH_TIME_RE.fullmatch(period_start):
        return None
    if not is_digest(checkpoint.get("checkpoint_hash")):
        return None
    return period_start.replace("-", "").replace(":", "") + "-" + checkpoint["checkpoint_hash"][7:]


def verify_witness_documents(metadata, bundle, registry) -> dict:
    """Offline core of `verify_witness`: same checks over already-fetched
    documents. `bundle` is the witness-proof-membership-v1 document.
    """
    if not isinstance(metadata, dict):
        metadata = {}
    if not isinstance(bundle, dict):
        bundle = {}
    checkpoint = bundle.get("checkpoint")
    membership = bundle.get("membership")
    if not isinstance(checkpoint, dict):
        checkpoint = {}
    if not isinstance(membership, dict):
        membership = {}
    checks: dict[str, bool | None] = {}
    proof_id = metadata.get("proof_id")

    try:
        leaf = proof_leaf_hash(metadata)
    except (ValueError, TypeError) as error:
        print(f"verify_witness: metadata not canonical: {error}", file=sys.stderr)
        leaf = None
    checks["leaf_hash_matches"] = leaf is not None and membership.get("leaf_hash") == leaf
    checks["subject_matches"] = (
        isinstance(proof_id, str)
        and PROOF_ID_RE.fullmatch(proof_id) is not None
        and membership.get("subject_id") == proof_id
        and bundle.get("proof_id") == proof_id
        and membership.get("subject_type") == "proof-v2"
        and checkpoint.get("subject_type") == "proof-v2"
        and checkpoint.get("kind") == "hourly"
    )
    checks["path_reaches_root"] = leaf is not None and verify_path(
        leaf, membership.get("path"), checkpoint.get("merkle_root")
    )
    try:
        recomputed = checkpoint_hash(checkpoint)
    except (ValueError, TypeError) as error:
        print(f"verify_witness: checkpoint not canonical: {error}", file=sys.stderr)
        recomputed = None
    checks["checkpoint_hash_matches"] = (
        recomputed is not None
        and checkpoint.get("checkpoint_hash") == recomputed
        and membership.get("checkpoint_hash") == recomputed
    )
    subject_count = checkpoint.get("subject_count")
    leaf_index = membership.get("leaf_index")
    checks["membership_consistent"] = (
        membership.get("checkpoint_kind") == checkpoint.get("kind")
        and isinstance(subject_count, int)
        and not isinstance(subject_count, bool)
        and membership.get("leaf_count") == subject_count
        and isinstance(leaf_index, int)
        and not isinstance(leaf_index, bool)
        and 0 <= leaf_index < subject_count
    )
    batch_id = _batch_id(checkpoint)
    checks["bundle_consistent"] = (
        bundle.get("network") == checkpoint.get("network")
        and (metadata.get("anchor") or {}).get("network") == checkpoint.get("network")
        and batch_id is not None
        and bundle.get("checkpoint_url")
        == f"https://verifyum.com/witness/checkpoints/{checkpoint.get('kind')}/{batch_id}.json"
    )
    checks["service_signature_valid"] = verify_service_signature(metadata, registry)

    decided = [value for value in checks.values() if value is not None]
    return {
        "valid": all(decided),
        "checks": {**checks, "subject_id": proof_id},
        "leaf_hash": leaf,
        "checkpoint_hash": recomputed,
        "checkpoint_url": bundle.get("checkpoint_url"),
        "network": checkpoint.get("network"),
        "period_end": checkpoint.get("period_end"),
        "boundary": "Shows that the proof metadata was included in a checkpoint no later than "
        "period_end and that the checkpoint is the one the external witnesses hold. "
        "Not authorship, ownership, or that the contents are true.",
    }


# --------------------------------------------------------------------------
# Command line
#
# The receipt sits beside the file as <file>.verifyum.json, the way an .ots
# file does, so `verify` needs nothing but the original path. It holds the
# nonce, which is the only thing that ties the file to its public proof, and
# which Verifyum never has. Losing it loses the link for good.
#
# The mode is set to 0600, which POSIX honours and Windows does not: there a
# receipt lands 0666 and inherits the directory's ACL. The tool therefore
# does not promise the file is private. It says what the file is and leaves
# the placing of it to someone who knows where their own secrets belong.
# --------------------------------------------------------------------------

RECEIPT_SUFFIX = ".verifyum.json"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3


def receipt_path(path: str) -> str:
    """Where the receipt for a file lives."""
    return path + RECEIPT_SUFFIX


def write_receipt(path: str, proof: dict) -> str:
    """Stores the proof and its draft beside the file.

    The mode request is honoured on POSIX and ignored on Windows, so this
    does not make the file private on its own.
    """
    target = receipt_path(path)
    document = {
        "schema": "https://verifyum.com/schema/receipt-v1.json",
        "protocol": "verifyum",
        "version": 2,
        "proof_id": proof.get("proof_id"),
        "commitment": proof.get("commitment"),
        "status": proof.get("status"),
        "proof_url": proof.get("proof_url"),
        "private_draft": proof.get("private_draft"),
    }
    body = json.dumps(document, indent=2, sort_keys=True) + "\n"
    temporary = target + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(body)
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, target)
    return target


def read_receipt(path: str) -> dict:
    with open(receipt_path(path), "r", encoding="utf-8") as handle:
        return json.load(handle)


def _emit(payload: dict, as_json: bool, lines: list) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True))
        return
    for line in lines:
        print(line)


def _cmd_stamp(args) -> int:
    worst = EXIT_OK
    for path in args.files:
        if not os.path.isfile(path):
            print("not a file: " + path, file=sys.stderr)
            worst = max(worst, EXIT_USAGE)
            continue
        if os.path.exists(receipt_path(path)) and not args.force:
            print("receipt already exists, use --force to replace: " + receipt_path(path), file=sys.stderr)
            worst = max(worst, EXIT_USAGE)
            continue
        try:
            proof = anchor_file(path, wait=not args.no_wait, timeout=args.timeout)
        except VerifyumError as error:
            print("verifyum: " + str(error), file=sys.stderr)
            worst = max(worst, EXIT_UNAVAILABLE)
            continue
        except OSError as error:
            print("verifyum: " + str(error), file=sys.stderr)
            worst = max(worst, EXIT_USAGE)
            continue
        target = write_receipt(path, proof)
        _emit(
            {"file": path, "receipt": target, "proof_id": proof.get("proof_id"), "status": proof.get("status"), "proof_url": proof.get("proof_url")},
            args.json,
            [
                "stamped  " + path,
                "  proof   " + str(proof.get("proof_id")),
                "  status  " + str(proof.get("status")),
                "  url     " + str(proof.get("proof_url")),
                "  receipt " + target,
                "          this holds the nonce. We do not have it and cannot",
                "          replace it. Keep it, and do not commit or sync it",
                "          anywhere you would not put a key.",
            ],
        )
    return worst


def _cmd_verify(args) -> int:
    worst = EXIT_OK
    for path in args.files:
        try:
            receipt = read_receipt(path)
            with open(path, "rb") as handle:
                data = handle.read()
        except (OSError, ValueError) as error:
            print("verifyum: " + str(error), file=sys.stderr)
            worst = max(worst, EXIT_USAGE)
            continue
        try:
            result = verify(receipt["proof_id"], data, receipt["private_draft"])
        except VerifyumError as error:
            print("verifyum: " + str(error), file=sys.stderr)
            worst = max(worst, EXIT_UNAVAILABLE)
            continue
        except (KeyError, TypeError) as error:
            print("verifyum: receipt is not usable: " + str(error), file=sys.stderr)
            worst = max(worst, EXIT_USAGE)
            continue
        if not result["valid"]:
            worst = max(worst, EXIT_FAILED)
        failed = [name for name, passed in result["checks"].items() if not passed]
        _emit(
            {"file": path, "valid": result["valid"], "checks": result["checks"], "transaction_signature": result.get("transaction_signature")},
            args.json,
            [
                ("verified " if result["valid"] else "FAILED   ") + path,
                "  proof   " + str(receipt.get("proof_id")),
                "  chain   " + str(result.get("transaction_signature")),
            ] + (["  failed  " + ", ".join(failed)] if failed else []),
        )
    return worst


def _cmd_witness(args) -> int:
    worst = EXIT_OK
    for target in args.targets:
        proof_id = target
        if os.path.exists(receipt_path(target)):
            try:
                proof_id = read_receipt(target)["proof_id"]
            except (OSError, ValueError, KeyError) as error:
                print("verifyum: " + str(error), file=sys.stderr)
                worst = max(worst, EXIT_USAGE)
                continue
        try:
            result = verify_witness(proof_id)
        except VerifyumError as error:
            print("verifyum: " + str(error), file=sys.stderr)
            worst = max(worst, EXIT_UNAVAILABLE)
            continue
        ok = bool(result.get("valid"))
        if not ok:
            worst = max(worst, EXIT_FAILED)
        _emit(
            {"proof_id": proof_id, **result},
            args.json,
            [
                ("witnessed " if ok else "FAILED    ") + proof_id,
                "  checkpoint " + str(result.get("checkpoint_hash") or result.get("checkpoint", {}).get("checkpoint_hash")),
            ],
        )
    return worst


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="verifyum",
        description="Prove that a file existed, unchanged, at a point in time.",
        epilog="The receipt beside each file holds the nonce. Verifyum never has it, "
               "so a lost receipt cannot be recovered from us or from anyone. Treat it "
               "like a key: it is not made private by being written.",
    )
    parser.add_argument("--version", action="version", version="verifyum " + USER_AGENT.split("/")[-1])
    sub = parser.add_subparsers(dest="command", required=True)

    stamp = sub.add_parser("stamp", help="anchor one or more files and write their receipts")
    stamp.add_argument("files", nargs="+")
    stamp.add_argument("--force", action="store_true", help="replace an existing receipt")
    stamp.add_argument("--no-wait", action="store_true", help="return as soon as the anchor is queued")
    stamp.add_argument("--timeout", type=int, default=180, help="seconds to wait for finality")
    stamp.add_argument("--json", action="store_true", help="machine readable output")
    stamp.set_defaults(handler=_cmd_stamp)

    check = sub.add_parser("verify", help="check files against their receipts and the public record")
    check.add_argument("files", nargs="+")
    check.add_argument("--json", action="store_true", help="machine readable output")
    check.set_defaults(handler=_cmd_verify)

    witness = sub.add_parser("witness", help="check a proof against the witness layer")
    witness.add_argument("targets", nargs="+", metavar="FILE_OR_PROOF_ID")
    witness.add_argument("--json", action="store_true", help="machine readable output")
    witness.set_defaults(handler=_cmd_witness)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
