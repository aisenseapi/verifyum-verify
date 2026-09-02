"""Verifyum client, single file, standard library only.

Creates a privacy-preserving proof that exact bytes existed at a point in
time. The data never leaves the machine: only a domain-separated commitment
is sent. No account, wallet or API key is required.

    from verifyum import anchor_bytes, anchor_file, anchor_record, verify

    proof = anchor_file("contract.pdf")
    print(proof["proof_url"])

Keep the returned draft. It holds the nonce, and without it nobody can link
the original data to the public proof.

Reference: https://verifyum.com/agents
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request

__all__ = ["commitment_for", "anchor_bytes", "anchor_file", "anchor_record", "verify", "VerifyumError"]

API_BASE = os.environ.get("VERIFYUM_API_BASE", "https://api.verifyum.com")
PROOF_DOMAIN = os.environ.get("VERIFYUM_PROOF_DOMAIN", "verifyum.com")
USER_AGENT = "verifyum-python/1.0"


class VerifyumError(RuntimeError):
    """A Verifyum request failed. `retry_after` is set when it is worth retrying."""

    def __init__(self, message: str, *, status: int | None = None, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def _canonical(value):
    """RFC 8785 style canonical JSON for the manifest shapes used here."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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
    digest = hashlib.sha256(b"verifyum:commitment:v2\n" + _canonical(manifest)).hexdigest()
    commitment = "sha256:" + digest
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
    return anchor_bytes(_canonical(record), **kwargs)


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
        + hashlib.sha256(b"verifyum:commitment:v2\n" + _canonical(manifest)).hexdigest()
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
