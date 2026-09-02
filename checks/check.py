"""Reproduces the Verifyum witness vectors with the Python port.

Reads the vector files from $VERIFYUM_VECTORS and prints one name=value
line per quantity so the ports can be diffed against each other. Exit code
is 0 only when every recomputed hash matches the published one.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clients"))

import verifyum  # noqa: E402

DEFAULT_VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")

JCS_PROBE = {"b": 1, "a": "x<y&z/\u00e9", "n": None, "t": True, "arr": [2, "s", {"z": 0, "y": []}]}


def _reject_duplicates(pairs):
    # A duplicate key would be collapsed silently by dict(); the spec says
    # to reject such a document rather than hash whichever value survived.
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_float(text: str):
    # json.loads would otherwise hand back a float and the hash would be
    # computed over a re-rendered number that no reference ever produced.
    raise ValueError(f"float {text} is not allowed")


def load(directory: str, name: str):
    """Returns (parsed document, raw file bytes)."""
    path = os.path.join(directory, name)
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates, parse_float=_reject_float)
    except ValueError as error:
        raise ValueError(f"{name}: {error}") from None
    return parsed, raw


def _walk_path(leaf: str, path) -> str:
    """Manual R9 walk so the reached value can be printed even on mismatch.
    A malformed step yields "invalid" instead of a traceback."""
    current = leaf
    if not isinstance(path, list):
        return "invalid"
    for step in path:
        if not isinstance(step, dict) or not verifyum.is_digest(step.get("hash")):
            return "invalid"
        if step.get("side") == "left":
            current = verifyum.node_hash(step["hash"], current)
        elif step.get("side") == "right":
            current = verifyum.node_hash(current, step["hash"])
        else:
            return "invalid"
    return current


def main() -> int:
    directory = os.environ.get("VERIFYUM_VECTORS") or DEFAULT_VECTORS
    try:
        metadata, _ = load(directory, "metadata.json")
        witnesses, _ = load(directory, "witnesses.json")
        hourly, hourly_raw = load(directory, "hourly.json")
        daily, daily_raw = load(directory, "daily.json")
        keys, _ = load(directory, "keys.json")
    except (OSError, ValueError) as error:
        print(f"check: cannot load vectors from {directory}: {error}", file=sys.stderr)
        return 2
    for name, doc in (("metadata.json", metadata), ("witnesses.json", witnesses), ("hourly.json", hourly),
                      ("daily.json", daily), ("keys.json", keys)):
        if not isinstance(doc, dict):
            print(f"check: {name} is not a JSON object", file=sys.stderr)
            return 2

    lines: list[tuple[str, str]] = []
    ok = True

    def fail(message: str) -> None:
        nonlocal ok
        ok = False
        print(f"check: {message}", file=sys.stderr)

    try:
        leaf = verifyum.proof_leaf_hash(metadata)
    except (ValueError, TypeError) as error:
        print(f"check: metadata.json is not canonical: {error}", file=sys.stderr)
        return 2
    lines.append(("proof_leaf_hash", leaf))

    membership = witnesses.get("membership") if isinstance(witnesses.get("membership"), dict) else {}
    checkpoint = witnesses.get("checkpoint") if isinstance(witnesses.get("checkpoint"), dict) else {}
    current = _walk_path(leaf, membership.get("path"))
    lines.append(("path_root", current))
    path_matches = verifyum.verify_path(leaf, membership.get("path"), checkpoint.get("merkle_root"))
    if path_matches != (current == checkpoint.get("merkle_root")):
        print("check: verify_path disagrees with the manual walk", file=sys.stderr)
        path_matches = False
    lines.append(("path_matches_checkpoint", "true" if path_matches else "false"))
    ok = ok and path_matches

    hourly_hash = verifyum.checkpoint_hash(hourly)
    hourly_matches = hourly_hash == hourly.get("checkpoint_hash")
    lines.append(("hourly_checkpoint_hash", hourly_hash))
    lines.append(("hourly_matches", "true" if hourly_matches else "false"))
    ok = ok and hourly_matches

    daily_hash = verifyum.checkpoint_hash(daily)
    daily_matches = daily_hash == daily.get("checkpoint_hash")
    lines.append(("daily_checkpoint_hash", daily_hash))
    lines.append(("daily_matches", "true" if daily_matches else "false"))
    ok = ok and daily_matches

    lines.append(("daily_document_digest", verifyum.checkpoint_document_digest(daily)))
    lines.append(("daily_sigsum_checksum", verifyum.sigsum_checksum(daily)))

    signature = verifyum.verify_service_signature(metadata, keys)
    if signature is None:
        print("check: cryptography not importable, service signature unchecked", file=sys.stderr)
        lines.append(("service_signature_valid", "unchecked"))
    else:
        lines.append(("service_signature_valid", "true" if signature else "false"))
        ok = ok and signature

    lines.append(("jcs_probe", verifyum.jcs(JCS_PROBE).decode("utf-8")))

    # Exit-code-only checks (no extra stdout lines, the contract above is
    # fixed): the whole witnesses.json bundle must be internally consistent
    # with the recomputed leaf and checkpoint hash, and the published
    # checkpoint files must be byte-identical to the canonical document.
    result = verifyum.verify_witness_documents(metadata, witnesses, keys)
    for name, value in result["checks"].items():
        if value is False:
            fail(f"witnesses.json check {name} failed")
    if hourly.get("kind") != "hourly" or daily.get("kind") != "daily":
        fail("hourly.json / daily.json have the wrong kind")
    if verifyum.checkpoint_document(hourly) != hourly_raw:
        fail("hourly.json bytes differ from the canonical checkpoint document")
    if verifyum.checkpoint_document(daily) != daily_raw:
        fail("daily.json bytes differ from the canonical checkpoint document")
    if checkpoint != hourly:
        fail("witnesses.json checkpoint differs from hourly.json")

    out = "".join(f"{name}={value}\n" for name, value in lines)
    sys.stdout.buffer.write(out.encode("utf-8"))
    sys.stdout.flush()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
