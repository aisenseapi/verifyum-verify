# Ground truth, all fetched live 2026-09-02
proof_id: 1ns0c79n4m0sy5es4wztcvrm1y
metadata.json -> proof leaf hash must be: sha256:4daa8b55d67b55edaa111c2b76e184cccc2fedc88a034b023ea91170ef6c871d
witnesses.json path from that leaf must reach root: sha256:dbde1e168a15113d88b12c28192ed236d85b23ae5479812d930888e9c6664e54
hourly.json checkpoint_hash: sha256:bc3653e93164e62d0bc1272b2d76eace51df7951d692a3138991c144c631728c (recompute from the document per the spec)
daily.json checkpoint_hash: sha256:6237cfaafaf4ad6ed3f54a4f6de7f758b7368ac1ff8bedd3e9b1f3aef0cee93a
daily.json document digest -> Sigsum leaf checksum = sha256(raw 32 bytes of document digest) must be hex: 6c0271f184d4a8ec991edca7298e0328469749192f7067a4b9dfb3ee3847a658 (this is the leaf at index 63546 in seasalp.glasklar.is, matched today)
keys.json + metadata.json -> service_signature must verify (Ed25519 over JCS(metadata minus service_signature))
