# verifyum (Go port)

Standard-library implementation of the Verifyum verification primitives in
`PROTOCOL.md` (R1 to R7, R9, R10), plus the check program that reproduces
the section 13 vectors. R8 (Merkle tree construction) is not implemented:
this port only verifies paths, it does not build trees. Section 3
field-level validation (canonical time, period arithmetic, proof-id and
memo checks) is only partially implemented; the hashes do not depend on it.

Requires Go 1.22 or newer: encoding/json emits `\b` and `\f` as short
escapes only from 1.22 (older toolchains wrote the six-character forms
`\u0008` and `\u000c`, which would break byte compatibility).
The `go 1.22` line in `go.mod` makes an older toolchain refuse to build
rather than silently diverge.

`EXPECTED_STDOUT.txt` next to this file is the exact stdout the check must
produce for the vectors (computed independently in Python from the spec);
diff `./check > out.txt` against it.

Build and run, from this directory:

    go build ./cmd/check
    ./check

On Windows the binary is `check.exe`, so run `.\check.exe`. The vector
directory is read from `VERIFYUM_VECTORS`; without it the check uses the
default path compiled into `cmd/check/main.go`. Exit code 0 means every
value reproduced and the service signature verified (or was left
unchecked because `keys.json` was absent).
