#!/bin/bash
#
# Verifyum verification in a shell. Reproduces the witness hashing rules of
# PROTOCOL.md with nothing but coreutils, xxd, jq and openssl, so a proof can
# be checked on a machine where installing a language runtime is not an
# option.
#
# Tools: bash 4+, sha256sum, base64, xxd, jq 1.6+, openssl 3 (Ed25519).
# On macOS replace sha256sum with "shasum -a 256" and use GNU coreutils, or
# adjust b64_decode to use "base64 -D".
#
# Reads the vector files from $VERIFYUM_VECTORS, default: the vectors
# directory beside this script. Prints one "name=value" line per quantity and
# exits 0 only when every recomputed value matches the published one.

set -uo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VECTORS=${VERIFYUM_VECTORS:-$HERE/vectors}

TMP=$(mktemp -d) || { echo "cannot create a temporary directory" >&2; exit 2; }
trap 'rm -rf "$TMP"' EXIT

for tool in sha256sum base64 xxd jq openssl; do
    command -v "$tool" > /dev/null 2>&1 || {
        echo "missing required tool: $tool" >&2
        exit 2
    }
done

for file in metadata.json witnesses.json hourly.json daily.json keys.json; do
    [ -r "$VECTORS/$file" ] || { echo "cannot read $VECTORS/$file" >&2; exit 2; }
done

problems=0
note () { problems=$((problems + 1)); echo "$1" >&2; }

# R1. The payload arrives on stdin because it may contain NUL bytes, which a
# shell variable cannot hold.
digest_stdin () {
    printf 'sha256:%s' "$(sha256sum | cut -d' ' -f1)"
}

# R2. jq -cS sorts object keys by codepoint, emits compact output, leaves "/"
# unescaped and writes non-ASCII raw, which is what the reference does. The
# trailing newline jq adds is dropped by command substitution.
jcs () {
    jq -cS . "$1"
}

jcs_expr () {
    jq -cS "$1" "$2"
}

# The 32 raw bytes behind a "sha256:<hex>" digest string.
digest_bytes () {
    local d=$1
    case $d in
        sha256:*) : ;;
        *) note "not a digest string: $d"; return 1 ;;
    esac
    local hex=${d#sha256:}
    [ ${#hex} -eq 64 ] || { note "digest is not 64 hex chars: $d"; return 1; }
    case $hex in
        *[!0-9a-f]*) note "digest has non-lowercase-hex: $d"; return 1 ;;
    esac
    printf '%s' "$hex" | xxd -r -p
}

# R5. The leaf covers the full public metadata document, signature included,
# under a prefix that begins with a NUL byte.
proof_leaf_hash () {
    { printf '\000verifyum:witness:proof-leaf:v1\n'
      printf '%s' "$(jcs "$1")"
    } | digest_stdin
}

# R7. Node hashing takes the raw bytes of both children, not their text.
node_hash () {
    { printf '\001verifyum:witness:node:v1\n'
      digest_bytes "$1"
      digest_bytes "$2"
    } | digest_stdin
}

# R3. The checkpoint hash is taken over the document with its own hash field
# removed, and this prefix has no leading NUL.
checkpoint_hash () {
    { printf 'verifyum:witness:checkpoint:v1\n'
      printf '%s' "$(jcs_expr 'del(.checkpoint_hash)' "$1")"
    } | digest_stdin
}

# R4. The checkpoint document is the canonical JSON plus one newline, which
# is exactly what jq -cS writes, so the file can go straight into the hash.
document_digest () {
    jcs_expr '.' "$1" | digest_stdin
}

sigsum_checksum () {
    digest_bytes "$1" | sha256sum | cut -d' ' -f1
}

# R10. Strict base64url: URL alphabet only, no padding, and a length that
# cannot be a truncated group.
b64url_decode () {
    local s=$1
    case $s in
        *[!A-Za-z0-9_-]*) note "value is not strict base64url"; return 1 ;;
    esac
    [ $(( ${#s} % 4 )) -ne 1 ] || { note "base64url length is impossible"; return 1; }
    local pad=$(( (4 - ${#s} % 4) % 4 ))
    local i
    for (( i = 0; i < pad; i++ )); do s="$s="; done
    printf '%s' "$s" | tr -- '-_' '+/' | base64 -d 2>/dev/null
}

# R9. Walk the path from the leaf to the root. A step must have exactly the
# two keys, and side decides which operand the sibling becomes.
path_root () {
    local current=$1 witnesses=$2
    local steps
    steps=$(jq -r '.membership.path | length' "$witnesses")
    local i side hash keys
    for (( i = 0; i < steps; i++ )); do
        keys=$(jq -r --argjson i "$i" '.membership.path[$i] | keys_unsorted | sort | join(",")' "$witnesses")
        [ "$keys" = "hash,side" ] || { note "path step $i does not have exactly side and hash"; return 1; }
        side=$(jq -r --argjson i "$i" '.membership.path[$i].side' "$witnesses")
        hash=$(jq -r --argjson i "$i" '.membership.path[$i].hash' "$witnesses")
        case $side in
            left)  current=$(node_hash "$hash" "$current") ;;
            right) current=$(node_hash "$current" "$hash") ;;
            *) note "path step $i has an invalid side: $side"; return 1 ;;
        esac
    done
    printf '%s' "$current"
}

verify_service_signature () {
    local metadata=$1 registry=$2
    local algorithm key_id value network
    algorithm=$(jq -r '.service_signature.algorithm // empty' "$metadata")
    key_id=$(jq -r '.service_signature.key_id // empty' "$metadata")
    value=$(jq -r '.service_signature.value // empty' "$metadata")
    network=$(jq -r '.anchor.network // empty' "$metadata")
    [ "$algorithm" = "ed25519" ] || { note "signature algorithm is not ed25519"; return 1; }

    local keys public
    keys=$(jq -r --arg id "$key_id" --arg n "$network" \
        '[.keys[] | select(.key_id == $id and .algorithm == "ed25519" and .network == $n and (.status == "active" or .status == "retired"))] | length' "$registry")
    [ "$keys" = "1" ] || { note "the registry has $keys keys matching $key_id on $network, expected exactly 1"; return 1; }
    public=$(jq -r --arg id "$key_id" '.keys[] | select(.key_id == $id) | .public_key' "$registry")

    b64url_decode "$public" > "$TMP/pub.raw" || return 1
    [ "$(stat -c%s "$TMP/pub.raw")" = "32" ] || { note "public key is not 32 bytes"; return 1; }
    b64url_decode "$value" > "$TMP/sig.bin" || return 1
    [ "$(stat -c%s "$TMP/sig.bin")" = "64" ] || { note "signature is not 64 bytes"; return 1; }

    # An Ed25519 SPKI wrapper is a fixed 12-byte header followed by the key.
    { printf '302a300506032b6570032100' | xxd -r -p; cat "$TMP/pub.raw"; } > "$TMP/pub.der"
    printf '%s' "$(jcs_expr 'del(.service_signature)' "$metadata")" > "$TMP/msg.bin"

    if openssl pkeyutl -verify -pubin -inkey "$TMP/pub.der" -keyform DER \
        -rawin -in "$TMP/msg.bin" -sigfile "$TMP/sig.bin" > /dev/null 2>&1; then
        printf 'true'
    else
        printf 'false'
    fi
}

# The probe exists so the ports can be compared on escaping and key order
# rather than only on values that happen to be ASCII.
printf '%s' '{"b":1,"a":"x<y&z/é","n":null,"t":true,"arr":[2,"s",{"z":0,"y":[]}]}' > "$TMP/probe.json"

leaf=$(proof_leaf_hash "$VECTORS/metadata.json")
root=$(path_root "$leaf" "$VECTORS/witnesses.json") || root="sha256:0000000000000000000000000000000000000000000000000000000000000000"
published_root=$(jq -r '.checkpoint.merkle_root' "$VECTORS/witnesses.json")
[ "$root" = "$published_root" ] && path_matches=true || { path_matches=false; note "the path does not reach the published root"; }

hourly=$(checkpoint_hash "$VECTORS/hourly.json")
hourly_published=$(jq -r '.checkpoint_hash' "$VECTORS/hourly.json")
[ "$hourly" = "$hourly_published" ] && hourly_matches=true || { hourly_matches=false; note "the hourly checkpoint hash does not match"; }

daily=$(checkpoint_hash "$VECTORS/daily.json")
daily_published=$(jq -r '.checkpoint_hash' "$VECTORS/daily.json")
[ "$daily" = "$daily_published" ] && daily_matches=true || { daily_matches=false; note "the daily checkpoint hash does not match"; }

daily_doc=$(document_digest "$VECTORS/daily.json")
sigsum=$(sigsum_checksum "$daily_doc")
signature=$(verify_service_signature "$VECTORS/metadata.json" "$VECTORS/keys.json") || signature=false
probe=$(jcs "$TMP/probe.json")

printf 'proof_leaf_hash=%s\n' "$leaf"
printf 'path_root=%s\n' "$root"
printf 'path_matches_checkpoint=%s\n' "$path_matches"
printf 'hourly_checkpoint_hash=%s\n' "$hourly"
printf 'hourly_matches=%s\n' "$hourly_matches"
printf 'daily_checkpoint_hash=%s\n' "$daily"
printf 'daily_matches=%s\n' "$daily_matches"
printf 'daily_document_digest=%s\n' "$daily_doc"
printf 'daily_sigsum_checksum=%s\n' "$sigsum"
printf 'service_signature_valid=%s\n' "$signature"
printf 'jcs_probe=%s\n' "$probe"

if [ "$path_matches" = true ] && [ "$hourly_matches" = true ] &&
   [ "$daily_matches" = true ] && [ "$signature" = true ]; then
    exit 0
fi
exit 1
