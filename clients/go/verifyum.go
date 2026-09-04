// Package verifyum implements the Verifyum verification primitives R1 to R10
// from PROTOCOL.md: canonical JSON, digests, checkpoint and leaf hashes,
// Merkle path verification and the Ed25519 service signature.
//
// Values are the shapes encoding/json produces with UseNumber: nil, bool,
// string, json.Number, []any and map[string]any. Nothing else is accepted,
// so a float can never reach the encoder by accident.
package verifyum

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Object is a decoded JSON object.
type Object = map[string]any

const (
	digestPrefix         = "sha256:"
	checkpointPrefix     = "verifyum:witness:checkpoint:v1\n"
	proofLeafPrefix      = "\x00verifyum:witness:proof-leaf:v1\n"
	checkpointLeafPrefix = "\x00verifyum:witness:checkpoint-leaf:v1\n"
	nodePrefix           = "\x01verifyum:witness:node:v1\n"

	// The reference has no path limit; 64 steps cover 2^64 leaves.
	maxPathLength = 64
)

var (
	checkpointKeys = []string{
		"algorithm", "checkpoint_hash", "created_at", "kind", "merkle_root",
		"network", "period_end", "period_start", "previous_checkpoint_hash",
		"protocol", "schema", "subject_count", "subject_type", "version",
	}
	metadataKeys = []string{
		"schema", "protocol", "version", "proof_id", "commitment",
		"submitted_at", "anchor", "service_signature",
	}
	signatureKeys = []string{"algorithm", "key_id", "value"}
)

// Parse decodes one JSON document into the value subset of section 2.1.
// Numbers stay as json.Number and are checked to be integers here, because
// the encoder would otherwise happily serialize a float.
func Parse(raw []byte) (any, error) {
	// The decoder replaces invalid UTF-8 with U+FFFD instead of failing.
	if !utf8.Valid(raw) {
		return nil, errors.New("document is not valid UTF-8")
	}
	// encoding/json keeps the last of duplicate object keys, where the
	// reference rejects the document. Saying "no published document has
	// duplicates" is an argument about today's data, not about an adversary,
	// and two verifiers that disagree on hostile input are worse than one.
	// The token walk below is a separate pass so the decode stays ordinary.
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	// Anything after the first value means the input was not one document.
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON document")
	}
	if err := check(v); err != nil {
		return nil, err
	}
	return v, nil
}

// rejectDuplicateKeys walks the token stream and fails on the first object
// that names a key twice, at any depth.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return walkForDuplicates(dec)
}

func walkForDuplicates(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		// A malformed document is the decoder's error to report, not ours.
		return nil
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil
			}
			if _, repeated := seen[key]; repeated {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkForDuplicates(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		_ = err
	case '[':
		for dec.More() {
			if err := walkForDuplicates(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		_ = err
	}
	return nil
}

// ParseObject is Parse restricted to a top-level object.
func ParseObject(raw []byte) (Object, error) {
	v, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("document is not a JSON object")
	}
	return obj, nil
}

func check(v any) error {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		return nil
	case string:
		if !utf8.ValidString(x) {
			return errors.New("string is not valid UTF-8")
		}
		return nil
	case json.Number:
		return checkInteger(string(x))
	case []any:
		for _, e := range x {
			if err := check(e); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		// The reference encodes an empty object as [] and cannot round-trip it.
		if len(x) == 0 {
			return errors.New("empty object is not encodable")
		}
		for k, e := range x {
			if !isKey(k) {
				return fmt.Errorf("object key %q is not printable ASCII", k)
			}
			if err := check(e); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
}

// checkInteger accepts only what the reference's signed 64-bit integer
// would have produced: no sign other than a leading minus, no fraction,
// no exponent, and no negative zero.
func checkInteger(s string) error {
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return fmt.Errorf("number %s is not a 64-bit integer", s)
	}
	if s == "-0" || s[0] == '+' {
		return fmt.Errorf("number %s is not canonical", s)
	}
	return nil
}

func isKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// JCS returns the canonical serialization of section 2. encoding/json
// already sorts map keys in byte order and, from Go 1.22, uses the RFC 8785
// short escapes; SetEscapeHTML(false) keeps <, > and & raw.
func JCS(v any) ([]byte, error) {
	if err := check(v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// Digest is R1.
func Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return digestPrefix + hex.EncodeToString(sum[:])
}

// IsDigest reports whether s matches ^sha256:[0-9a-f]{64}$.
func IsDigest(s string) bool {
	if len(s) != len(digestPrefix)+64 || !strings.HasPrefix(s, digestPrefix) {
		return false
	}
	for i := len(digestPrefix); i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// DigestBytes returns the 32 raw bytes of a digest string.
func DigestBytes(s string) ([]byte, error) {
	if !IsDigest(s) {
		return nil, fmt.Errorf("not a digest string: %q", s)
	}
	return hex.DecodeString(s[len(digestPrefix):])
}

func requireKeys(obj Object, keys []string) error {
	if len(obj) != len(keys) {
		return fmt.Errorf("object has %d keys, expected %d", len(obj), len(keys))
	}
	for _, k := range keys {
		if _, present := obj[k]; !present {
			return fmt.Errorf("missing key %q", k)
		}
	}
	return nil
}

// validateCheckpoint covers the parts of section 3.3 the hash rules rely on.
func validateCheckpoint(cp Object) error {
	if err := requireKeys(cp, checkpointKeys); err != nil {
		return err
	}
	kind, _ := cp["kind"].(string)
	subjectType, _ := cp["subject_type"].(string)
	switch {
	case kind == "hourly" && subjectType == "proof-v2":
	case kind == "daily" && subjectType == "hourly-checkpoint-v1":
	default:
		return fmt.Errorf("checkpoint kind %q does not match subject_type %q", kind, subjectType)
	}
	for _, k := range []string{"checkpoint_hash", "merkle_root"} {
		if s, _ := cp[k].(string); !IsDigest(s) {
			return fmt.Errorf("checkpoint %s is not a digest string", k)
		}
	}
	return nil
}

// CheckpointHash is R3: only checkpoint_hash is removed before hashing.
func CheckpointHash(cp Object) (string, error) {
	if err := validateCheckpoint(cp); err != nil {
		return "", err
	}
	body := make(Object, len(cp))
	for k, v := range cp {
		if k != "checkpoint_hash" {
			body[k] = v
		}
	}
	enc, err := JCS(body)
	if err != nil {
		return "", err
	}
	return Digest(append([]byte(checkpointPrefix), enc...)), nil
}

// CheckpointDocument is R4: the full canonical checkpoint plus one newline,
// which is byte-for-byte what verifyum.com publishes.
func CheckpointDocument(cp Object) ([]byte, error) {
	if err := validateCheckpoint(cp); err != nil {
		return nil, err
	}
	enc, err := JCS(cp)
	if err != nil {
		return nil, err
	}
	return append(enc, '\n'), nil
}

// DocumentDigest is R1 over R4.
func DocumentDigest(cp Object) (string, error) {
	doc, err := CheckpointDocument(cp)
	if err != nil {
		return "", err
	}
	return Digest(doc), nil
}

// SigsumChecksum is the Sigsum leaf checksum of a daily checkpoint: the
// publisher submits the 32 raw digest bytes as the message and Sigsum
// hashes the message once more.
func SigsumChecksum(daily Object) (string, error) {
	if kind, _ := daily["kind"].(string); kind != "daily" {
		return "", errors.New("sigsum checksum is only defined for daily checkpoints")
	}
	d, err := DocumentDigest(daily)
	if err != nil {
		return "", err
	}
	raw, err := DigestBytes(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ProofLeafHash is R5 over the full metadata, service_signature included.
func ProofLeafHash(metadata Object) (string, error) {
	if err := requireKeys(metadata, metadataKeys); err != nil {
		return "", err
	}
	enc, err := JCS(metadata)
	if err != nil {
		return "", err
	}
	return Digest(append([]byte(proofLeafPrefix), enc...)), nil
}

// CheckpointLeafHash is R6 over the raw bytes of an hourly checkpoint_hash.
func CheckpointLeafHash(hourly Object) (string, error) {
	if err := validateCheckpoint(hourly); err != nil {
		return "", err
	}
	if kind, _ := hourly["kind"].(string); kind != "hourly" {
		return "", errors.New("only hourly checkpoints are daily-tree subjects")
	}
	// validateCheckpoint already proved checkpoint_hash is a digest string.
	raw, err := DigestBytes(hourly["checkpoint_hash"].(string))
	if err != nil {
		return "", err
	}
	return Digest(append([]byte(checkpointLeafPrefix), raw...)), nil
}

// NodeHash is R7.
func NodeHash(left, right string) (string, error) {
	l, err := DigestBytes(left)
	if err != nil {
		return "", err
	}
	r, err := DigestBytes(right)
	if err != nil {
		return "", err
	}
	payload := make([]byte, 0, len(nodePrefix)+len(l)+len(r))
	payload = append(payload, nodePrefix...)
	payload = append(payload, l...)
	payload = append(payload, r...)
	return Digest(payload), nil
}

// PathRoot walks a membership path per R9 and returns the digest reached.
// Each step must be an object with exactly the keys side and hash; a step
// with two other keys fails the side or hash check below, so the key count
// alone is enough to enforce the exact set.
func PathRoot(leafHash string, path any) (string, error) {
	if !IsDigest(leafHash) {
		return "", errors.New("leaf_hash is not a digest string")
	}
	steps, ok := path.([]any)
	if !ok {
		return "", errors.New("path is not an array")
	}
	if len(steps) > maxPathLength {
		return "", fmt.Errorf("path has %d steps, limit is %d", len(steps), maxPathLength)
	}
	current := leafHash
	for i, raw := range steps {
		step, ok := raw.(map[string]any)
		if !ok || len(step) != 2 {
			return "", fmt.Errorf("path step %d is not an object with exactly side and hash", i)
		}
		side, _ := step["side"].(string)
		hash, _ := step["hash"].(string)
		if !IsDigest(hash) {
			return "", fmt.Errorf("path step %d hash is not a digest string", i)
		}
		var err error
		switch side {
		case "left":
			current, err = NodeHash(hash, current)
		case "right":
			current, err = NodeHash(current, hash)
		default:
			return "", fmt.Errorf("path step %d side %q is not left or right", i, side)
		}
		if err != nil {
			return "", err
		}
	}
	return current, nil
}

// VerifyPath is R9.
func VerifyPath(leafHash string, path any, root string) (bool, error) {
	if !IsDigest(root) {
		return false, errors.New("root is not a digest string")
	}
	reached, err := PathRoot(leafHash, path)
	if err != nil {
		return false, err
	}
	return reached == root, nil
}

// DecodeBase64URL is the strict decoder of section 11.1. Strict() rejects
// non-zero trailing bits but tolerates newlines, hence the alphabet scan;
// the re-encode comparison is kept as the spec's own canonical check.
func DecodeBase64URL(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("base64url: character outside the URL alphabet")
		}
	}
	if len(s)%4 == 1 {
		return nil, errors.New("base64url: invalid length")
	}
	out, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	if base64.RawURLEncoding.EncodeToString(out) != s {
		return nil, errors.New("base64url: encoding is not canonical")
	}
	return out, nil
}

// VerifyServiceSignature is R10. A nil error means the signature verifies
// against exactly one usable registry key.
func VerifyServiceSignature(metadata Object, registry Object) error {
	if err := requireKeys(metadata, metadataKeys); err != nil {
		return err
	}
	sig, ok := metadata["service_signature"].(map[string]any)
	if !ok {
		return errors.New("service_signature is not an object")
	}
	if err := requireKeys(sig, signatureKeys); err != nil {
		return err
	}
	if alg, _ := sig["algorithm"].(string); alg != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", alg)
	}
	keyID, ok := sig["key_id"].(string)
	if !ok || keyID == "" {
		return errors.New("service_signature.key_id is not a string")
	}
	value, ok := sig["value"].(string)
	if !ok {
		return errors.New("service_signature.value is not a string")
	}
	sigBytes, err := DecodeBase64URL(value)
	if err != nil {
		return err
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, expected %d", len(sigBytes), ed25519.SignatureSize)
	}
	// Indexing a nil map is safe, so a missing anchor fails the type check.
	anchor, _ := metadata["anchor"].(map[string]any)
	network, ok := anchor["network"].(string)
	if !ok {
		return errors.New("anchor.network is not a string")
	}
	pub, err := registryKey(registry, keyID, network)
	if err != nil {
		return err
	}
	unsigned := make(Object, len(metadata))
	for k, v := range metadata {
		if k != "service_signature" {
			unsigned[k] = v
		}
	}
	message, err := JCS(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), message, sigBytes) {
		return errors.New("service signature does not verify")
	}
	return nil
}

// registryKey selects the one registry entry that may sign for keyID on
// network. Zero matches and more than one are both failures, never a guess.
func registryKey(registry Object, keyID, network string) ([]byte, error) {
	entries, ok := registry["keys"].([]any)
	if !ok {
		return nil, errors.New("registry has no keys array")
	}
	matches := 0
	var encoded string
	for _, raw := range entries {
		e, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, _ := e["key_id"].(string)
		net, _ := e["network"].(string)
		status, _ := e["status"].(string)
		alg, _ := e["algorithm"].(string)
		pk, isString := e["public_key"].(string)
		if id != keyID || net != network || alg != "ed25519" || !isString {
			continue
		}
		if status != "active" && status != "retired" {
			continue
		}
		matches++
		encoded = pk
	}
	if matches == 0 {
		return nil, fmt.Errorf("no usable registry key %q for %s", keyID, network)
	}
	if matches > 1 {
		return nil, fmt.Errorf("registry key %q for %s is not unique", keyID, network)
	}
	pub, err := DecodeBase64URL(encoded)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, expected %d", len(pub), ed25519.PublicKeySize)
	}
	return pub, nil
}
