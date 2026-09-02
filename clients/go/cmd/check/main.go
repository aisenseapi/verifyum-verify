// Command check reproduces the PROTOCOL.md section 13 vectors and prints
// one name=value line per quantity. Diagnostics go to stderr only, so the
// stdout of every port can be diffed directly.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"verifyum"
)

const defaultVectors = "checks/vectors"

// A raw string literal keeps \u00e9 as a JSON escape for the parser to
// decode, which is what the probe is meant to exercise.
const probe = `{"b":1,"a":"x<y&z/\u00e9","n":null,"t":true,"arr":[2,"s",{"z":0,"y":[]}]}`

// findVectors walks up from the working directory looking for the vectors,
// so the program runs from the repository root, from clients/go, or from
// anywhere between them.
func findVectors() string {
	at, err := os.Getwd()
	if err != nil {
		return defaultVectors
	}
	for {
		candidate := filepath.Join(at, defaultVectors)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(at)
		if parent == at {
			return defaultVectors
		}
		at = parent
	}
}

func main() {
	dir := os.Getenv("VERIFYUM_VECTORS")
	if dir == "" {
		dir = findVectors()
	}

	metadata := mustLoad(dir, "metadata.json")
	bundle := mustLoad(dir, "witnesses.json")
	hourly := mustLoad(dir, "hourly.json")
	daily := mustLoad(dir, "daily.json")

	ok := true
	var lines []string
	emit := func(name, value string) {
		lines = append(lines, name+"="+value)
	}

	leaf, err := verifyum.ProofLeafHash(metadata)
	if err != nil {
		fatal(err)
	}
	emit("proof_leaf_hash", leaf)

	checkpoint, _ := bundle["checkpoint"].(map[string]any)
	membership, _ := bundle["membership"].(map[string]any)
	root, err := verifyum.PathRoot(leaf, membership["path"])
	if err != nil {
		warn(err)
		root = "invalid"
	}
	emit("path_root", root)
	merkleRoot, _ := checkpoint["merkle_root"].(string)
	pathMatches := err == nil && verifyum.IsDigest(merkleRoot) && root == merkleRoot
	emit("path_matches_checkpoint", boolString(pathMatches))
	ok = ok && pathMatches

	for _, cp := range []struct {
		name string
		doc  verifyum.Object
	}{{"hourly", hourly}, {"daily", daily}} {
		hash, err := verifyum.CheckpointHash(cp.doc)
		if err != nil {
			fatal(err)
		}
		emit(cp.name+"_checkpoint_hash", hash)
		declared, _ := cp.doc["checkpoint_hash"].(string)
		matches := hash == declared
		emit(cp.name+"_matches", boolString(matches))
		ok = ok && matches
	}

	documentDigest, err := verifyum.DocumentDigest(daily)
	if err != nil {
		fatal(err)
	}
	emit("daily_document_digest", documentDigest)
	checksum, err := verifyum.SigsumChecksum(daily)
	if err != nil {
		fatal(err)
	}
	emit("daily_sigsum_checksum", checksum)

	// A missing registry leaves the signature unchecked rather than failed;
	// a present registry that does not verify is a failure.
	signature := "unchecked"
	registry, err := load(dir, "keys.json")
	switch {
	case errors.Is(err, os.ErrNotExist):
		warn(err)
	case err != nil:
		fatal(err)
	default:
		if err := verifyum.VerifyServiceSignature(metadata, registry); err != nil {
			warn(err)
			signature = "false"
			ok = false
		} else {
			signature = "true"
		}
	}
	emit("service_signature_valid", signature)

	probeValue, err := verifyum.Parse([]byte(probe))
	if err != nil {
		fatal(err)
	}
	encoded, err := verifyum.JCS(probeValue)
	if err != nil {
		fatal(err)
	}
	emit("jcs_probe", string(encoded))

	for _, line := range lines {
		fmt.Println(line)
	}
	if !ok {
		os.Exit(1)
	}
}

func load(dir, name string) (verifyum.Object, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	obj, err := verifyum.ParseObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return obj, nil
}

func mustLoad(dir, name string) verifyum.Object {
	obj, err := load(dir, name)
	if err != nil {
		fatal(err)
	}
	return obj
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func warn(err error) {
	fmt.Fprintln(os.Stderr, "check:", err)
}

// fatal is for inputs the check cannot even start on; exit 2 keeps it
// apart from exit 1, which means the vectors loaded but did not reproduce.
func fatal(err error) {
	warn(err)
	os.Exit(2)
}
