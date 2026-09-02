#!/usr/bin/env node
/**
 * Conformance check for the Node port. Loads the shared vectors, recomputes
 * every quantity ports are compared on, prints them as name=value lines and
 * exits 0 only when the recomputed values agree with the documents.
 *
 *   VERIFYUM_VECTORS=/path/to/vectors node check.mjs
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkpointDocument,
  checkpointDocumentDigest,
  checkpointHash,
  explainServiceSignature,
  jcs,
  parseDocument,
  pathRoot,
  proofLeafHash,
  sigsumChecksum,
  validateCheckpoint,
  validateProofMetadata,
  validateWitnessBundle,
} from "../clients/verifyum.mjs";

const DEFAULT_VECTORS = join(dirname(fileURLToPath(import.meta.url)), "vectors");
const vectors = process.env.VERIFYUM_VECTORS || DEFAULT_VECTORS;

let problems = 0;
const warn = (message) => {
  problems += 1;
  process.stderr.write(`${message}\n`);
};
const readBytes = (name) => readFileSync(join(vectors, name));
// Strict parse: a number written with a fraction or exponent is rejected like the reference does.
const readJson = (name) => {
  try {
    return parseDocument(readBytes(name));
  } catch (error) {
    process.stderr.write(`${name}: rejected, ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
};

// Validation problems are reported on stderr and fail the exit code, but do
// not change the printed values, so every port prints the same lines even on
// a document it would reject.
function validate(label, run) {
  try {
    run();
  } catch (error) {
    warn(`${label}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const metadata = readJson("metadata.json");
const witnesses = readJson("witnesses.json");
const hourlyBytes = readBytes("hourly.json");
const dailyBytes = readBytes("daily.json");
const hourly = readJson("hourly.json");
const daily = readJson("daily.json");

validate("metadata.json", () => validateProofMetadata(metadata));
validate("witnesses.json", () => validateWitnessBundle(witnesses));
validate("hourly.json", () => validateCheckpoint(hourly));
validate("daily.json", () => validateCheckpoint(daily));
for (const [name, bytes, checkpoint] of [["hourly.json", hourlyBytes, hourly], ["daily.json", dailyBytes, daily]]) {
  if (!bytes.equals(checkpointDocument(checkpoint))) warn(`${name}: file bytes differ from the canonical checkpoint document`);
}

const leafHash = proofLeafHash(metadata);
if (leafHash !== witnesses.membership.leaf_hash) warn("witnesses.json: membership.leaf_hash differs from R5 over metadata.json");
let root = "invalid";
try {
  root = pathRoot(leafHash, witnesses.membership.path);
} catch (error) {
  warn(`witnesses.json path: ${error instanceof Error ? error.message : String(error)}`);
}
const pathMatches = root === witnesses.checkpoint.merkle_root;

const hourlyHash = checkpointHash(hourly);
const hourlyMatches = hourlyHash === hourly.checkpoint_hash;
const dailyHash = checkpointHash(daily);
const dailyMatches = dailyHash === daily.checkpoint_hash;

let signatureState = "unchecked";
if (existsSync(join(vectors, "keys.json"))) {
  const problem = explainServiceSignature(metadata, readJson("keys.json"));
  if (problem !== null) warn(`service signature: ${problem}`);
  signatureState = problem === null ? "true" : "false";
} else {
  // A missing registry leaves the signature unchecked; it is not a mismatch, so it does not fail the run.
  process.stderr.write("keys.json not found, service signature unchecked\n");
}

const probe = { b: 1, a: "x<y&z/\u00e9", n: null, t: true, arr: [2, "s", { z: 0, y: [] }] };

const lines = [
  `proof_leaf_hash=${leafHash}`,
  `path_root=${root}`,
  `path_matches_checkpoint=${pathMatches}`,
  `hourly_checkpoint_hash=${hourlyHash}`,
  `hourly_matches=${hourlyMatches}`,
  `daily_checkpoint_hash=${dailyHash}`,
  `daily_matches=${dailyMatches}`,
  `daily_document_digest=${checkpointDocumentDigest(daily)}`,
  `daily_sigsum_checksum=${sigsumChecksum(daily)}`,
  `service_signature_valid=${signatureState}`,
  `jcs_probe=${jcs(probe)}`,
];
process.stdout.write(`${lines.join("\n")}\n`);

// Exit 0 only when every recomputed value agrees with the documents and no validation problem was reported.
const ok = pathMatches && hourlyMatches && dailyMatches && signatureState !== "false" && problems === 0;
process.exitCode = ok ? 0 : 1;
