#!/usr/bin/env node
/**
 * Verifyum client, single file, no dependencies. Node.js 20+ or any modern
 * runtime with Web Crypto and fetch.
 *
 * Creates a privacy-preserving proof that exact bytes existed at a point in
 * time. The data never leaves the machine: only a domain-separated
 * commitment is sent. No account, wallet or API key is required.
 *
 *   import { anchorFile, anchorRecord, verify } from "./verifyum.mjs";
 *
 *   const proof = await anchorFile("contract.pdf");
 *   console.log(proof.proof_url);
 *
 * Keep the returned privateDraft. It holds the nonce, and without it nobody
 * can link the original data to the public proof.
 *
 * Reference: https://verifyum.com/agents
 */

import { createHash, createPublicKey, verify as ed25519Verify } from "node:crypto";

const API_BASE = globalThis.process?.env?.VERIFYUM_API_BASE ?? "https://api.verifyum.com";
const PROOF_DOMAIN = globalThis.process?.env?.VERIFYUM_PROOF_DOMAIN ?? "verifyum.com";
const USER_AGENT = "verifyum-js/1.3.0";
const PREFIX = new TextEncoder().encode("verifyum:commitment:v2\n");

export class VerifyumError extends Error {
  constructor(message, { status = null, retryAfter = null } = {}) {
    super(message);
    this.name = "VerifyumError";
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

/** RFC 8785 style canonical JSON for the shapes used here. */
export function canonicalize(value) {
  if (value === null || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

const hex = (buffer) => Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (bytes) => hex(await crypto.subtle.digest("SHA-256", bytes));

async function request(method, path, payload) {
  const url = path.startsWith("https://") ? path : API_BASE + path;
  const response = await fetch(url, {
    method,
    headers: {
      "User-Agent": USER_AGENT,
      Accept: "application/json",
      ...(payload ? { "Content-Type": "application/json" } : {}),
    },
    body: payload ? JSON.stringify(payload) : undefined,
    redirect: "error",
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const retryAfter = Number.parseInt(response.headers.get("retry-after") ?? "", 10);
    throw new VerifyumError(body.message ?? body.error ?? `HTTP ${response.status}`, {
      status: response.status,
      retryAfter: Number.isFinite(retryAfter) ? retryAfter : null,
    });
  }
  return body;
}

/** Returns { commitment, privateDraft }. The draft must be kept locally. */
export async function commitmentFor(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of nonceBytes) binary += String.fromCharCode(byte);
  const nonce = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");

  const manifest = {
    file: { hash: { algorithm: "sha256", value: await sha256(bytes) }, size: String(bytes.length) },
    nonce,
    protocol: "verifyum",
    version: 2,
  };
  const canonical = new TextEncoder().encode(canonicalize(manifest));
  const input = new Uint8Array(PREFIX.length + canonical.length);
  input.set(PREFIX, 0);
  input.set(canonical, PREFIX.length);
  const commitment = `sha256:${await sha256(input)}`;

  return {
    commitment,
    privateDraft: {
      format: "verifyum-private-draft",
      version: 2,
      created_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      manifest,
      commitment,
    },
  };
}

/** Anchors a commitment over `data` and waits for finalization by default. */
export async function anchorBytes(data, { idempotencyKey, wait = true, timeoutMs = 180000 } = {}) {
  const { commitment, privateDraft } = await commitmentFor(data);
  const key = idempotencyKey ?? `js-${(await sha256(new TextEncoder().encode(commitment))).slice(0, 32)}`;

  const health = await request("GET", "/health");
  if (health.anchoring !== "enabled" || health.access !== "public") {
    throw new VerifyumError("Verifyum is not accepting public anchors right now", { retryAfter: 300 });
  }

  let result = await request("POST", "/v2/anchor", { commitment, idempotency_key: key });
  if (wait && result.proof_id) {
    const deadline = Date.now() + timeoutMs;
    while (!["finalized", "failed"].includes(result.status) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 3000));
      result = await request("GET", `/v2/proofs/${result.proof_id}`);
    }
  }
  privateDraft.anchor_result = {
    proof_id: result.proof_id ?? null,
    status: result.status ?? null,
    network: result.network ?? null,
    proof_url: result.proof_url ?? null,
    status_url: result.status_url ?? null,
  };
  return { ...result, commitment, privateDraft };
}

/** Anchors the exact bytes of a local file (Node.js). */
export async function anchorFile(path, options) {
  const { readFile } = await import("node:fs/promises");
  return anchorBytes(new Uint8Array(await readFile(path)), options);
}

/**
 * Anchors a decision record or any JSON document, canonicalized first.
 * See https://verifyum.com/schema/agent-decision-record-v1.json
 */
export async function anchorRecord(record, options) {
  return anchorBytes(new TextEncoder().encode(canonicalize(record)), options);
}

/**
 * Checks that `data` matches the draft and that the proof is finalized. For a
 * fully independent result, also fetch the Solana transaction named in the
 * metadata from any RPC endpoint and compare its memo.
 */
export async function verify(proofId, data, draft) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const manifest = draft.manifest;
  const canonical = new TextEncoder().encode(canonicalize(manifest));
  const input = new Uint8Array(PREFIX.length + canonical.length);
  input.set(PREFIX, 0);
  input.set(canonical, PREFIX.length);

  const checks = {
    hashMatches: (await sha256(bytes)) === manifest.file.hash.value,
    sizeMatches: String(bytes.length) === manifest.file.size,
    commitmentMatches: `sha256:${await sha256(input)}` === draft.commitment,
  };
  const metadata = await request("GET", `https://${proofId}.${PROOF_DOMAIN}/.well-known/verifyum.json`);
  checks.publicCommitmentMatches = metadata.commitment === draft.commitment;
  checks.anchorFinalized = metadata.anchor?.status === "finalized";

  return {
    valid: Object.values(checks).every(Boolean),
    checks,
    transactionSignature: metadata.anchor?.transaction_signature ?? null,
    network: metadata.anchor?.network ?? null,
    boundary:
      "Shows that these exact bytes existed no later than the block time. " +
      "Not authorship, ownership, or that the contents are true.",
  };
}

/* ------------------------------------------------------------------------
 * Witness Layer verification.
 *
 * Byte-exact against ports/PROTOCOL.md (rules R1..R10). Every hash below is
 * computed over the re-serialized canonical form, never over bytes as
 * received, except checkpointDocument() which defines the published bytes.
 * Uses node:crypto rather than Web Crypto so the primitives are synchronous
 * and Ed25519 is available without a dependency.
 * ---------------------------------------------------------------------- */

const REGISTRY_URL = `https://${PROOF_DOMAIN}/.well-known/verifyum-service-keys.json`;
const CHECKPOINT_URL_PREFIX = `https://${PROOF_DOMAIN}/witness/checkpoints/`;
const RECEIPTS_URL_PREFIX = `https://${PROOF_DOMAIN}/witness/receipts/`;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const PROOF_ID_PATTERN = /^[0-7][0-9a-hjkmnp-tv-z]{25}$/;
const CANONICAL_TIME_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const TRANSACTION_SIGNATURE_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{80,90}$/;
const ANCHOR_ADDRESS_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const OBJECT_KEY_PATTERN = /^[\x20-\x7e]+$/;
// PHP turns these keys into integers and the reference then rejects them; never emit them.
const INTEGER_LIKE_KEY_PATTERN = /^(?:0|-?[1-9][0-9]*)$/;
const JSON_INTEGER_PATTERN = /^-?(?:0|[1-9][0-9]*)$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const NETWORKS = new Set(["devnet", "mainnet-beta"]);
const MAX_PATH_LENGTH = 64;

export const WITNESS_BOUNDARY_STATEMENT =
  "A witnessed proof shows that its public metadata was included in a checkpoint that independent " +
  "third parties observed. It does not prove authorship, ownership, or that the file contents are true.";

const utf8 = (text) => Buffer.from(text, "utf8");
const sha256Raw = (bytes) => createHash("sha256").update(bytes).digest();
const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** True when `value` is a digest string, the only digest form documents carry. */
export function isDigest(value) {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

/** R1. `payload` is a string (UTF-8 encoded) or any byte container. */
export function digest(payload) {
  const bytes = typeof payload === "string" ? utf8(payload) : Buffer.from(payload);
  return `sha256:${sha256Raw(bytes).toString("hex")}`;
}

/** The 32 raw bytes behind a digest string. Throws on anything else. */
export function digestBytes(value) {
  if (!isDigest(value)) throw new VerifyumError(`not a digest string: ${String(value)}`);
  return Buffer.from(value.slice("sha256:".length), "hex");
}

function assertCanonicalizable(value, where) {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    // A lone surrogate is not UTF-8 representable; the reference rejects invalid UTF-8.
    if (!value.isWellFormed()) throw new VerifyumError(`${where}: string is not well-formed UTF-16`);
    return;
  }
  if (typeof value === "number") {
    // The reference encoder throws on floats; anything beyond 53 bits could not round-trip here.
    if (!Number.isSafeInteger(value)) throw new VerifyumError(`${where}: only integers can be canonicalized`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertCanonicalizable(item, `${where}[${index}]`));
    return;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).filter((key) => value[key] !== undefined);
    // The reference cannot tell {} from [], so an empty object has no defined encoding.
    if (keys.length === 0) throw new VerifyumError(`${where}: empty object has no canonical form`);
    for (const key of keys) {
      if (!OBJECT_KEY_PATTERN.test(key)) throw new VerifyumError(`${where}: key ${JSON.stringify(key)} is not printable ASCII`);
      if (INTEGER_LIKE_KEY_PATTERN.test(key)) throw new VerifyumError(`${where}: key ${JSON.stringify(key)} looks like an integer, which the reference rejects`);
      assertCanonicalizable(value[key], `${where}.${key}`);
    }
    return;
  }
  throw new VerifyumError(`${where}: ${typeof value} cannot be canonicalized`);
}

/**
 * R2. Strict JCS as a string: canonicalize() with the reference's rejections
 * (floats, empty objects, non-ASCII keys) and its one deviation from RFC 8785.
 */
export function jcs(value) {
  assertCanonicalizable(value, "$");
  // JSON.stringify leaves U+2028/U+2029 raw while the PHP reference escapes
  // them. Keys are ASCII-only, so any raw occurrence came from a string value.
  return canonicalize(value).replaceAll("\u2028", "\\u2028").replaceAll("\u2029", "\\u2029");
}

/**
 * Parses a protocol document strictly. JSON.parse would silently fold `2.0`
 * and `1e2` into integers, but the reference throws on any number with a
 * fraction or exponent, so the number's source text is checked (Node 21+
 * exposes it to the reviver; older runtimes fall back to plain JSON.parse).
 */
export function parseDocument(text) {
  const source = typeof text === "string" ? text : Buffer.from(text).toString("utf8");
  return JSON.parse(source, (key, value, context) => {
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) throw new VerifyumError(`number at ${JSON.stringify(key)} is not an integer`);
      const literal = context?.source;
      if (typeof literal === "string" && !JSON_INTEGER_PATTERN.test(literal)) {
        throw new VerifyumError(`number at ${JSON.stringify(key)} is written as ${literal}, only plain integers are allowed`);
      }
    }
    return value;
  });
}

/** R3. Only `checkpoint_hash` is removed before hashing; there is no domain byte. */
export function checkpointHash(checkpoint) {
  const { checkpoint_hash: _omitted, ...rest } = checkpoint;
  return digest(`verifyum:witness:checkpoint:v1\n${jcs(rest)}`);
}

/** R4. The exact bytes published at the checkpoint URL: canonical JSON plus one newline. */
export function checkpointDocument(checkpoint) {
  return utf8(`${jcs(checkpoint)}\n`);
}

/** R4. What OpenTimestamps, GitHub, Wayback, RFC 3161, Software Heritage and Sigsum witness. */
export function checkpointDocumentDigest(checkpoint) {
  return digest(checkpointDocument(checkpoint));
}

/** R4. Sigsum leaf checksum as hex: the log hashes the 32 raw digest bytes once more. */
export function sigsumChecksum(checkpoint) {
  return sha256Raw(digestBytes(checkpointDocumentDigest(checkpoint))).toString("hex");
}

/** R5. Over the full metadata including service_signature. */
export function proofLeafHash(metadata) {
  return digest(`\x00verifyum:witness:proof-leaf:v1\n${jcs(metadata)}`);
}

/** R6. Over the raw bytes of an hourly checkpoint's hash, not its document. */
export function checkpointLeafHash(hourlyCheckpoint) {
  if (hourlyCheckpoint?.kind !== "hourly") throw new VerifyumError("checkpoint leaves are only defined for hourly checkpoints");
  return digest(Buffer.concat([utf8("\x00verifyum:witness:checkpoint-leaf:v1\n"), digestBytes(hourlyCheckpoint.checkpoint_hash)]));
}

/** R7. Interior nodes use prefix byte 0x01 so a leaf can never pose as a node. */
export function nodeHash(left, right) {
  return digest(Buffer.concat([utf8("\x01verifyum:witness:node:v1\n"), digestBytes(left), digestBytes(right)]));
}

/** R9. Folds the path and returns the root it reaches; throws on a malformed step. */
export function pathRoot(leafHash, path) {
  if (!isDigest(leafHash)) throw new VerifyumError("leaf hash is not a digest string");
  if (!Array.isArray(path) || path.length > MAX_PATH_LENGTH) throw new VerifyumError("path must be an array of at most 64 steps");
  let current = leafHash;
  path.forEach((step, index) => {
    // Extra or missing keys invalidate the step rather than being ignored.
    if (!isPlainObject(step) || Object.keys(step).length !== 2 || !("side" in step) || !("hash" in step)) {
      throw new VerifyumError(`path step ${index} must have exactly the keys side and hash`);
    }
    if (!isDigest(step.hash)) throw new VerifyumError(`path step ${index}: hash is not a digest string`);
    if (step.side === "left") current = nodeHash(step.hash, current);
    else if (step.side === "right") current = nodeHash(current, step.hash);
    else throw new VerifyumError(`path step ${index}: side must be left or right`);
  });
  return current;
}

/** R9. `side` names where the sibling sits. An empty path means root == leaf. */
export function verifyPath(leafHash, path, root) {
  if (!isDigest(root)) return false;
  try {
    return pathRoot(leafHash, path) === root;
  } catch {
    return false;
  }
}

/** 11.1. Node's decoder tolerates non-zero trailing bits; the round trip rejects them. */
export function decodeBase64UrlStrict(value) {
  if (typeof value !== "string" || !BASE64URL_PATTERN.test(value) || value.length % 4 === 1) return null;
  const decoded = Buffer.from(value, "base64url");
  return decoded.toString("base64url") === value ? decoded : null;
}

/** R10. Returns null when the signature verifies, otherwise the reason it does not. */
export function explainServiceSignature(metadata, registry) {
  const signature = metadata?.service_signature;
  if (!isPlainObject(signature)) return "metadata has no service_signature object";
  const keys = Object.keys(signature).sort();
  if (keys.join(",") !== "algorithm,key_id,value") return "service_signature must have exactly algorithm, key_id, value";
  if (signature.algorithm !== "ed25519") return `unsupported algorithm ${String(signature.algorithm)}`;
  if (typeof signature.key_id !== "string") return "service_signature.key_id is not a string";

  const network = metadata?.anchor?.network;
  const candidates = (Array.isArray(registry?.keys) ? registry.keys : []).filter(
    (entry) =>
      isPlainObject(entry) &&
      entry.key_id === signature.key_id &&
      entry.network === network &&
      (entry.status === "active" || entry.status === "retired") &&
      entry.algorithm === "ed25519" &&
      typeof entry.public_key === "string",
  );
  if (candidates.length === 0) return `no usable registry key ${signature.key_id} for network ${String(network)}`;
  if (candidates.length > 1) return `registry key ${signature.key_id} is not unique for network ${String(network)}`;

  const publicKey = decodeBase64UrlStrict(candidates[0].public_key);
  if (publicKey === null || publicKey.length !== 32) return "registry public key is not 32 bytes of strict base64url";
  const signatureBytes = decodeBase64UrlStrict(signature.value);
  if (signatureBytes === null || signatureBytes.length !== 64) return "signature value is not 64 bytes of strict base64url";

  let message;
  try {
    const { service_signature: _omitted, ...unsigned } = metadata;
    message = utf8(jcs(unsigned));
  } catch (error) {
    return `metadata cannot be canonicalized: ${error instanceof Error ? error.message : "unknown error"}`;
  }
  // node:crypto only takes key objects, so the raw key is wrapped in the fixed SPKI header.
  const keyObject = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]), format: "der", type: "spki" });
  return ed25519Verify(null, message, keyObject, signatureBytes) ? null : "Ed25519 signature does not verify";
}

/** R10 as a boolean; use explainServiceSignature() for the reason. */
export function verifyServiceSignature(metadata, registry) {
  return explainServiceSignature(metadata, registry) === null;
}

/* ---- Section 3 validation: reject malformed input before trusting a hash ---- */

function fail(message) {
  throw new VerifyumError(message);
}

function requireExactKeys(object, expected, label) {
  if (!isPlainObject(object)) fail(`${label} must be an object`);
  const actual = Object.keys(object).sort().join(",");
  if (actual !== [...expected].sort().join(",")) fail(`${label} must have exactly the keys ${expected.join(", ")}`);
}

function isCanonicalTime(value) {
  if (typeof value !== "string" || !CANONICAL_TIME_PATTERN.test(value)) return false;
  const parsed = new Date(value);
  // Re-formatting catches rolled-over dates such as February 30.
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value.replace("Z", ".000Z");
}

const unixSeconds = (value) => Math.floor(new Date(value).getTime() / 1000);

export function buildMemo(proofId, commitment) {
  return `verifyum:v2:id=${proofId};alg=sha256;commitment=${commitment.slice("sha256:".length)}`;
}

/** 3.2. Throws a VerifyumError naming the first violation. */
export function validateProofMetadata(metadata) {
  requireExactKeys(metadata, ["schema", "protocol", "version", "proof_id", "commitment", "submitted_at", "anchor", "service_signature"], "metadata");
  if (metadata.schema !== "https://verifyum.com/schema/proof-v2.json") fail("metadata.schema is not proof-v2");
  if (metadata.protocol !== "verifyum" || metadata.version !== 2) fail("metadata is not verifyum protocol version 2");
  if (typeof metadata.proof_id !== "string" || !PROOF_ID_PATTERN.test(metadata.proof_id)) fail("metadata.proof_id is not a proof id");
  if (!isDigest(metadata.commitment)) fail("metadata.commitment is not a digest string");
  if (!isCanonicalTime(metadata.submitted_at)) fail("metadata.submitted_at is not a canonical time");

  const anchor = metadata.anchor;
  requireExactKeys(anchor, ["provider", "network", "transaction_signature", "slot", "block_time", "anchor_address", "memo", "status"], "metadata.anchor");
  if (anchor.provider !== "solana") fail("anchor.provider is not solana");
  if (!NETWORKS.has(anchor.network)) fail("anchor.network is not a known network");
  if (typeof anchor.transaction_signature !== "string" || !TRANSACTION_SIGNATURE_PATTERN.test(anchor.transaction_signature)) fail("anchor.transaction_signature is not base58");
  if (!Number.isSafeInteger(anchor.slot) || anchor.slot < 0) fail("anchor.slot is not a non-negative integer");
  if (anchor.block_time !== null && !isCanonicalTime(anchor.block_time)) fail("anchor.block_time is not null or a canonical time");
  if (typeof anchor.anchor_address !== "string" || !ANCHOR_ADDRESS_PATTERN.test(anchor.anchor_address)) fail("anchor.anchor_address is not base58");
  if (anchor.memo !== buildMemo(metadata.proof_id, metadata.commitment)) fail("anchor.memo does not match proof_id and commitment");
  if (anchor.status !== "finalized") fail("anchor.status is not finalized");

  requireExactKeys(metadata.service_signature, ["algorithm", "key_id", "value"], "metadata.service_signature");
  if (metadata.service_signature.algorithm !== "ed25519") fail("service_signature.algorithm is not ed25519");
  if (typeof metadata.service_signature.key_id !== "string" || typeof metadata.service_signature.value !== "string") {
    fail("service_signature.key_id and value must be strings");
  }
  return metadata;
}

/** 3.3. Includes the R3 self-check on checkpoint_hash. */
export function validateCheckpoint(checkpoint) {
  requireExactKeys(checkpoint, [
    "algorithm", "checkpoint_hash", "created_at", "kind", "merkle_root", "network", "period_end", "period_start",
    "previous_checkpoint_hash", "protocol", "schema", "subject_count", "subject_type", "version",
  ], "checkpoint");
  if (checkpoint.schema !== "https://verifyum.com/schema/witness-checkpoint-v1.json") fail("checkpoint.schema is not witness-checkpoint-v1");
  if (checkpoint.protocol !== "verifyum" || checkpoint.version !== 1) fail("checkpoint is not verifyum protocol version 1");
  if (checkpoint.kind !== "hourly" && checkpoint.kind !== "daily") fail("checkpoint.kind is not hourly or daily");
  if (!NETWORKS.has(checkpoint.network)) fail("checkpoint.network is not a known network");
  for (const field of ["period_start", "period_end", "created_at"]) {
    if (!isCanonicalTime(checkpoint[field])) fail(`checkpoint.${field} is not a canonical time`);
  }
  if (checkpoint.algorithm !== "verifyum-sha256-merkle-v1") fail("checkpoint.algorithm is not verifyum-sha256-merkle-v1");
  const expectedSubjectType = checkpoint.kind === "hourly" ? "proof-v2" : "hourly-checkpoint-v1";
  if (checkpoint.subject_type !== expectedSubjectType) fail(`checkpoint.subject_type must be ${expectedSubjectType}`);
  if (!Number.isSafeInteger(checkpoint.subject_count) || checkpoint.subject_count < 1) fail("checkpoint.subject_count must be a positive integer");
  if (!isDigest(checkpoint.merkle_root)) fail("checkpoint.merkle_root is not a digest string");
  if (checkpoint.previous_checkpoint_hash !== null && !isDigest(checkpoint.previous_checkpoint_hash)) fail("checkpoint.previous_checkpoint_hash is not null or a digest string");
  if (!isDigest(checkpoint.checkpoint_hash)) fail("checkpoint.checkpoint_hash is not a digest string");

  const duration = checkpoint.kind === "hourly" ? 3600 : 86400;
  const start = unixSeconds(checkpoint.period_start);
  const end = unixSeconds(checkpoint.period_end);
  if (start % duration !== 0) fail("checkpoint.period_start is not aligned to the period");
  if (end - start !== duration) fail("checkpoint.period_end is not one period after period_start");
  if (unixSeconds(checkpoint.created_at) < end) fail("checkpoint.created_at precedes period_end");
  if (checkpointHash(checkpoint) !== checkpoint.checkpoint_hash) fail("checkpoint.checkpoint_hash does not match its recomputation");
  return checkpoint;
}

/** 3.4. Requires a checkpoint that already passed validateCheckpoint(). */
export function validateMembership(membership, checkpoint) {
  requireExactKeys(membership, [
    "schema", "protocol", "version", "checkpoint_kind", "checkpoint_hash", "subject_type", "subject_id",
    "leaf_hash", "leaf_index", "leaf_count", "path",
  ], "membership");
  if (membership.schema !== "https://verifyum.com/schema/witness-membership-v1.json") fail("membership.schema is not witness-membership-v1");
  if (membership.protocol !== "verifyum" || membership.version !== 1) fail("membership is not verifyum protocol version 1");
  if (membership.checkpoint_kind !== checkpoint.kind) fail("membership.checkpoint_kind differs from the checkpoint");
  if (membership.checkpoint_hash !== checkpoint.checkpoint_hash) fail("membership.checkpoint_hash differs from the checkpoint");
  if (membership.subject_type !== checkpoint.subject_type) fail("membership.subject_type differs from the checkpoint");
  const subjectOk = membership.subject_type === "proof-v2"
    ? typeof membership.subject_id === "string" && PROOF_ID_PATTERN.test(membership.subject_id)
    : isDigest(membership.subject_id);
  if (!subjectOk) fail("membership.subject_id does not fit the subject type");
  if (!isDigest(membership.leaf_hash)) fail("membership.leaf_hash is not a digest string");
  if (!Number.isSafeInteger(membership.leaf_count) || membership.leaf_count !== checkpoint.subject_count) fail("membership.leaf_count differs from checkpoint.subject_count");
  if (!Number.isSafeInteger(membership.leaf_index) || membership.leaf_index < 0 || membership.leaf_index >= membership.leaf_count) fail("membership.leaf_index is out of range");
  if (!verifyPath(membership.leaf_hash, membership.path, checkpoint.merkle_root)) fail("membership.path does not reach checkpoint.merkle_root");
  return membership;
}

/** The batch id embedded in a published checkpoint URL. */
export function checkpointBatchId(checkpoint) {
  return `${checkpoint.period_start.replaceAll("-", "").replaceAll(":", "")}-${checkpoint.checkpoint_hash.slice("sha256:".length)}`;
}

/** 3.5. The per-proof bundle served as verifyum-witnesses.json. */
export function validateWitnessBundle(bundle) {
  requireExactKeys(bundle, ["schema", "protocol", "version", "network", "proof_id", "checkpoint_url", "checkpoint", "membership"], "bundle");
  if (bundle.schema !== "https://verifyum.com/schema/witness-proof-membership-v1.json") fail("bundle.schema is not witness-proof-membership-v1");
  if (bundle.protocol !== "verifyum" || bundle.version !== 1) fail("bundle is not verifyum protocol version 1");
  validateCheckpoint(bundle.checkpoint);
  if (bundle.network !== bundle.checkpoint.network) fail("bundle.network differs from the checkpoint");
  if (bundle.checkpoint.subject_type !== "proof-v2") fail("bundle.checkpoint is not an hourly proof checkpoint");
  validateMembership(bundle.membership, bundle.checkpoint);
  if (bundle.membership.subject_type !== "proof-v2") fail("bundle.membership is not a proof membership");
  if (bundle.proof_id !== bundle.membership.subject_id) fail("bundle.proof_id differs from membership.subject_id");
  const expectedUrl = `${CHECKPOINT_URL_PREFIX}${bundle.checkpoint.kind}/${checkpointBatchId(bundle.checkpoint)}.json`;
  if (bundle.checkpoint_url !== expectedUrl) fail("bundle.checkpoint_url does not name this checkpoint");
  return bundle;
}

/**
 * The additive proof -> hourly -> daily bridge. The version 1 proof bundle
 * remains untouched and is embedded byte-for-byte, so old clients keep
 * working while new clients can reach the daily witness channels.
 */
export function validateWitnessChain(chain, expectedBundle = null) {
  requireExactKeys(chain, [
    "schema", "protocol", "version", "network", "proof_id", "proof_membership",
    "hourly_receipts_url", "daily_checkpoint_url", "daily_receipts_url",
    "daily_checkpoint", "daily_membership",
  ], "witness chain");
  if (chain.schema !== "https://verifyum.com/schema/witness-proof-chain-v1.json") fail("witness chain schema is not witness-proof-chain-v1");
  if (chain.protocol !== "verifyum" || chain.version !== 1) fail("witness chain is not verifyum version 1");
  validateWitnessBundle(chain.proof_membership);
  validateCheckpoint(chain.daily_checkpoint);
  validateMembership(chain.daily_membership, chain.daily_checkpoint);

  const hourly = chain.proof_membership.checkpoint;
  const daily = chain.daily_checkpoint;
  if (daily.kind !== "daily" || daily.subject_type !== "hourly-checkpoint-v1") fail("witness chain daily checkpoint has the wrong kind");
  if (chain.network !== chain.proof_membership.network || chain.network !== daily.network) fail("witness chain mixes networks");
  if (chain.proof_id !== chain.proof_membership.proof_id) fail("witness chain proof_id differs from its proof membership");
  if (chain.daily_membership.subject_id !== hourly.checkpoint_hash) fail("daily membership does not name the hourly checkpoint hash");
  if (chain.daily_membership.leaf_hash !== checkpointLeafHash(hourly)) fail("daily membership leaf is not derived from the hourly checkpoint hash");

  const hourlyBatch = checkpointBatchId(hourly);
  const dailyBatch = checkpointBatchId(daily);
  if (chain.hourly_receipts_url !== `${RECEIPTS_URL_PREFIX}hourly/${hourlyBatch}.json`) fail("hourly receipts URL is not canonical");
  if (chain.daily_checkpoint_url !== `${CHECKPOINT_URL_PREFIX}daily/${dailyBatch}.json`) fail("daily checkpoint URL is not canonical");
  if (chain.daily_receipts_url !== `${RECEIPTS_URL_PREFIX}daily/${dailyBatch}.json`) fail("daily receipts URL is not canonical");
  if (unixSeconds(hourly.period_start) < unixSeconds(daily.period_start) || unixSeconds(hourly.period_end) > unixSeconds(daily.period_end)) {
    fail("hourly checkpoint is outside the daily checkpoint period");
  }
  if (expectedBundle !== null && jcs(chain.proof_membership) !== jcs(expectedBundle)) fail("witness chain does not embed the published proof membership exactly");
  return chain;
}

/* ---- Whole-proof verification ---- */

function attempt(checks, name, run) {
  try {
    run();
    checks[name] = true;
  } catch (error) {
    checks[name] = false;
    checks.problems.push(`${name}: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}

/**
 * Pure verification of already-fetched documents. `publishedCheckpoint` is the
 * optional raw body of `bundle.checkpoint_url`; when given it must equal the
 * canonical document byte for byte.
 */
export function verifyWitnessDocuments({ proofId, metadata, bundle, chain = null, registry = null, publishedCheckpoint = null }) {
  const checks = { problems: [] };
  attempt(checks, "metadata_valid", () => {
    validateProofMetadata(metadata);
    if (metadata.proof_id !== proofId) fail("metadata.proof_id is not the requested proof");
  });
  attempt(checks, "service_signature_valid", () => {
    if (registry === null) fail("no key registry supplied");
    const problem = explainServiceSignature(metadata, registry);
    if (problem !== null) fail(problem);
  });
  attempt(checks, "bundle_valid", () => {
    validateWitnessBundle(bundle);
    if (bundle.proof_id !== proofId) fail("bundle.proof_id is not the requested proof");
  });
  attempt(checks, "leaf_hash_matches", () => {
    if (proofLeafHash(metadata) !== bundle?.membership?.leaf_hash) fail("R5 over the metadata differs from membership.leaf_hash");
  });
  attempt(checks, "path_matches_checkpoint", () => {
    if (!verifyPath(bundle?.membership?.leaf_hash, bundle?.membership?.path, bundle?.checkpoint?.merkle_root)) fail("path does not reach merkle_root");
  });
  if (publishedCheckpoint !== null) {
    attempt(checks, "published_checkpoint_matches", () => {
      if (!Buffer.from(publishedCheckpoint).equals(checkpointDocument(bundle.checkpoint))) fail("published bytes differ from the canonical document");
    });
  }
  if (chain !== null) {
    attempt(checks, "daily_chain_valid", () => validateWitnessChain(chain, bundle));
  }

  const { problems, ...results } = checks;
  return {
    proof_id: proofId,
    witnessed: true,
    valid: Object.values(results).every(Boolean),
    checks: results,
    problems,
    checkpoint_hash: bundle?.checkpoint?.checkpoint_hash ?? null,
    merkle_root: bundle?.checkpoint?.merkle_root ?? null,
    checkpoint_url: bundle?.checkpoint_url ?? null,
    leaf_index: bundle?.membership?.leaf_index ?? null,
    leaf_count: bundle?.membership?.leaf_count ?? null,
    daily_witnessed: chain !== null,
    daily_checkpoint_hash: chain?.daily_checkpoint?.checkpoint_hash ?? null,
    hourly_receipts_url: chain?.hourly_receipts_url ?? null,
    daily_receipts_url: chain?.daily_receipts_url ?? null,
    boundary: WITNESS_BOUNDARY_STATEMENT,
  };
}

async function fetchBytes(url) {
  const response = await fetch(url, { headers: { "User-Agent": USER_AGENT, Accept: "application/json" }, redirect: "error" });
  if (!response.ok) throw new VerifyumError(`HTTP ${response.status} for ${url}`, { status: response.status });
  return Buffer.from(await response.arrayBuffer());
}

/**
 * Fetches a proof's public metadata, witness bundle, the published checkpoint
 * file and the key registry, then verifies them offline. A proof whose hourly
 * checkpoint has not been published yet returns `witnessed: false`; that is
 * not a failure, the proof is simply younger than the next checkpoint.
 */
export async function verifyWitness(proofId, { registryUrl = REGISTRY_URL } = {}) {
  if (typeof proofId !== "string" || !PROOF_ID_PATTERN.test(proofId)) {
    throw new VerifyumError("proofId must be a canonical 26-character Verifyum proof id");
  }
  const base = `https://${proofId}.${PROOF_DOMAIN}`;
  // Documents are parsed strictly (parseDocument) rather than through request(), which uses plain JSON.parse.
  const metadata = parseDocument(await fetchBytes(`${base}/.well-known/verifyum.json`));
  let bundle;
  try {
    bundle = parseDocument(await fetchBytes(`${base}/.well-known/verifyum-witnesses.json`));
  } catch (error) {
    if (error instanceof VerifyumError && error.status === 404) {
      return { proof_id: proofId, witnessed: false, valid: false, checks: {}, problems: [], boundary: WITNESS_BOUNDARY_STATEMENT };
    }
    throw error;
  }
  const registry = parseDocument(await fetchBytes(registryUrl));
  let chain = null;
  try {
    chain = parseDocument(await fetchBytes(`${base}/.well-known/verifyum-witness-chain.json`));
  } catch (error) {
    if (!(error instanceof VerifyumError && error.status === 404)) throw error;
  }
  // Only follow a checkpoint URL on our own host; the bundle is data, not a place to send requests.
  const publishedCheckpoint = typeof bundle.checkpoint_url === "string" && bundle.checkpoint_url.startsWith(CHECKPOINT_URL_PREFIX)
    ? await fetchBytes(bundle.checkpoint_url)
    : null;
  return verifyWitnessDocuments({ proofId, metadata, bundle, chain, registry, publishedCheckpoint });
}

// ---------------------------------------------------------------------------
// Self-bearing receipts
//
// A receipt used to hold the nonce and a proof id and nothing else, so the
// holder depended on our uptime for the life of the claim. It now carries the
// signed metadata, the witness bundle with its Merkle path, and the key
// registry: about three kilobytes, after which no request to us is needed.
//
// The bundle is read from the same .well-known document the Python client
// takes from the API; the two were compared byte for byte, so a receipt
// written by either client checks with the other.
// ---------------------------------------------------------------------------

export const RECEIPT_VERSION = 4;

const SOLANA_RPC = globalThis.process?.env?.VERIFYUM_SOLANA_RPC ?? "https://api.mainnet-beta.solana.com";

const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/** Everything a receipt needs to be checkable without us. */
export async function fetchEvidence(proofId) {
  const base = `https://${proofId}.${PROOF_DOMAIN}`;
  const evidence = {};
  const collect = async (name, url) => {
    try { evidence[name] = parseDocument(await fetchBytes(url)); }
    catch { /* absent for now; upgrade fills it in */ }
  };
  await collect("metadata", `${base}/.well-known/verifyum.json`);
  await collect("witness_bundle", `${base}/.well-known/verifyum-witnesses.json`);
  await collect("witness_chain", `${base}/.well-known/verifyum-witness-chain.json`);
  await collect("service_keys", REGISTRY_URL);
  return evidence;
}

/** True when the receipt can be checked with no network at all. */
export function receiptIsComplete(receipt) {
  return ["metadata", "witness_bundle", "service_keys"].every(
    (part) => receipt?.[part] !== null && typeof receipt?.[part] === "object"
  );
}

/** True once the optional daily bridge has also been captured. */
export function receiptHasDailyChain(receipt) {
  return receipt?.witness_chain !== null && typeof receipt?.witness_chain === "object";
}

function receiptVersion(receipt) {
  return receiptHasDailyChain(receipt) ? RECEIPT_VERSION : 3;
}

/** The exact memo the anchor carries, rebuilt rather than trusted. */
export function receiptMemo(metadata) {
  return buildMemo(metadata.proof_id, metadata.commitment);
}

/**
 * Checks a file against a complete receipt without contacting anyone.
 *
 * Covers the local binding, the signed metadata, the Merkle path into the
 * checkpoint and the service signature. It cannot cover the ledger; for that
 * see verifyIndependent.
 */
export async function verifyOffline(data, receipt) {
  if (!receiptIsComplete(receipt)) {
    throw new VerifyumError("receipt does not carry its evidence yet; run `verifyum upgrade` while online");
  }
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const draft = receipt.private_draft;
  const manifest = draft.manifest;
  const metadata = receipt.metadata;

  const canonical = new TextEncoder().encode(canonicalize(manifest));
  const input = new Uint8Array(PREFIX.length + canonical.length);
  input.set(PREFIX, 0);
  input.set(canonical, PREFIX.length);

  const checks = {
    hash_matches: createHash("sha256").update(bytes).digest("hex") === manifest.file.hash.value,
    size_matches: String(bytes.length) === manifest.file.size,
    commitment_matches: "sha256:" + createHash("sha256").update(input).digest("hex") === draft.commitment,
    metadata_commitment_matches: metadata.commitment === draft.commitment,
    anchor_finalized: metadata.anchor?.status === "finalized",
  };

  const witness = verifyWitnessDocuments({
    proofId: metadata.proof_id,
    metadata,
    bundle: receipt.witness_bundle,
    chain: receipt.witness_chain ?? null,
    registry: receipt.service_keys,
  });
  Object.assign(checks, witness.checks);
  delete checks.subject_id;
  checks.memo_matches = metadata.anchor?.memo === receiptMemo(metadata);

  return {
    valid: Object.values(checks).every((value) => value === true),
    checks,
    transaction_signature: metadata.anchor?.transaction_signature ?? null,
    network: metadata.anchor?.network ?? null,
    offline: true,
  };
}

/**
 * Reads the anchor from a public Solana RPC and compares the memo itself.
 *
 * Nothing here touches verifyum.com: the ledger answers, not the operator.
 */
export async function verifyIndependent(receipt, { rpcUrl = SOLANA_RPC } = {}) {
  const metadata = receipt?.metadata;
  if (!metadata || typeof metadata !== "object") {
    throw new VerifyumError("receipt does not carry its metadata; run `verifyum upgrade` while online");
  }
  const signature = metadata.anchor?.transaction_signature;
  if (typeof signature !== "string") {
    throw new VerifyumError("receipt carries no transaction signature");
  }

  let answer;
  try {
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": USER_AGENT },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "getTransaction",
        params: [signature, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 }],
      }),
    });
    answer = await response.json();
  } catch (error) {
    throw new VerifyumError(`could not reach the Solana RPC: ${error.message}`);
  }
  if (answer?.error) {
    throw new VerifyumError("Solana RPC refused: " + String(answer.error.message));
  }

  const result = answer?.result;
  const checks = { transaction_found: result !== null && typeof result === "object" };
  let observed = null;
  if (checks.transaction_found) {
    checks.transaction_succeeded = (result.meta?.err ?? null) === null;
    for (const instruction of result.transaction?.message?.instructions ?? []) {
      if (instruction?.program === "spl-memo" || instruction?.programId === MEMO_PROGRAM) {
        if (typeof instruction.parsed === "string") { observed = instruction.parsed; break; }
      }
    }
    checks.memo_present = typeof observed === "string";
    checks.memo_matches_receipt = observed === receiptMemo(metadata);
    const address = metadata.anchor?.anchor_address;
    checks.anchor_address_matches = typeof address !== "string" || (
      result.transaction?.message?.accountKeys ?? []
    ).some((account) => account?.signer && account.pubkey === address);
  }
  return {
    valid: Object.values(checks).every((value) => value === true),
    checks,
    transaction_signature: signature,
    memo: observed,
    block_time: result?.blockTime ?? null,
    source: rpcUrl,
  };
}


// ---------------------------------------------------------------------------
// Command line
//
// The receipt sits beside the file as <file>.verifyum.json, the way an .ots
// file does, so verify needs nothing but the original path. It holds the
// nonce, the only thing tying the file to its public proof, and which
// Verifyum never has. A lost receipt cannot be recovered from us or anyone.
//
// The mode is set to 0600, which POSIX honours and Windows does not: there a
// receipt lands 0666 and inherits the directory's ACL. The tool therefore
// does not promise the file is private. It says what the file is and leaves
// the placing of it to someone who knows where their own secrets belong.
//
// Reading and writing happen through node:fs, imported here rather than at
// the top, so a browser or a bundler that only wants the library never has
// to resolve it.
// ---------------------------------------------------------------------------

export const RECEIPT_SUFFIX = ".verifyum.json";

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_USAGE = 2;
const EXIT_UNAVAILABLE = 3;

export function receiptPath(path) {
  return path + RECEIPT_SUFFIX;
}

async function writeReceipt(fs, path, proof, evidence) {
  const target = receiptPath(path);
  const document = {
    schema: "https://verifyum.com/schema/receipt-v1.json",
    protocol: "verifyum",
    version: receiptVersion(evidence ?? {}),
    proof_id: proof.proof_id ?? null,
    commitment: proof.commitment ?? null,
    status: proof.status ?? null,
    proof_url: proof.proof_url ?? null,
    private_draft: proof.private_draft ?? null,
    ...(evidence ?? {}),
  };
  const temporary = target + ".tmp";
  await fs.writeFile(temporary, JSON.stringify(document, Object.keys(document).sort(), 2) + "\n", { mode: 0o600 });
  await fs.rename(temporary, target);
  return target;
}

async function readReceipt(fs, path) {
  return JSON.parse(await fs.readFile(receiptPath(path), "utf8"));
}

function emit(payload, asJson, lines) {
  if (asJson) {
    process.stdout.write(JSON.stringify(payload) + "\n");
    return;
  }
  for (const line of lines) { process.stdout.write(line + "\n"); }
}

function usage() {
  process.stdout.write([
    "usage: verifyum <command> [options] <files...>",
    "",
    "  stamp    anchor one or more files and write their receipts",
    "  verify   check files against their receipts and the public record",
    "  upgrade  fetch the evidence a receipt needs to stand alone",
    "  witness  check a proof against the witness layer",
    "",
    "options:",
    "  --json         machine readable output",
    "  --offline      check using the receipt alone, contacting no one (verify)",
    "  --independent  also read the anchor from a public Solana RPC (verify)",
    "  --force        replace an existing receipt (stamp, upgrade)",
    "  --no-wait      return as soon as the anchor is queued (stamp)",
    "",
    "The receipt beside each file holds the nonce. Verifyum never has it, so a",
    "lost receipt cannot be recovered from us or from anyone. Treat it like a",
    "key: it is not made private by being written.",
    "",
  ].join("\n"));
}

export async function main(argv) {
  const fs = await import("node:fs/promises");
  const args = argv.slice();
  const command = args.shift();
  const flags = new Set(args.filter((a) => a.startsWith("--")));
  const targets = args.filter((a) => !a.startsWith("--"));
  const asJson = flags.has("--json");

  if (!command || command === "--help" || command === "-h") { usage(); return EXIT_USAGE; }
  if (command === "--version") { process.stdout.write(USER_AGENT.split("/").pop() + "\n"); return EXIT_OK; }
  if (!["stamp", "verify", "upgrade", "witness"].includes(command)) {
    process.stderr.write("verifyum: unknown command " + command + "\n");
    return EXIT_USAGE;
  }
  if (!targets.length) { usage(); return EXIT_USAGE; }

  let worst = EXIT_OK;
  const fail = (code, message) => {
    process.stderr.write("verifyum: " + message + "\n");
    worst = Math.max(worst, code);
  };

  for (const target of targets) {
    if (command === "stamp") {
      try {
        if (!flags.has("--force")) {
          try { await fs.access(receiptPath(target)); fail(EXIT_USAGE, "receipt already exists, use --force to replace: " + receiptPath(target)); continue; } catch { /* absent, good */ }
        }
        const proof = await anchorFile(target, { wait: !flags.has("--no-wait") });
        const evidence = proof.proof_id ? await fetchEvidence(proof.proof_id) : {};
        const written = await writeReceipt(fs, target, proof, evidence);
        emit(
          { file: target, receipt: written, proof_id: proof.proof_id, status: proof.status, proof_url: proof.proof_url },
          asJson,
          [
            "stamped  " + target,
            "  proof   " + proof.proof_id,
            "  status  " + proof.status,
            "  url     " + proof.proof_url,
            "  receipt " + written,
            "          this holds the nonce. We do not have it and cannot",
            "          replace it. Keep it, and do not commit or sync it",
            "          anywhere you would not put a key.",
          ]
        );
      } catch (error) {
        fail(error instanceof VerifyumError ? EXIT_UNAVAILABLE : EXIT_USAGE, error.message);
      }
      continue;
    }

    if (command === "verify") {
      try {
        const receipt = await readReceipt(fs, target);
        const data = await fs.readFile(target);
        const result = flags.has("--offline")
          ? await verifyOffline(data, receipt)
          : await verify(receipt.proof_id, data, receipt.private_draft);
        if (flags.has("--independent")) {
          const chain = await verifyIndependent(receipt);
          for (const [name, value] of Object.entries(chain.checks)) {
            result.checks["chain_" + name] = value;
          }
          result.valid = result.valid && chain.valid;
          result.chain_source = chain.source;
        }
        if (!result.valid) { worst = Math.max(worst, EXIT_FAILED); }
        const failed = Object.entries(result.checks).filter(([, ok]) => !ok).map(([name]) => name);
        emit(
          { file: target, valid: result.valid, checks: result.checks, transaction_signature: result.transaction_signature ?? null },
          asJson,
          [
            (result.valid ? "verified " : "FAILED   ") + target,
            "  proof   " + receipt.proof_id,
            "  chain   " + (result.transaction_signature ?? "-"),
          ].concat(failed.length ? ["  failed  " + failed.join(", ")] : [])
        );
      } catch (error) {
        fail(error instanceof VerifyumError ? EXIT_UNAVAILABLE : EXIT_USAGE, error.message);
      }
      continue;
    }

    if (command === "upgrade") {
      try {
        const receipt = await readReceipt(fs, target);
        if (receiptIsComplete(receipt) && receiptHasDailyChain(receipt) && !flags.has("--force")) {
          emit({ file: target, upgraded: false, self_bearing: true, daily_chain: true }, asJson, ["already complete  " + target]);
          continue;
        }
        const merged = { ...receipt, ...(await fetchEvidence(receipt.proof_id)) };
        merged.version = receiptVersion(merged);
        const temporary = receiptPath(target) + ".tmp";
        await fs.writeFile(temporary, JSON.stringify(merged, null, 2) + "\n", { mode: 0o600 });
        await fs.rename(temporary, receiptPath(target));
        const complete = receiptIsComplete(merged);
        if (!complete) { worst = Math.max(worst, EXIT_UNAVAILABLE); }
        emit({ file: target, upgraded: true, self_bearing: complete, daily_chain: receiptHasDailyChain(merged) }, asJson,
          [(complete ? "upgraded " : "still incomplete ") + target,
           complete && receiptHasDailyChain(merged) ? "  this receipt now links offline through the daily checkpoint"
                    : complete ? "  hourly evidence complete; daily checkpoint is not published yet"
                    : "  the witness bundle is not published yet; try again after the hour"]);
      } catch (error) {
        fail(error instanceof VerifyumError ? EXIT_UNAVAILABLE : EXIT_USAGE, error.message);
      }
      continue;
    }

    try {
      let proofId = target;
      try {
        await fs.access(receiptPath(target));
        proofId = (await readReceipt(fs, target)).proof_id;
      } catch { /* not a stamped file, treat the argument as a proof id */ }
      const result = await verifyWitness(proofId);
      if (!result.valid) { worst = Math.max(worst, EXIT_FAILED); }
      emit(
        { proof_id: proofId, ...result },
        asJson,
        [ (result.valid ? "witnessed " : "FAILED    ") + proofId ]
      );
    } catch (error) {
      fail(error instanceof VerifyumError ? EXIT_UNAVAILABLE : EXIT_USAGE, error.message);
    }
  }
  return worst;
}

// Run only when invoked directly, so importing the library starts nothing.
if (globalThis.process?.argv?.[1]) {
  const { pathToFileURL } = await import("node:url");
  if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    process.exitCode = await main(process.argv.slice(2));
  }
}
