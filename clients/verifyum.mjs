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

const API_BASE = globalThis.process?.env?.VERIFYUM_API_BASE ?? "https://api.verifyum.com";
const USER_AGENT = "verifyum-js/1.0";
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
  const metadata = await request("GET", `https://${proofId}.verifyum.com/.well-known/verifyum.json`);
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
