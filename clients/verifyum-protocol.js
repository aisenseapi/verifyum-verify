const CROCKFORD_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
const COMMITMENT_PREFIX = new TextEncoder().encode("verifyum:commitment:v2\n");
const PROOF_ID_PATTERN = /^[0-7][0-9a-hjkmnp-tv-z]{25}$/;
const COMMITMENT_PATTERN = /^sha256:[0-9a-f]{64}$/;
const HEX_256_PATTERN = /^[0-9a-f]{64}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function assertUnicodeScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError("JCS input contains an unpaired high surrogate");
      }
      index += 1;
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError("JCS input contains an unpaired low surrogate");
    }
  }
}

export function canonicalize(value) {
  if (value === null) {
    return "null";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError("JCS numbers must be finite and cannot be negative zero");
    }
    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    assertUnicodeScalarString(value);
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }

  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const fields = keys.map((key) => {
      assertUnicodeScalarString(key);
      const fieldValue = value[key];
      if (fieldValue === undefined || typeof fieldValue === "function" || typeof fieldValue === "symbol") {
        throw new TypeError(`JCS cannot serialize property ${key}`);
      }
      return `${JSON.stringify(key)}:${canonicalize(fieldValue)}`;
    });
    return `{${fields.join(",")}}`;
  }

  throw new TypeError(`JCS cannot serialize ${typeof value}`);
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function bytesToProofId(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
    throw new TypeError("A proof ID requires exactly 16 bytes");
  }

  let buffer = 0;
  let bitCount = 2;
  let output = "";

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      output += CROCKFORD_ALPHABET[(buffer >>> bitCount) & 31];
      buffer &= bitCount === 0 ? 0 : (1 << bitCount) - 1;
    }
  }

  if (bitCount !== 0 || output.length !== 26 || !PROOF_ID_PATTERN.test(output)) {
    throw new Error("Proof ID encoding failed");
  }

  return output;
}

export function generateProofId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToProofId(bytes);
}

export function generateNonce() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

export function createManifest({ fileHash, fileSize, nonce }) {
  if (!HEX_256_PATTERN.test(fileHash)) {
    throw new TypeError("fileHash must be a lowercase SHA-256 value");
  }

  const size = typeof fileSize === "bigint" ? fileSize.toString() : String(fileSize);
  if (!/^(0|[1-9][0-9]*)$/.test(size)) {
    throw new TypeError("fileSize must be a non-negative decimal integer");
  }

  if (!NONCE_PATTERN.test(nonce)) {
    throw new TypeError("nonce must encode exactly 32 bytes as unpadded base64url");
  }

  return {
    file: {
      hash: {
        algorithm: "sha256",
        value: fileHash,
      },
      size,
    },
    nonce,
    protocol: "verifyum",
    version: 2,
  };
}

export async function sha256(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", view));
}

export async function hashFile(file) {
  return bytesToHex(await sha256(await file.arrayBuffer()));
}

export async function computeCommitment(manifest) {
  const canonical = new TextEncoder().encode(canonicalize(manifest));
  const input = new Uint8Array(COMMITMENT_PREFIX.length + canonical.length);
  input.set(COMMITMENT_PREFIX, 0);
  input.set(canonical, COMMITMENT_PREFIX.length);
  return `sha256:${bytesToHex(await sha256(input))}`;
}

export function buildMemo(proofId, commitment) {
  if (!PROOF_ID_PATTERN.test(proofId)) {
    throw new TypeError("Invalid proof ID");
  }
  if (!COMMITMENT_PATTERN.test(commitment)) {
    throw new TypeError("Invalid commitment");
  }
  return `verifyum:v2:id=${proofId};alg=sha256;commitment=${commitment.slice(7)}`;
}

export function isValidProofId(value) {
  return PROOF_ID_PATTERN.test(value);
}

export function isValidCommitment(value) {
  return COMMITMENT_PATTERN.test(value);
}
