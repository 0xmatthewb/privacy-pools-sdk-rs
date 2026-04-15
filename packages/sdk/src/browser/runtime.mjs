const PROVER_UNAVAILABLE_MESSAGE =
  "Browser proving support is still blocked on a wasm-capable Rust prover backend.";

const BROWSER_CAPABILITIES = Object.freeze({
  runtime: "browser",
  provingAvailable: false,
  verificationAvailable: true,
  workerAvailable: true,
  reason:
    "Browser verification is available via Rust/WASM; proving is still blocked on a wasm-capable Rust prover backend.",
});

const STABLE_BACKEND_NAME = "Arkworks";

let wasmModulePromise = null;

export class BrowserRuntimeUnavailableError extends Error {
  constructor(message = PROVER_UNAVAILABLE_MESSAGE) {
    super(message);
    this.name = "BrowserRuntimeUnavailableError";
  }
}

export function getRuntimeCapabilities() {
  return { ...BROWSER_CAPABILITIES };
}

export async function getVersion() {
  const wasm = await getWasmModule();
  return wasm.getVersion();
}

export async function getStableBackendName() {
  const wasm = await getWasmModule();
  return wasm.getStableBackendName?.() ?? STABLE_BACKEND_NAME;
}

export async function fastBackendSupportedOnTarget() {
  const wasm = await getWasmModule();
  return wasm.fastBackendSupportedOnTarget?.() ?? false;
}

export async function deriveMasterKeys(mnemonic) {
  return invokeJson("deriveMasterKeysJson", mnemonic);
}

export async function deriveDepositSecrets(masterKeys, scope, index) {
  return invokeJson(
    "deriveDepositSecretsJson",
    JSON.stringify(masterKeys),
    scope,
    index,
  );
}

export async function deriveWithdrawalSecrets(masterKeys, label, index) {
  return invokeJson(
    "deriveWithdrawalSecretsJson",
    JSON.stringify(masterKeys),
    label,
    index,
  );
}

export async function getCommitment(value, label, nullifier, secret) {
  return invokeJson("getCommitmentJson", value, label, nullifier, secret);
}

export async function calculateWithdrawalContext(withdrawal, scope) {
  const wasm = await getWasmModule();
  return wasm.calculateWithdrawalContextJson(JSON.stringify(withdrawal), scope);
}

export async function generateMerkleProof(leaves, leaf) {
  return invokeJson("generateMerkleProofJson", JSON.stringify(leaves), leaf);
}

export async function buildCircuitMerkleWitness(proof, depth) {
  return invokeJson(
    "buildCircuitMerkleWitnessJson",
    JSON.stringify(proof),
    depth,
  );
}

export async function buildWithdrawalCircuitInput(request) {
  return invokeJson(
    "buildWithdrawalCircuitInputJson",
    JSON.stringify(request),
  );
}

export async function verifyArtifactBytes(manifestJson, circuit, artifacts) {
  const wasm = await getWasmModule();
  const normalizedArtifacts = normalizeArtifactInputs(artifacts);
  return JSON.parse(
    wasm.verifyArtifactBytes(manifestJson, circuit, normalizedArtifacts),
  );
}

export async function getArtifactStatuses(manifestJson, artifactsRoot) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, "withdraw");
  const verifiedKinds = new Set();

  if (fetchedArtifacts.every((artifact) => artifact.exists)) {
    try {
      const verifiedBundle = await verifyArtifactBytes(
        manifestJson,
        "withdraw",
        fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
      );
      for (const artifact of verifiedBundle.artifacts) {
        verifiedKinds.add(artifact.kind);
      }
    } catch {
      // Fail closed: fetched artifacts remain unverified unless the full bundle verifies.
    }
  }

  return fetchedArtifacts.map((artifact) => ({
    version: manifest.version,
    circuit: artifact.circuit,
    kind: artifact.kind,
    filename: artifact.filename,
    path: artifact.path,
    exists: artifact.exists,
    verified: artifact.exists && verifiedKinds.has(artifact.kind),
  }));
}

export async function resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, "withdraw");
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const bundle = await verifyArtifactBytes(
    manifestJson,
    "withdraw",
    fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
  );
  const urlsByKind = new Map(
    fetchedArtifacts.map((artifact) => [artifact.kind, artifact.path]),
  );

  return {
    version: bundle.version,
    circuit: bundle.circuit,
    artifacts: bundle.artifacts.map((artifact) => ({
      circuit: artifact.circuit,
      kind: artifact.kind,
      filename: artifact.filename,
      path: urlsByKind.get(artifact.kind) ?? "",
    })),
  };
}

export async function prepareWithdrawalCircuitSession(manifestJson, artifactsRoot) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, "withdraw");
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const wasm = await getWasmModule();
  return JSON.parse(
    wasm.prepareWithdrawalCircuitSessionFromBytes(
      manifestJson,
      normalizeArtifactInputs(
        fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
      ),
    ),
  );
}

export async function prepareWithdrawalCircuitSessionFromBytes(
  manifestJson,
  artifacts,
) {
  const wasm = await getWasmModule();
  return JSON.parse(
    wasm.prepareWithdrawalCircuitSessionFromBytes(
      manifestJson,
      normalizeArtifactInputs(artifacts),
    ),
  );
}

export async function removeWithdrawalCircuitSession(sessionHandle) {
  const wasm = await getWasmModule();
  return wasm.removeWithdrawalCircuitSession(sessionHandle);
}

export async function proveWithdrawal(
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
) {
  void backendProfile;
  void manifestJson;
  void artifactsRoot;
  void request;
  throw new BrowserRuntimeUnavailableError();
}

export async function proveWithdrawalWithSession(
  backendProfile,
  sessionHandle,
  request,
) {
  void backendProfile;
  void sessionHandle;
  void request;
  throw new BrowserRuntimeUnavailableError();
}

export async function verifyWithdrawalProof(
  backendProfile,
  manifestJson,
  artifactsRoot,
  proof,
) {
  assertStableBackend(backendProfile);
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, "withdraw");
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const wasm = await getWasmModule();
  return wasm.verifyWithdrawalProof(
    manifestJson,
    normalizeArtifactInputs(
      fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
    ),
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function verifyWithdrawalProofWithSession(
  backendProfile,
  sessionHandle,
  proof,
) {
  assertStableBackend(backendProfile);
  const wasm = await getWasmModule();
  return wasm.verifyWithdrawalProofWithSession(
    sessionHandle,
    JSON.stringify(encodeProofBundle(proof)),
  );
}

async function getWasmModule() {
  if (!wasmModulePromise) {
    wasmModulePromise = initializeWasmModule().catch((error) => {
      wasmModulePromise = null;
      throw error;
    });
  }

  return wasmModulePromise;
}

async function initializeWasmModule() {
  const wasmModule = await import("./generated/privacy_pools_sdk_web.js");
  const init = wasmModule.default;
  const wasmUrl = new URL("./generated/privacy_pools_sdk_web_bg.wasm", import.meta.url);

  if (typeof process !== "undefined" && process.versions?.node && typeof document === "undefined") {
    const { readFile } = await import("node:fs/promises");
    const wasmBytes = await readFile(wasmUrl);
    await init({ module_or_path: wasmBytes });
  } else {
    await init({ module_or_path: wasmUrl });
  }

  return wasmModule;
}

async function invokeJson(methodName, ...args) {
  const wasm = await getWasmModule();
  return JSON.parse(wasm[methodName](...args));
}

function parseManifest(manifestJson) {
  const manifest = JSON.parse(manifestJson);
  if (!manifest || typeof manifest !== "object" || !Array.isArray(manifest.artifacts)) {
    throw new TypeError("manifestJson must describe an artifact manifest");
  }
  return manifest;
}

function assertStableBackend(backendProfile) {
  if (backendProfile === "stable") {
    return;
  }

  throw new BrowserRuntimeUnavailableError(
    "Browser verification currently supports only the stable backend.",
  );
}

async function fetchArtifactInputs(manifest, artifactsRoot, circuit) {
  const descriptors = manifest.artifacts.filter((artifact) => artifact.circuit === circuit);
  if (descriptors.length === 0) {
    throw new Error(`manifest does not declare artifacts for circuit ${circuit}`);
  }

  const baseUrl = resolveArtifactsRoot(artifactsRoot);
  return Promise.all(
    descriptors.map(async (descriptor) => {
      const url = new URL(descriptor.filename, baseUrl).toString();
      try {
        const response = await fetch(url);
        if (!response.ok) {
          return descriptorStatus(descriptor, url, null);
        }

        const bytes = new Uint8Array(await response.arrayBuffer());
        return descriptorStatus(descriptor, url, bytes);
      } catch {
        return descriptorStatus(descriptor, url, null);
      }
    }),
  );
}

function descriptorStatus(descriptor, path, bytes) {
  return {
    circuit: descriptor.circuit,
    kind: descriptor.kind,
    filename: descriptor.filename,
    path,
    exists: bytes !== null,
    bytes,
  };
}

function resolveArtifactsRoot(artifactsRoot) {
  const normalizedRoot = artifactsRoot.endsWith("/")
    ? artifactsRoot
    : `${artifactsRoot}/`;

  if (typeof location !== "undefined") {
    return new URL(normalizedRoot, location.href);
  }

  return new URL(normalizedRoot);
}

function normalizeArtifactInputs(artifacts) {
  if (!Array.isArray(artifacts)) {
    throw new TypeError("artifacts must be an array");
  }

  return artifacts.map((artifact) => ({
    kind: artifact.kind,
    bytes: toUint8Array(artifact.bytes),
  }));
}

function encodeProofBundle(bundle) {
  return {
    proof: {
      pi_a: normalizePair(bundle?.proof?.piA ?? bundle?.proof?.pi_a, "piA"),
      pi_b: normalizePairRows(bundle?.proof?.piB ?? bundle?.proof?.pi_b, "piB"),
      pi_c: normalizePair(bundle?.proof?.piC ?? bundle?.proof?.pi_c, "piC"),
      protocol: String(bundle?.proof?.protocol ?? ""),
      curve: String(bundle?.proof?.curve ?? ""),
    },
    public_signals: normalizeStringArray(
      bundle?.publicSignals ?? bundle?.public_signals,
      "publicSignals",
    ),
  };
}

function normalizePair(value, label) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new TypeError(`${label} must contain exactly two coordinates`);
  }

  return value.map((entry) => String(entry));
}

function normalizePairRows(value, label) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new TypeError(`${label} must contain exactly two rows`);
  }

  return value.map((row) => normalizePair(row, label));
}

function normalizeStringArray(value, label) {
  if (!Array.isArray(value)) {
    throw new TypeError(`${label} must be an array`);
  }

  return value.map((entry) => String(entry));
}

function toUint8Array(bytes) {
  if (bytes instanceof Uint8Array) {
    return bytes;
  }

  if (bytes instanceof ArrayBuffer) {
    return new Uint8Array(bytes);
  }

  if (ArrayBuffer.isView(bytes)) {
    return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  if (Array.isArray(bytes)) {
    return Uint8Array.from(bytes);
  }

  throw new TypeError("artifact bytes must be a Uint8Array, ArrayBuffer, or number[]");
}
