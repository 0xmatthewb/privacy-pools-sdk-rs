const PROVER_UNAVAILABLE_MESSAGE =
  "Browser proving supports only the stable Rust/WASM backend.";

const BROWSER_CAPABILITIES = Object.freeze({
  runtime: "browser",
  provingAvailable: true,
  verificationAvailable: true,
  workerAvailable: true,
  reason:
    "Browser proving and verification are available through Rust/WASM with browser-native circuit witness execution.",
});

const STABLE_BACKEND_NAME = "Arkworks";

let wasmModulePromise = null;
const browserSessionArtifacts = new Map();

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

export async function buildCommitmentCircuitInput(request) {
  return invokeJson(
    "buildCommitmentCircuitInputJson",
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
  return getArtifactStatusesForCircuit(manifestJson, artifactsRoot, "withdraw");
}

export async function getCommitmentArtifactStatuses(manifestJson, artifactsRoot) {
  return getArtifactStatusesForCircuit(manifestJson, artifactsRoot, "commitment");
}

async function getArtifactStatusesForCircuit(manifestJson, artifactsRoot, circuit) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, circuit);
  const verifiedKinds = new Set();

  if (fetchedArtifacts.every((artifact) => artifact.exists)) {
    try {
      const verifiedBundle = await verifyArtifactBytes(
        manifestJson,
        circuit,
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
  return resolveVerifiedArtifactBundleForCircuit(manifestJson, artifactsRoot, "withdraw");
}

export async function resolveVerifiedCommitmentArtifactBundle(
  manifestJson,
  artifactsRoot,
) {
  return resolveVerifiedArtifactBundleForCircuit(
    manifestJson,
    artifactsRoot,
    "commitment",
  );
}

async function resolveVerifiedArtifactBundleForCircuit(
  manifestJson,
  artifactsRoot,
  circuit,
) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, circuit);
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const bundle = await verifyArtifactBytes(
    manifestJson,
    circuit,
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
  return prepareCircuitSession(manifestJson, artifactsRoot, "withdraw");
}

export async function prepareCommitmentCircuitSession(manifestJson, artifactsRoot) {
  return prepareCircuitSession(manifestJson, artifactsRoot, "commitment");
}

async function prepareCircuitSession(manifestJson, artifactsRoot, circuit) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, circuit);
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const wasm = await getWasmModule();
  const methodName =
    circuit === "commitment"
      ? "prepareCommitmentCircuitSessionFromBytes"
      : "prepareWithdrawalCircuitSessionFromBytes";
  const normalizedArtifacts = fetchedArtifacts.map(({ kind, bytes }) => ({
    kind,
    bytes,
  }));
  const session = JSON.parse(
    wasm[methodName](
      manifestJson,
      normalizeArtifactInputs(normalizedArtifacts),
    ),
  );
  rememberSessionArtifacts(session, normalizedArtifacts);
  return session;
}

export async function prepareWithdrawalCircuitSessionFromBytes(
  manifestJson,
  artifacts,
) {
  const wasm = await getWasmModule();
  const normalizedArtifacts = normalizeArtifactInputs(artifacts);
  const session = JSON.parse(
    wasm.prepareWithdrawalCircuitSessionFromBytes(
      manifestJson,
      normalizedArtifacts,
    ),
  );
  rememberSessionArtifacts(session, normalizedArtifacts);
  return session;
}

export async function prepareCommitmentCircuitSessionFromBytes(
  manifestJson,
  artifacts,
) {
  const wasm = await getWasmModule();
  const normalizedArtifacts = normalizeArtifactInputs(artifacts);
  const session = JSON.parse(
    wasm.prepareCommitmentCircuitSessionFromBytes(
      manifestJson,
      normalizedArtifacts,
    ),
  );
  rememberSessionArtifacts(session, normalizedArtifacts);
  return session;
}

export async function removeWithdrawalCircuitSession(sessionHandle) {
  const wasm = await getWasmModule();
  const removed = wasm.removeWithdrawalCircuitSession(sessionHandle);
  if (removed) {
    browserSessionArtifacts.delete(sessionHandle);
  }
  return removed;
}

export async function removeCommitmentCircuitSession(sessionHandle) {
  const wasm = await getWasmModule();
  const removed = wasm.removeCommitmentCircuitSession(sessionHandle);
  if (removed) {
    browserSessionArtifacts.delete(sessionHandle);
  }
  return removed;
}

export async function proveWithdrawal(
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "withdraw" });
  const { fetchedArtifacts, artifactInputs } = await loadProvingArtifactInputs(
    manifestJson,
    artifactsRoot,
    "withdraw",
  );
  const wasmArtifact = requireWasmArtifact(fetchedArtifacts, "withdraw");
  const witness = await calculateCircuitWitness(
    wasmArtifact.bytes,
    await buildWithdrawalWitnessInput(request),
    (payload) => emitStatus(status, { circuit: "withdraw", ...payload }),
  );
  emitStatus(status, { stage: "prove", circuit: "withdraw" });
  const wasm = await getWasmModule();
  const proving = JSON.parse(
    wasm.proveWithdrawalWithWitnessJson(
      manifestJson,
      normalizeArtifactInputs(artifactInputs),
      JSON.stringify(witness),
    ),
  );
  emitStatus(status, { stage: "verify", circuit: "withdraw" });
  emitStatus(status, { stage: "done", circuit: "withdraw" });
  return proving;
}

export async function proveWithdrawalWithSession(
  backendProfile,
  sessionHandle,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "withdraw" });
  const sessionArtifacts = getSessionArtifacts(sessionHandle, "withdraw");
  const witness = await calculateCircuitWitness(
    sessionArtifacts.wasmBytes,
    await buildWithdrawalWitnessInput(request),
    (payload) => emitStatus(status, { circuit: "withdraw", ...payload }),
  );
  emitStatus(status, { stage: "prove", circuit: "withdraw" });
  const wasm = await getWasmModule();
  const proving = JSON.parse(
    wasm.proveWithdrawalWithSessionWitnessJson(
      sessionHandle,
      JSON.stringify(witness),
    ),
  );
  emitStatus(status, { stage: "verify", circuit: "withdraw" });
  emitStatus(status, { stage: "done", circuit: "withdraw" });
  return proving;
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

export async function proveCommitment(
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "commitment" });
  const { fetchedArtifacts, artifactInputs } = await loadProvingArtifactInputs(
    manifestJson,
    artifactsRoot,
    "commitment",
  );
  const wasmArtifact = requireWasmArtifact(fetchedArtifacts, "commitment");
  const witness = await calculateCircuitWitness(
    wasmArtifact.bytes,
    await buildCommitmentWitnessInput(request),
    (payload) => emitStatus(status, { circuit: "commitment", ...payload }),
  );
  emitStatus(status, { stage: "prove", circuit: "commitment" });
  const wasm = await getWasmModule();
  const proving = JSON.parse(
    wasm.proveCommitmentWithWitnessJson(
      manifestJson,
      normalizeArtifactInputs(artifactInputs),
      JSON.stringify(witness),
    ),
  );
  emitStatus(status, { stage: "verify", circuit: "commitment" });
  emitStatus(status, { stage: "done", circuit: "commitment" });
  return proving;
}

export async function proveCommitmentWithSession(
  backendProfile,
  sessionHandle,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "commitment" });
  const sessionArtifacts = getSessionArtifacts(sessionHandle, "commitment");
  const witness = await calculateCircuitWitness(
    sessionArtifacts.wasmBytes,
    await buildCommitmentWitnessInput(request),
    (payload) => emitStatus(status, { circuit: "commitment", ...payload }),
  );
  emitStatus(status, { stage: "prove", circuit: "commitment" });
  const wasm = await getWasmModule();
  const proving = JSON.parse(
    wasm.proveCommitmentWithSessionWitnessJson(
      sessionHandle,
      JSON.stringify(witness),
    ),
  );
  emitStatus(status, { stage: "verify", circuit: "commitment" });
  emitStatus(status, { stage: "done", circuit: "commitment" });
  return proving;
}

export async function verifyCommitmentProof(
  backendProfile,
  manifestJson,
  artifactsRoot,
  proof,
) {
  assertStableBackend(backendProfile);
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, "commitment");
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const wasm = await getWasmModule();
  return wasm.verifyCommitmentProof(
    manifestJson,
    normalizeArtifactInputs(
      fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
    ),
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function verifyCommitmentProofWithSession(
  backendProfile,
  sessionHandle,
  proof,
) {
  assertStableBackend(backendProfile);
  const wasm = await getWasmModule();
  return wasm.verifyCommitmentProofWithSession(
    sessionHandle,
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

async function buildWithdrawalWitnessInput(request) {
  const wasm = await getWasmModule();
  return wasm.buildWithdrawalWitnessInputJson(JSON.stringify(request));
}

async function buildCommitmentWitnessInput(request) {
  const wasm = await getWasmModule();
  return wasm.buildCommitmentWitnessInputJson(JSON.stringify(request));
}

async function loadProvingArtifactInputs(manifestJson, artifactsRoot, circuit) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, circuit);
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  return {
    fetchedArtifacts,
    artifactInputs: fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
  };
}

function rememberSessionArtifacts(session, artifacts) {
  const wasmArtifact = artifacts.find((artifact) => artifact.kind === "wasm");
  if (!wasmArtifact) {
    browserSessionArtifacts.delete(session.handle);
    return;
  }

  browserSessionArtifacts.set(session.handle, {
    circuit: session.circuit,
    wasmBytes: toUint8Array(wasmArtifact.bytes),
  });
}

function getSessionArtifacts(sessionHandle, expectedCircuit) {
  const artifacts = browserSessionArtifacts.get(sessionHandle);
  if (!artifacts) {
    throw new Error(
      `browser ${expectedCircuit} circuit session \`${sessionHandle}\` is not proof-capable`,
    );
  }
  if (artifacts.circuit !== expectedCircuit) {
    throw new Error(
      `browser session \`${sessionHandle}\` is for circuit \`${artifacts.circuit}\``,
    );
  }
  return artifacts;
}

function requireWasmArtifact(fetchedArtifacts, circuit) {
  const wasmArtifact = fetchedArtifacts.find((artifact) => artifact.kind === "wasm");
  if (!wasmArtifact?.bytes) {
    throw new Error(`browser ${circuit} proving requires a verified wasm artifact`);
  }
  return wasmArtifact;
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
    "Browser proving and verification currently support only the stable backend.",
  );
}

async function calculateCircuitWitness(wasmBytes, inputJson, status) {
  // Host the manifest-pinned Circom witness artifact; protocol shaping stays in Rust/WASM.
  emitStatus(status, { stage: "witness" });
  const bytes = toUint8Array(wasmBytes);
  const imports = {
    runtime: {
      exceptionHandler(code) {
        throw new Error(`circuit witness exception: ${code}`);
      },
      printErrorMessage() {},
      writeBufferMessage() {},
      showSharedRWMemory() {},
    },
  };
  const instance = await WebAssembly.instantiate(bytes, imports);
  const exports = instance.instance?.exports ?? instance.exports;
  const n32 = Number(exports.getFieldNumLen32());
  exports.init(0);

  const input = JSON.parse(inputJson);
  for (const [name, values] of Object.entries(input)) {
    const [msb, lsb] = fnv64Parts(name);
    values.forEach((value, index) => {
      const limbs = toArray32(BigInt(value), n32);
      for (let cursor = 0; cursor < n32; cursor += 1) {
        exports.writeSharedRWMemory(cursor, limbs[n32 - 1 - cursor]);
      }
      exports.setInputSignal(msb, lsb, index);
    });
  }

  const witnessSize = Number(exports.getWitnessSize());
  const witness = [];
  for (let index = 0; index < witnessSize; index += 1) {
    exports.getWitness(index);
    const limbs = [];
    for (let cursor = 0; cursor < n32; cursor += 1) {
      limbs[n32 - 1 - cursor] = Number(exports.readSharedRWMemory(cursor));
    }
    witness.push(fromArray32(limbs).toString());
  }
  emitStatus(status, { stage: "witness", witnessSize });
  return witness;
}

function fnv64Parts(value) {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  const bytes = new TextEncoder().encode(value);
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = (hash * prime) & mask;
  }
  return [
    Number((hash >> 32n) & 0xffffffffn),
    Number(hash & 0xffffffffn),
  ];
}

function toArray32(value, size) {
  const limbs = Array(size).fill(0);
  let remaining = value;
  const radix = 0x100000000n;
  let cursor = size;
  while (remaining !== 0n) {
    cursor -= 1;
    if (cursor < 0) {
      throw new Error("circuit input value exceeds field limb width");
    }
    limbs[cursor] = Number(remaining % radix);
    remaining /= radix;
  }
  return limbs;
}

function fromArray32(limbs) {
  const radix = 0x100000000n;
  let value = 0n;
  for (const limb of limbs) {
    value = value * radix + BigInt(limb >>> 0);
  }
  return value;
}

function emitStatus(target, status) {
  if (typeof target === "function") {
    target(status);
    return;
  }
  if (target?.onStatus && typeof target.onStatus === "function") {
    target.onStatus(status);
  }
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
