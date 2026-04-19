import { NativeModules, Platform } from "react-native";
import {
  buildWithdrawalCircuitInput,
  calculateWithdrawalContext,
  deriveMasterKeysHandleBytes,
  type ExecutionPolicy,
  finalizePreparedTransaction,
  generateDepositSecretsHandle,
  generateWithdrawalSecretsHandle,
  generateMerkleProof,
  getCommitment,
  getCommitmentFromHandles,
  getStableBackendName,
  planVerifiedRagequitTransactionWithHandle,
  planVerifiedWithdrawalTransactionWithHandle,
  removeSecretHandle,
  removeVerifiedProofHandle,
  submitSignedTransaction,
  verifySignedManifest,
  verifySignedManifestArtifacts,
} from "@0xmatthewb/privacy-pools-sdk-react-native";
import {
  getArtifactStatuses,
  prepareCommitmentCircuitSession,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalExecution,
  proveAndVerifyCommitmentHandle,
  proveCommitmentWithSession,
  removeCommitmentCircuitSession,
  removeWithdrawalCircuitSession,
  resolveVerifiedArtifactBundle,
  startProveWithdrawalJobWithSession,
  verifyCommitmentProofWithSession,
  verifyWithdrawalProofWithSession,
  waitForProveWithdrawalJob,
} from "@0xmatthewb/privacy-pools-sdk-react-native/testing";

export const SUCCESS_MARKER = "PRIVACY_POOLS_RN_SMOKE_OK";
export const ERROR_MARKER = "PRIVACY_POOLS_RN_SMOKE_ERROR";
export const PROGRESS_MARKER = "PRIVACY_POOLS_RN_SMOKE_PROGRESS";
export const REPORT_MARKER = "PRIVACY_POOLS_RN_APP_REPORT";

type FixturePayload = {
  root: string;
  artifactsRoot: string;
  reportPath: string;
  statusPath: string;
  withdrawalManifestJson: string;
  commitmentManifestJson: string;
  signedManifestPayloadJson: string;
  signedManifestSignatureHex: string;
  signedManifestPublicKeyHex: string;
  cryptoCompatibilityJson: string;
  withdrawalCircuitInputJson: string;
  assuranceGoldensJson: string;
  auditParityCasesJson: string;
  executionFixtureJson: string;
};

type SmokeFixturesModule = {
  copyFixtures(): Promise<FixturePayload>;
  markSuccess(marker: string): Promise<boolean>;
  markFailure(marker: string, message: string): Promise<boolean>;
  markProgress(marker: string, message: string): Promise<boolean>;
  markReport(marker: string, reportJson: string): Promise<boolean>;
};

type CircuitWitness = {
  root: string;
  leaf: string;
  index: number;
  siblings: string[];
  depth: number;
};

type CryptoFixture = {
  mnemonic: string;
  scope: string;
  label: string;
  keys?: {
    masterNullifier: string;
    masterSecret: string;
  };
  depositSecrets: {
    nullifier: string;
    secret: string;
  };
};

type WithdrawalFixture = {
  label: string;
  existingValue: string;
  withdrawalAmount: string;
  newNullifier: string;
  newSecret: string;
  stateWitness: CircuitWitness;
  aspWitness: CircuitWitness;
};

type AuditCaseFixture = {
  comparisonCases: ComparisonCase[];
  merkleCases: MerkleCase[];
};

type ComparisonCase = {
  name: string;
  mnemonic: string;
  scope: string;
  label: string;
  depositIndex: string;
  withdrawalIndex: string;
  value: string;
  withdrawal: {
    processooor: string;
    data: string;
  };
};

type MerkleCase = {
  name: string;
  leaves: string[];
  leaf: string;
};

function utf8Bytes(value: string): number[] {
  return Array.from(new TextEncoder().encode(value));
}

type GoldenFixture = {
  cases: Array<{
    name: string;
    masterKeys: Record<string, string>;
    depositSecrets: Record<string, string>;
    withdrawalSecrets: Record<string, string>;
    precommitmentHash: string;
    commitment: Record<string, string>;
    withdrawalContextHex: string;
  }>;
  merkleCases: Array<{
    name: string;
    proof: {
      root: string;
      leaf: string;
      index: number;
      siblings: string[];
    };
  }>;
};

type BenchmarkSample = {
  inputPreparationMs: number;
  witnessGenerationMs: number;
  proofGenerationMs: number;
  verificationMs: number;
  proveAndVerifyMs: number;
};

type AppReport = {
  generatedAt: string;
  runtime: "react-native-app";
  platform: "ios" | "android";
  surface: "react-native";
  smoke: {
    backend: string;
    commitmentVerified: boolean;
    withdrawalVerified: boolean;
    executionSubmitted: boolean;
    signedManifestVerified: boolean;
    wrongSignedManifestPublicKeyRejected: boolean;
    tamperedSignedManifestArtifactsRejected: boolean;
    tamperedProofRejected: boolean;
    handleKindMismatchRejected: boolean;
    staleVerifiedProofHandleRejected: boolean;
    staleCommitmentSessionRejected: boolean;
    staleWithdrawalSessionRejected: boolean;
    wrongRootRejected: boolean;
    wrongChainIdRejected: boolean;
    wrongCodeHashRejected: boolean;
    wrongSignerRejected: boolean;
  };
  parity: {
    totalChecks: number;
    passed: number;
    failed: number;
    failedChecks: string[];
  };
  benchmark: {
    artifactResolutionMs: number;
    bundleVerificationMs: number;
    sessionPreloadMs: number;
    firstInputPreparationMs: number;
    firstWitnessGenerationMs: number;
    firstProofGenerationMs: number;
    firstVerificationMs: number;
    firstProveAndVerifyMs: number;
    iterations: number;
    warmup: number;
    peakResidentMemoryBytes: null;
    samples: BenchmarkSample[];
  };
};

type ExecutionFixture = {
  platform: "ios" | "android";
  validRpcUrl: string;
  wrongRootRpcUrl: string;
  signerUrl: string;
  wrongSignerUrl: string;
  expectedChainId: number;
  caller: string;
  poolAddress: string;
  entrypointAddress: string;
  expectedPoolCodeHash: string;
  expectedEntrypointCodeHash: string;
};

const smokeFixtures = NativeModules.PrivacyPoolsSmokeFixtures as
  | SmokeFixturesModule
  | undefined;

export async function runReactNativeAppSmoke(): Promise<void> {
  if (!smokeFixtures) {
    throw new Error("PrivacyPoolsSmokeFixtures native helper is not linked");
  }

  assertSafeSurfaceLinked();
  assertSafeNativeMethodsLinked();
  assertTestingSurfaceLinked();
  assertTestingNativeMethodsLinked();

  const fixtures = await smokeFixtures.copyFixtures();
  await markSmokeProgress("fixtures copied");
  const crypto = JSON.parse(fixtures.cryptoCompatibilityJson) as CryptoFixture;
  const withdrawalFixture = JSON.parse(
    fixtures.withdrawalCircuitInputJson,
  ) as WithdrawalFixture;
  const goldens = JSON.parse(fixtures.assuranceGoldensJson) as GoldenFixture;
  const auditCases = JSON.parse(fixtures.auditParityCasesJson) as AuditCaseFixture;
  const executionFixture = JSON.parse(
    fixtures.executionFixtureJson,
  ) as ExecutionFixture;

  const smokeResult = await runSmokeFlow(
    fixtures,
    crypto,
    withdrawalFixture,
    executionFixture,
  );
  const parity = await runParityChecks(goldens, auditCases);
  assert(
    parity.failed === 0,
    `react native parity checks must all pass: ${parity.failedChecks.join(", ")}`,
  );
  const { benchmark, ...smoke } = smokeResult;

  const report: AppReport = {
    generatedAt: new Date().toISOString(),
    runtime: "react-native-app",
    platform: normalizePlatform(),
    surface: "react-native",
    smoke,
    parity,
    benchmark,
  };

  await smokeFixtures.markReport(REPORT_MARKER, JSON.stringify(report));
  await smokeFixtures.markSuccess(SUCCESS_MARKER);
}

export async function markSmokeFailure(message: string): Promise<void> {
  if (!smokeFixtures) {
    return;
  }

  try {
    await smokeFixtures.markFailure(ERROR_MARKER, message);
  } catch {
  }
}

async function markSmokeProgress(message: string): Promise<void> {
  if (!smokeFixtures) {
    return;
  }

  try {
    await smokeFixtures.markProgress(PROGRESS_MARKER, message);
  } catch {
  }
}

async function withProgressHeartbeat<T>(
  message: string,
  operation: () => Promise<T>,
): Promise<T> {
  await markSmokeProgress(message);
  const interval = setInterval(() => {
    void markSmokeProgress(message);
  }, 30_000);
  try {
    return await operation();
  } finally {
    clearInterval(interval);
  }
}

async function runSmokeFlow(
  fixtures: FixturePayload,
  crypto: CryptoFixture,
  withdrawalFixture: WithdrawalFixture,
  executionFixture: ExecutionFixture,
) {
  await markSmokeProgress("checking stable backend");
  const backendName = normalizeBackendName(await getStableBackendName());
  assertEqual(backendName, "arkworks", "stable backend");

  await markSmokeProgress("building commitment");
  const commitment = await getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    crypto.depositSecrets.nullifier,
    crypto.depositSecrets.secret,
  );

  await markSmokeProgress("preparing commitment session");
  const commitmentSession = await prepareCommitmentCircuitSession(
    fixtures.commitmentManifestJson,
    fixtures.artifactsRoot,
  );
  await markSmokeProgress("proving commitment");
  const commitmentProof = await proveCommitmentWithSession(
    "stable",
    commitmentSession.handle,
    { commitment },
  );
  assertEqual(
    normalizeBackendName(commitmentProof.backend),
    "arkworks",
    "commitment backend",
  );
  await markSmokeProgress("verifying commitment");
  const commitmentVerified = await verifyCommitmentProofWithSession(
    "stable",
    commitmentSession.handle,
    commitmentProof.proof,
  );
  await markSmokeProgress("checking commitment tamper rejection");
  const tamperedCommitmentProof = JSON.parse(
    JSON.stringify(commitmentProof.proof),
  ) as typeof commitmentProof.proof;
  tamperedCommitmentProof.public_signals[0] = "9";
  const tamperedProofRejected = await rejectsOrFalse(async () =>
    verifyCommitmentProofWithSession(
      "stable",
      commitmentSession.handle,
      tamperedCommitmentProof,
    )
  );
  assert(commitmentVerified, "commitment proof verifies");
  assert(
    await removeCommitmentCircuitSession(commitmentSession.handle),
    "commitment session removed",
  );
  await markSmokeProgress("checking stale commitment session rejection");
  const staleCommitmentSessionRejected = await failsClosed(async () => {
    await verifyCommitmentProofWithSession(
      "stable",
      commitmentSession.handle,
      commitmentProof.proof,
    );
  });
  assert(staleCommitmentSessionRejected, "stale commitment session");

  const withdrawalRequest = {
    commitment,
    withdrawal: {
      processooor: executionFixture.entrypointAddress,
      data: [0x12, 0x34],
    },
    scope: crypto.scope,
    withdrawal_amount: withdrawalFixture.withdrawalAmount,
    state_witness: withdrawalFixture.stateWitness,
    asp_witness: withdrawalFixture.aspWitness,
    new_nullifier: withdrawalFixture.newNullifier,
    new_secret: withdrawalFixture.newSecret,
  };

  await markSmokeProgress("resolving withdrawal artifacts");
  const artifactResolutionStart = nowMs();
  await getArtifactStatuses(
    fixtures.withdrawalManifestJson,
    fixtures.artifactsRoot,
    "withdraw",
  );
  const artifactResolutionMs = nowMs() - artifactResolutionStart;

  await markSmokeProgress("verifying withdrawal bundle");
  const bundleVerificationStart = nowMs();
  await resolveVerifiedArtifactBundle(
    fixtures.withdrawalManifestJson,
    fixtures.artifactsRoot,
    "withdraw",
  );
  const bundleVerificationMs = nowMs() - bundleVerificationStart;

  await markSmokeProgress("building withdrawal input");
  const inputPreparationStart = nowMs();
  await buildWithdrawalCircuitInput(withdrawalRequest);
  const inputPreparationMs = nowMs() - inputPreparationStart;

  await markSmokeProgress("preparing withdrawal session");
  const sessionPreloadStart = nowMs();
  const withdrawalSession = await prepareWithdrawalCircuitSession(
    fixtures.withdrawalManifestJson,
    fixtures.artifactsRoot,
  );
  const sessionPreloadMs = nowMs() - sessionPreloadStart;

  await markSmokeProgress("proving withdrawal");
  const proveStartedAt = nowMs();
  const stageTimes = new Map<string, number>();
  const withdrawalJob = await startProveWithdrawalJobWithSession(
    "stable",
    withdrawalSession.handle,
    withdrawalRequest,
  );
  const withdrawalProof = await withProgressHeartbeat(
    "proving withdrawal",
    () =>
      waitForProveWithdrawalJob(withdrawalJob, {
        onProgress(status) {
          const stage = status.stage ?? status.state;
          if (stage && !stageTimes.has(stage)) {
            stageTimes.set(stage, nowMs());
            void markSmokeProgress(`withdrawal job ${stage}`);
          }
        },
      }),
  );
  const proveFinishedAt = nowMs();
  const proveStageStartedAt = stageTimes.get("prove");
  const witnessGenerationMs =
    proveStageStartedAt == null
      ? proveFinishedAt - proveStartedAt
      : Math.max(0, proveStageStartedAt - proveStartedAt);
  const proofGenerationMs =
    proveStageStartedAt == null ? 0 : Math.max(0, proveFinishedAt - proveStageStartedAt);

  await markSmokeProgress("verifying withdrawal");
  const verificationStart = nowMs();
  const withdrawalVerified = await verifyWithdrawalProofWithSession(
    "stable",
    withdrawalSession.handle,
    withdrawalProof.proof,
  );
  const verificationMs = nowMs() - verificationStart;
  const proveAndVerifyMs = proveFinishedAt - proveStartedAt + verificationMs;

  assertEqual(
    normalizeBackendName(withdrawalProof.backend),
    "arkworks",
    "withdrawal backend",
  );
  assert(withdrawalVerified, "withdrawal proof verifies");
  assert(
    await removeWithdrawalCircuitSession(withdrawalSession.handle),
    "withdrawal session removed",
  );
  await markSmokeProgress("checking stale withdrawal session rejection");
  const staleWithdrawalSessionRejected = await failsClosed(async () => {
    await verifyWithdrawalProofWithSession(
      "stable",
      withdrawalSession.handle,
      withdrawalProof.proof,
    );
  });
  assert(staleWithdrawalSessionRejected, "stale withdrawal session");

  await markSmokeProgress("running execution happy path");
  const executionSubmitted = await runExecutionHappyPath(
    fixtures,
    withdrawalRequest,
    executionFixture,
  );
  assert(executionSubmitted, "execution submit happy path");
  await markSmokeProgress("checking wrong chain id rejection");
  const wrongChainIdRejected = await failsClosed(async () => {
    await withProgressHeartbeat("checking wrong chain id rejection", () =>
      prepareWithdrawalExecution(
        "stable",
        fixtures.withdrawalManifestJson,
        fixtures.artifactsRoot,
        withdrawalRequest,
        executionFixture.expectedChainId + 1,
        executionFixture.poolAddress,
        executionFixture.validRpcUrl,
        strictExecutionPolicy(executionFixture),
      ),
    );
  });
  assert(wrongChainIdRejected, "wrong chain id rejected");
  await markSmokeProgress("checking wrong code hash rejection");
  const wrongCodeHashRejected = await failsClosed(async () => {
    await withProgressHeartbeat("checking wrong code hash rejection", () =>
      prepareWithdrawalExecution(
        "stable",
        fixtures.withdrawalManifestJson,
        fixtures.artifactsRoot,
        withdrawalRequest,
        executionFixture.expectedChainId,
        executionFixture.poolAddress,
        executionFixture.validRpcUrl,
        {
          ...strictExecutionPolicy(executionFixture),
          expected_pool_code_hash: mutateHex(executionFixture.expectedPoolCodeHash),
        },
      ),
    );
  });
  assert(wrongCodeHashRejected, "wrong code hash rejected");
  await markSmokeProgress("checking wrong root rejection");
  const wrongRootRejected = await failsClosed(async () => {
    await withProgressHeartbeat("checking wrong root rejection", () =>
      prepareWithdrawalExecution(
        "stable",
        fixtures.withdrawalManifestJson,
        fixtures.artifactsRoot,
        withdrawalRequest,
        executionFixture.expectedChainId,
        executionFixture.poolAddress,
        executionFixture.wrongRootRpcUrl,
        strictExecutionPolicy(executionFixture),
      ),
    );
  });
  assert(wrongRootRejected, "wrong root rejected");
  await markSmokeProgress("checking wrong signer rejection");
  const wrongSignerRejected = await failsClosed(async () => {
    const prepared = await withProgressHeartbeat(
      "checking wrong signer rejection",
      () =>
        prepareWithdrawalExecution(
          "stable",
          fixtures.withdrawalManifestJson,
          fixtures.artifactsRoot,
          withdrawalRequest,
          executionFixture.expectedChainId,
          executionFixture.poolAddress,
          executionFixture.validRpcUrl,
          strictExecutionPolicy(executionFixture),
        ),
    );
    const finalized = await finalizePreparedTransaction(
      executionFixture.validRpcUrl,
      prepared,
    );
    const wrongSignedTransaction = await signFinalizedRequest(
      executionFixture.wrongSignerUrl,
      finalized.request,
    );
    await submitSignedTransaction(
      executionFixture.validRpcUrl,
      finalized,
      wrongSignedTransaction,
    );
  });
  assert(wrongSignerRejected, "wrong signer rejected");

  await markSmokeProgress("verifying signed manifest");
  const signedManifestVerified = Boolean(
    await verifySignedManifest(
      fixtures.signedManifestPayloadJson,
      fixtures.signedManifestSignatureHex,
      fixtures.signedManifestPublicKeyHex,
    ),
  );
  assert(signedManifestVerified, "signed manifest verifies");
  await markSmokeProgress("checking signed manifest failures");
  const wrongSignedManifestPublicKeyRejected = await failsClosed(async () => {
    await verifySignedManifest(
      fixtures.signedManifestPayloadJson,
      fixtures.signedManifestSignatureHex,
      mutateHex(fixtures.signedManifestPublicKeyHex),
    );
  });
  assert(
    wrongSignedManifestPublicKeyRejected,
    "wrong signed manifest public key is rejected",
  );
  const tamperedSignedManifestArtifactsRejected = await failsClosed(async () => {
    await verifySignedManifestArtifacts(
      fixtures.signedManifestPayloadJson,
      fixtures.signedManifestSignatureHex,
      fixtures.signedManifestPublicKeyHex,
      [{ filename: "withdraw-fixture.wasm", bytes: [1, 2, 3] }],
    );
  });
  assert(
    tamperedSignedManifestArtifactsRejected,
    "tampered signed manifest artifacts are rejected",
  );

  await markSmokeProgress("checking verified proof handle lifecycle");
  const masterKeysHandle = await deriveMasterKeysHandleBytes(
    utf8Bytes(crypto.mnemonic),
  );
  const depositSecretsHandle = await generateDepositSecretsHandle(
    masterKeysHandle,
    crypto.scope,
    "0",
  );
  const commitmentHandle = await getCommitmentFromHandles(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    depositSecretsHandle,
  );
  const verifiedCommitmentHandle = await proveAndVerifyCommitmentHandle(
    "stable",
    fixtures.commitmentManifestJson,
    fixtures.artifactsRoot,
    commitmentHandle,
  );
  const handleKindMismatchRejected = await failsClosed(async () => {
    await planVerifiedWithdrawalTransactionWithHandle(
      1,
      "0x2222222222222222222222222222222222222222",
      verifiedCommitmentHandle,
    );
  });
  assert(handleKindMismatchRejected, "verified handle kind mismatch is rejected");
  assert(
    await removeVerifiedProofHandle(verifiedCommitmentHandle),
    "verified commitment handle removed",
  );
  const staleVerifiedProofHandleRejected = await failsClosed(async () => {
    await planVerifiedRagequitTransactionWithHandle(
      1,
      "0x2222222222222222222222222222222222222222",
      verifiedCommitmentHandle,
    );
  });
  assert(
    staleVerifiedProofHandleRejected,
    "stale verified proof handle is rejected",
  );

  return {
    backend: backendName,
    commitmentVerified,
    withdrawalVerified,
    executionSubmitted,
    signedManifestVerified,
    wrongSignedManifestPublicKeyRejected,
    tamperedSignedManifestArtifactsRejected,
    tamperedProofRejected,
    handleKindMismatchRejected,
    staleVerifiedProofHandleRejected,
    staleCommitmentSessionRejected,
    staleWithdrawalSessionRejected,
    wrongRootRejected,
    wrongChainIdRejected,
    wrongCodeHashRejected,
    wrongSignerRejected,
    benchmark: {
      artifactResolutionMs,
      bundleVerificationMs,
      sessionPreloadMs,
      firstInputPreparationMs: inputPreparationMs,
      firstWitnessGenerationMs: witnessGenerationMs,
      firstProofGenerationMs: proofGenerationMs,
      firstVerificationMs: verificationMs,
      firstProveAndVerifyMs: proveAndVerifyMs,
      iterations: 1,
      warmup: 0,
      peakResidentMemoryBytes: null,
      samples: [
        {
          inputPreparationMs,
          witnessGenerationMs,
          proofGenerationMs,
          verificationMs,
          proveAndVerifyMs,
        },
      ],
    },
  };
}

async function runExecutionHappyPath(
  fixtures: FixturePayload,
  withdrawalRequest: {
    commitment: string;
    withdrawal: { processooor: string; data: number[] };
    scope: string;
    withdrawal_amount: string;
    state_witness: CircuitWitness;
    asp_witness: CircuitWitness;
    new_nullifier: string;
    new_secret: string;
  },
  executionFixture: ExecutionFixture,
): Promise<boolean> {
  const prepared = await withProgressHeartbeat(
    "execution happy path: prepare",
    () =>
      prepareWithdrawalExecution(
        "stable",
        fixtures.withdrawalManifestJson,
        fixtures.artifactsRoot,
        withdrawalRequest,
        executionFixture.expectedChainId,
        executionFixture.poolAddress,
        executionFixture.validRpcUrl,
        strictExecutionPolicy(executionFixture),
      ),
  );
  await markSmokeProgress("execution happy path: finalize");
  const finalized = await finalizePreparedTransaction(
    executionFixture.validRpcUrl,
    prepared,
  );
  await markSmokeProgress("execution happy path: sign");
  const signedTransaction = await signFinalizedRequest(
    executionFixture.signerUrl,
    finalized.request,
  );
  await markSmokeProgress("execution happy path: submit");
  const submitted = await submitSignedTransaction(
    executionFixture.validRpcUrl,
    finalized,
    signedTransaction,
  );
  return submitted.receipt.transaction_hash.length > 0;
}

function strictExecutionPolicy(
  executionFixture: ExecutionFixture,
): ExecutionPolicy {
  return {
    expected_chain_id: executionFixture.expectedChainId,
    caller: executionFixture.caller,
    expected_pool_code_hash: executionFixture.expectedPoolCodeHash,
    expected_entrypoint_code_hash: executionFixture.expectedEntrypointCodeHash,
    mode: "strict",
  };
}

async function signFinalizedRequest(
  signerUrl: string,
  request: Record<string, unknown>,
): Promise<string> {
  if (typeof fetch !== "function") {
    throw new Error("fetch is unavailable in the react native smoke runtime");
  }
  const fixtureRequest = {
    ...request,
    chainId: request.chain_id,
    gasLimit: request.gas_limit,
    gasPrice: request.gas_price,
    maxFeePerGas: request.max_fee_per_gas,
    maxPriorityFeePerGas: request.max_priority_fee_per_gas,
  };
  const response = await fetch(signerUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(fixtureRequest),
  });
  if (!response.ok) {
    throw new Error(`signer fixture request failed: ${response.status}`);
  }
  const payload = (await response.json()) as { signedTransaction?: string };
  if (!payload.signedTransaction) {
    throw new Error("signer fixture response missing signedTransaction");
  }
  return payload.signedTransaction;
}

async function runParityChecks(
  goldens: GoldenFixture,
  auditCases: AuditCaseFixture,
) {
  await markSmokeProgress("running parity checks");
  const checks: Array<{ name: string; passed: boolean; detail?: string }> = [];
  const goldenCaseMap = new Map(goldens.cases.map((entry) => [entry.name, entry]));
  const goldenMerkleMap = new Map(
    goldens.merkleCases.map((entry) => [entry.name, entry]),
  );
  const recordCheck = (name: string, actual: unknown, expected: unknown) => {
    const passed = deepEqual(actual, expected);
    checks.push({
      name,
      passed,
      detail: passed
        ? undefined
        : `${name}: expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`,
    });
  };

  for (const fixture of auditCases.comparisonCases) {
    const expected = goldenCaseMap.get(fixture.name);
    if (!expected) {
      checks.push({ name: `${fixture.name}: fixture`, passed: false });
      continue;
    }

    const masterKeysHandle = await deriveMasterKeysHandleBytes(
      utf8Bytes(fixture.mnemonic),
    );
    const depositSecretsHandle = await generateDepositSecretsHandle(
      masterKeysHandle,
      fixture.scope,
      fixture.depositIndex,
    );
    const withdrawalSecretsHandle = await generateWithdrawalSecretsHandle(
      masterKeysHandle,
      fixture.label,
      fixture.withdrawalIndex,
    );
    let commitmentHandle: string | undefined;
    let withdrawalCommitmentHandle: string | undefined;

    try {
      checks.push({
        name: `${fixture.name}: masterKeysHandle`,
        passed: masterKeysHandle.length > 0,
      });
      checks.push({
        name: `${fixture.name}: depositSecretsHandle`,
        passed: depositSecretsHandle.length > 0,
      });
      checks.push({
        name: `${fixture.name}: withdrawalSecretsHandle`,
        passed: withdrawalSecretsHandle.length > 0,
      });

      commitmentHandle = await getCommitmentFromHandles(
        fixture.value,
        fixture.label,
        depositSecretsHandle,
      );
      checks.push({
        name: `${fixture.name}: commitmentHandle`,
        passed: commitmentHandle.length > 0,
      });
      const commitment = normalizeCommitment(
        await getCommitment(
          fixture.value,
          fixture.label,
          expected.depositSecrets.nullifier,
          expected.depositSecrets.secret,
        ),
      );
      recordCheck(
        `${fixture.name}: precommitmentHash`,
        commitment.precommitmentHash,
        expected.precommitmentHash,
      );
      recordCheck(`${fixture.name}: commitment`, commitment, expected.commitment);

      withdrawalCommitmentHandle = await getCommitmentFromHandles(
        fixture.value,
        fixture.label,
        withdrawalSecretsHandle,
      );
      checks.push({
        name: `${fixture.name}: withdrawalCommitmentHandle`,
        passed: withdrawalCommitmentHandle.length > 0,
      });
      const withdrawalSecretsCommitment = normalizeCommitment(
        await getCommitment(
          fixture.value,
          fixture.label,
          expected.withdrawalSecrets.nullifier,
          expected.withdrawalSecrets.secret,
        ),
      );
      const expectedWithdrawalSecretsCommitment = normalizeCommitment(
        await getCommitment(
          fixture.value,
          fixture.label,
          expected.withdrawalSecrets.nullifier,
          expected.withdrawalSecrets.secret,
        ),
      );
      recordCheck(
        `${fixture.name}: withdrawalSecretsCommitment`,
        withdrawalSecretsCommitment,
        expectedWithdrawalSecretsCommitment,
      );

      const withdrawalContextHex = await calculateWithdrawalContext(
        {
          processooor: fixture.withdrawal.processooor,
          data: hexToBytes(fixture.withdrawal.data),
        },
        fixture.scope,
      );
      recordCheck(
        `${fixture.name}: withdrawalContextHex`,
        withdrawalContextHex,
        expected.withdrawalContextHex,
      );
    } finally {
      const handlesToRemove = [
        withdrawalCommitmentHandle,
        commitmentHandle,
        withdrawalSecretsHandle,
        depositSecretsHandle,
        masterKeysHandle,
      ].filter((handle): handle is string => typeof handle === "string");
      await Promise.all(
        handlesToRemove.map((handle) => removeSecretHandle(handle)),
      );
    }
  }

  for (const fixture of auditCases.merkleCases) {
    const expected = goldenMerkleMap.get(fixture.name);
    if (!expected) {
      checks.push({ name: `${fixture.name}: merkleFixture`, passed: false });
      continue;
    }

    const proof = normalizeMerkleProof(
      await generateMerkleProof(fixture.leaves, fixture.leaf),
    );
    recordCheck(`${fixture.name}: merkleProof`, proof, expected.proof);
  }

  const failedChecks = checks
    .filter((check) => !check.passed)
    .map((check) => check.detail ?? check.name);
  return {
    totalChecks: checks.length,
    passed: checks.length - failedChecks.length,
    failed: failedChecks.length,
    failedChecks,
  };
}

async function failsClosed(operation: () => Promise<unknown>): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

function normalizePlatform(): "ios" | "android" {
  return Platform.OS === "ios" ? "ios" : "android";
}

function normalizeObject(value: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [toCamelCase(key), normalizeValue(entry)]),
  ) as Record<string, string>;
}

function normalizeCommitment(value: Record<string, unknown>) {
  return normalizeObject(value);
}

function normalizeMerkleProof(value: {
  root: string;
  leaf: string;
  index: number;
  siblings: string[];
}) {
  return {
    root: normalizeValue(value.root),
    leaf: normalizeValue(value.leaf),
    index: value.index,
    siblings: value.siblings.map((entry) => normalizeValue(entry)),
  };
}

function normalizeValue(value: unknown): string {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value === "number") {
    return String(value);
  }
  return String(value);
}

function toCamelCase(value: string): string {
  return value
    .replace(/[-_]+([a-z0-9])/g, (_, character) => character.toUpperCase())
    .replace(/^([A-Z])/, (character) => character.toLowerCase());
}

function hexToBytes(value: string): number[] {
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (normalized.length === 0) {
    return [];
  }
  const padded = normalized.length % 2 === 0 ? normalized : `0${normalized}`;
  const bytes = [];
  for (let index = 0; index < padded.length; index += 2) {
    bytes.push(Number.parseInt(padded.slice(index, index + 2), 16));
  }
  return bytes;
}

function mutateHex(value: string): string {
  if (value.length === 0) {
    return "00";
  }
  const last = value.at(-1) ?? "0";
  const replacement = last === "0" ? "1" : "0";
  return `${value.slice(0, -1)}${replacement}`;
}

async function rejectsOrFalse(
  operation: () => Promise<boolean>,
): Promise<boolean> {
  try {
    return !(await operation());
  } catch {
    return true;
  }
}

function deepEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, canonicalize(entry)]),
    );
  }
  return value;
}

function nowMs(): number {
  return Date.now();
}

function assertSafeSurfaceLinked(): void {
  const safeExports = {
    buildWithdrawalCircuitInput,
    calculateWithdrawalContext,
    deriveMasterKeysHandleBytes,
    finalizePreparedTransaction,
    generateDepositSecretsHandle,
    generateWithdrawalSecretsHandle,
    generateMerkleProof,
    getCommitment,
    getCommitmentFromHandles,
    getStableBackendName,
    planVerifiedRagequitTransactionWithHandle,
    planVerifiedWithdrawalTransactionWithHandle,
    removeSecretHandle,
    removeVerifiedProofHandle,
    submitSignedTransaction,
    verifySignedManifest,
    verifySignedManifestArtifacts,
  };
  const missingExports = Object.entries(safeExports)
    .filter(([, value]) => typeof value !== "function")
    .map(([name]) => name);
  if (missingExports.length === 0) {
    return;
  }

  const linkedMethods = Object.keys(NativeModules.PrivacyPoolsSdk ?? {}).sort();
  throw new Error(
    [
      `react native safe surface missing exports: ${missingExports.join(", ")}`,
      "ensure @0xmatthewb/privacy-pools-sdk-react-native resolves to the safe entrypoint",
      `linked native methods: ${linkedMethods.join(", ") || "(none)"}`,
    ].join("; "),
  );
}

function assertTestingSurfaceLinked(): void {
  const testingExports = {
    getArtifactStatuses,
    prepareCommitmentCircuitSession,
    prepareWithdrawalCircuitSession,
    prepareWithdrawalExecution,
    proveAndVerifyCommitmentHandle,
    proveCommitmentWithSession,
    removeCommitmentCircuitSession,
    removeWithdrawalCircuitSession,
    resolveVerifiedArtifactBundle,
    startProveWithdrawalJobWithSession,
    verifyCommitmentProofWithSession,
    verifyWithdrawalProofWithSession,
    waitForProveWithdrawalJob,
  };
  const missingExports = Object.entries(testingExports)
    .filter(([, value]) => typeof value !== "function")
    .map(([name]) => name);
  if (missingExports.length === 0) {
    return;
  }

  const linkedMethods = Object.keys(NativeModules.PrivacyPoolsSdk ?? {}).sort();
  throw new Error(
    [
      `react native testing surface missing exports: ${missingExports.join(", ")}`,
      "ensure @0xmatthewb/privacy-pools-sdk-react-native/testing resolves to the testing entrypoint",
      `linked native methods: ${linkedMethods.join(", ") || "(none)"}`,
    ].join("; "),
  );
}

function assertSafeNativeMethodsLinked(): void {
  const nativeModule = NativeModules.PrivacyPoolsSdk as
    | Record<string, unknown>
    | undefined;
  const requiredMethods = [
    "buildWithdrawalCircuitInput",
    "calculateWithdrawalContext",
    "deriveMasterKeysHandleBytes",
    "finalizePreparedTransaction",
    "generateDepositSecretsHandle",
    "generateWithdrawalSecretsHandle",
    "generateMerkleProof",
    "getCommitment",
    "getCommitmentFromHandles",
    "getStableBackendName",
    "planVerifiedRagequitTransactionWithHandle",
    "planVerifiedWithdrawalTransactionWithHandle",
    "removeSecretHandle",
    "removeVerifiedProofHandle",
    "submitSignedTransaction",
    "verifySignedManifest",
    "verifySignedManifestArtifacts",
  ];
  const missingMethods = requiredMethods.filter(
    (name) => typeof nativeModule?.[name] !== "function",
  );
  if (missingMethods.length === 0) {
    const unexpectedPlaintextMethods = [
      "deriveMasterKeys",
      "deriveDepositSecrets",
      "deriveWithdrawalSecrets",
    ].filter((name) => typeof nativeModule?.[name] === "function");
    if (unexpectedPlaintextMethods.length === 0) {
      return;
    }

    throw new Error(
      [
        `react native safe surface unexpectedly exposes plaintext helpers: ${unexpectedPlaintextMethods.join(", ")}`,
        `linked native methods: ${Object.keys(nativeModule ?? {}).sort().join(", ") || "(none)"}`,
      ].join("; "),
    );
  }

  throw new Error(
    [
      `react native safe surface missing native methods: ${missingMethods.join(", ")}`,
      `linked native methods: ${Object.keys(nativeModule ?? {}).sort().join(", ") || "(none)"}`,
    ].join("; "),
  );
}

function assertTestingNativeMethodsLinked(): void {
  const nativeModule = NativeModules.PrivacyPoolsSdk as
    | Record<string, unknown>
    | undefined;
  const requiredMethods = [
    "getArtifactStatuses",
    "prepareCommitmentCircuitSession",
    "prepareWithdrawalCircuitSession",
    "prepareWithdrawalExecution",
    "proveAndVerifyCommitmentHandle",
    "proveCommitmentWithSession",
    "removeCommitmentCircuitSession",
    "removeWithdrawalCircuitSession",
    "resolveVerifiedArtifactBundle",
    "startProveWithdrawalJobWithSession",
    "verifyCommitmentProofWithSession",
    "verifyWithdrawalProofWithSession",
  ];
  const missingMethods = requiredMethods.filter(
    (name) => typeof nativeModule?.[name] !== "function",
  );
  if (missingMethods.length === 0) {
    return;
  }

  throw new Error(
    [
      `react native testing surface missing native methods: ${missingMethods.join(", ")}`,
      `linked native methods: ${Object.keys(nativeModule ?? {}).sort().join(", ") || "(none)"}`,
    ].join("; "),
  );
}

function normalizeBackendName(value: string): string {
  return value.toLowerCase();
}

function assert(value: boolean, label: string): void {
  if (!value) {
    throw new Error(`assertion failed: ${label}`);
  }
}

function assertEqual(actual: string, expected: string, label: string): void {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}
