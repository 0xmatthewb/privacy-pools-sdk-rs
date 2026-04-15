import { NativeModules } from "react-native";
import {
  getCommitment,
  getStableBackendName,
  prepareCommitmentCircuitSession,
  prepareWithdrawalCircuitSession,
  proveCommitmentWithSession,
  proveWithdrawalWithSession,
  removeCommitmentCircuitSession,
  removeWithdrawalCircuitSession,
  verifyCommitmentProofWithSession,
  verifyWithdrawalProofWithSession,
} from "@0xmatthewb/privacy-pools-sdk-react-native";

export const SUCCESS_MARKER = "PRIVACY_POOLS_RN_SMOKE_OK";
export const ERROR_MARKER = "PRIVACY_POOLS_RN_SMOKE_ERROR";

type FixturePayload = {
  root: string;
  artifactsRoot: string;
  withdrawalManifestJson: string;
  commitmentManifestJson: string;
  cryptoCompatibilityJson: string;
  withdrawalCircuitInputJson: string;
};

type SmokeFixturesModule = {
  copyFixtures(): Promise<FixturePayload>;
  markSuccess(marker: string): Promise<boolean>;
  markFailure(marker: string, message: string): Promise<boolean>;
};

type CircuitWitness = {
  root: string;
  leaf: string;
  index: number;
  siblings: string[];
  depth: number;
};

type CryptoFixture = {
  scope: string;
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

const smokeFixtures = NativeModules.PrivacyPoolsSmokeFixtures as
  | SmokeFixturesModule
  | undefined;

export async function runReactNativeAppSmoke(): Promise<void> {
  if (!smokeFixtures) {
    throw new Error("PrivacyPoolsSmokeFixtures native helper is not linked");
  }

  const fixtures = await smokeFixtures.copyFixtures();
  const crypto = JSON.parse(fixtures.cryptoCompatibilityJson) as CryptoFixture;
  const withdrawalFixture = JSON.parse(
    fixtures.withdrawalCircuitInputJson,
  ) as WithdrawalFixture;

  const backendName = await getStableBackendName();
  assertEqual(backendName, "arkworks", "stable backend");

  const commitment = await getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    crypto.depositSecrets.nullifier,
    crypto.depositSecrets.secret,
  );

  const commitmentSession = await prepareCommitmentCircuitSession(
    fixtures.commitmentManifestJson,
    fixtures.artifactsRoot,
  );
  const commitmentProof = await proveCommitmentWithSession(
    "stable",
    commitmentSession.handle,
    { commitment },
  );
  assertEqual(commitmentProof.backend, "arkworks", "commitment backend");
  assert(
    await verifyCommitmentProofWithSession(
      "stable",
      commitmentSession.handle,
      commitmentProof.proof,
    ),
    "commitment proof verifies",
  );
  assert(
    await removeCommitmentCircuitSession(commitmentSession.handle),
    "commitment session removed",
  );
  await assertFailsClosed(async () => {
    await verifyCommitmentProofWithSession(
      "stable",
      commitmentSession.handle,
      commitmentProof.proof,
    );
  }, "stale commitment session");

  const withdrawalSession = await prepareWithdrawalCircuitSession(
    fixtures.withdrawalManifestJson,
    fixtures.artifactsRoot,
  );
  const withdrawalProof = await proveWithdrawalWithSession(
    "stable",
    withdrawalSession.handle,
    {
      commitment,
      withdrawal: {
        processooor: "0x1111111111111111111111111111111111111111",
        data: [0x12, 0x34],
      },
      scope: crypto.scope,
      withdrawal_amount: withdrawalFixture.withdrawalAmount,
      state_witness: withdrawalFixture.stateWitness,
      asp_witness: withdrawalFixture.aspWitness,
      new_nullifier: withdrawalFixture.newNullifier,
      new_secret: withdrawalFixture.newSecret,
    },
  );
  assertEqual(withdrawalProof.backend, "arkworks", "withdrawal backend");
  assert(
    await verifyWithdrawalProofWithSession(
      "stable",
      withdrawalSession.handle,
      withdrawalProof.proof,
    ),
    "withdrawal proof verifies",
  );
  assert(
    await removeWithdrawalCircuitSession(withdrawalSession.handle),
    "withdrawal session removed",
  );
  await assertFailsClosed(async () => {
    await verifyWithdrawalProofWithSession(
      "stable",
      withdrawalSession.handle,
      withdrawalProof.proof,
    );
  }, "stale withdrawal session");

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

async function assertFailsClosed(
  operation: () => Promise<unknown>,
  label: string,
): Promise<void> {
  try {
    await operation();
  } catch {
    return;
  }

  throw new Error(`${label} did not fail closed`);
}
