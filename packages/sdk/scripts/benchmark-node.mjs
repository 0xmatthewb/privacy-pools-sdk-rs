import { readFileSync } from "node:fs";

import {
  artifactsRoot,
  buildBenchmarkReport,
  cryptoFixture,
  nowMs,
  peakRssBytes,
  withdrawalFixture,
  withdrawalManifestPath,
  writeReport,
} from "./benchmark-common.mjs";

import * as nodeEntry from "../src/node/index.mjs";

const options = parseArgs(process.argv.slice(2));

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

async function main() {
  const manifestText = readFileSync(withdrawalManifestPath, "utf8");
  const sdk = new nodeEntry.PrivacyPoolsSdkClient();
  const commitment = await sdk.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    cryptoFixture.depositSecrets.nullifier,
    cryptoFixture.depositSecrets.secret,
  );
  const request = {
    commitment,
    withdrawal: {
      processooor: "0x1111111111111111111111111111111111111111",
      data: "0x1234",
    },
    scope: cryptoFixture.scope,
    withdrawalAmount: withdrawalFixture.withdrawalAmount,
    stateWitness: withdrawalFixture.stateWitness,
    aspWitness: withdrawalFixture.aspWitness,
    newNullifier: withdrawalFixture.newNullifier,
    newSecret: withdrawalFixture.newSecret,
  };

  try {
    const artifactResolutionStart = nowMs();
    await sdk.getArtifactStatuses(manifestText, artifactsRoot);
    const artifactResolutionMs = nowMs() - artifactResolutionStart;

    const bundleVerificationStart = nowMs();
    await sdk.resolveVerifiedArtifactBundle(manifestText, artifactsRoot);
    const bundleVerificationMs = nowMs() - bundleVerificationStart;

    const sessionPreloadStart = nowMs();
    const session = await sdk.prepareWithdrawalCircuitSession(
      manifestText,
      artifactsRoot,
    );
    const sessionPreloadMs = nowMs() - sessionPreloadStart;

    const samples = [];
    for (let iteration = 0; iteration < options.iterations; iteration += 1) {
      const inputPreparationStart = nowMs();
      await sdk.buildWithdrawalCircuitInput(request);
      const inputPreparationMs = nowMs() - inputPreparationStart;

      const proveStart = nowMs();
      const proof = await sdk.proveWithdrawalWithSession(
        "stable",
        session.handle,
        request,
      );
      const proveMs = nowMs() - proveStart;

      const verificationStart = nowMs();
      const verified = await sdk.verifyWithdrawalProofWithSession(
        "stable",
        session.handle,
        proof.proof,
      );
      const verificationMs = nowMs() - verificationStart;
      if (!verified) {
        throw new Error("node benchmark proof did not verify");
      }

      samples.push({
        inputPreparationMs,
        witnessGenerationMs: proveMs,
        proofGenerationMs: 0,
        verificationMs,
        proveAndVerifyMs: proveMs + verificationMs,
      });
    }

    const report = buildBenchmarkReport({
      deviceLabel: options.deviceLabel,
      deviceModel: options.deviceModel,
      deviceClass: options.deviceClass,
      samples,
      artifactResolutionMs,
      bundleVerificationMs,
      sessionPreloadMs,
      peakResidentMemoryBytes: peakRssBytes(),
    });
    report.phase_estimation =
      "node wrapper exposes combined prove timing; witness_generation_ms contains the combined prove duration and proof_generation_ms remains 0";
    writeReport(options.report, report);
    console.log(`wrote node benchmark report to ${options.report}`);
  } finally {
    await sdk.dispose();
  }
}

function parseArgs(rawArgs) {
  const parsed = {
    report: "",
    iterations: 3,
    deviceLabel: "desktop",
    deviceModel: "reference-desktop",
    deviceClass: "desktop-reference",
  };

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    switch (arg) {
      case "--report":
        parsed.report = rawArgs[++index] ?? "";
        break;
      case "--iterations":
        parsed.iterations = Number.parseInt(rawArgs[++index] ?? "3", 10);
        break;
      case "--device-label":
        parsed.deviceLabel = rawArgs[++index] ?? "";
        break;
      case "--device-model":
        parsed.deviceModel = rawArgs[++index] ?? "";
        break;
      case "--device-class":
        parsed.deviceClass = rawArgs[++index] ?? "";
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!parsed.report) {
    throw new Error("--report is required");
  }
  if (!parsed.deviceLabel || !parsed.deviceModel || !parsed.deviceClass) {
    throw new Error("device metadata is required");
  }

  return parsed;
}
