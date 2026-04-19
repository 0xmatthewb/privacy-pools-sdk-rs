import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

function report({ runtime, platform, surface, smokeOverrides = {}, parityOverrides = {} }) {
  return {
    generatedAt: "2026-01-01T00:00:00.000Z",
    runtime,
    platform,
    surface,
    smoke: {
      backend: "arkworks",
      commitmentVerified: true,
      withdrawalVerified: true,
      executionSubmitted: true,
      signedManifestVerified: true,
      wrongSignedManifestPublicKeyRejected: true,
      tamperedSignedManifestArtifactsRejected: true,
      tamperedProofRejected: true,
      handleKindMismatchRejected: true,
      staleVerifiedProofHandleRejected: true,
      staleCommitmentSessionRejected: true,
      staleWithdrawalSessionRejected: true,
      wrongRootRejected: true,
      wrongChainIdRejected: true,
      wrongCodeHashRejected: true,
      wrongSignerRejected: true,
      ...smokeOverrides,
    },
    parity: {
      totalChecks: 4,
      passed: 4,
      failed: 0,
      failedChecks: [],
      ...parityOverrides,
    },
    benchmark: {
      artifactResolutionMs: 0,
      bundleVerificationMs: 0,
      sessionPreloadMs: 0,
      firstInputPreparationMs: 0,
      firstWitnessGenerationMs: 0,
      firstProofGenerationMs: 0,
      firstVerificationMs: 0,
      firstProveAndVerifyMs: 0,
      iterations: 1,
      warmup: 0,
      peakResidentMemoryBytes: null,
      samples: [{
        inputPreparationMs: 0,
        witnessGenerationMs: 0,
        proofGenerationMs: 0,
        verificationMs: 0,
        proveAndVerifyMs: 0,
      }],
    },
  };
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function runAssembler(tempRoot, overrides = {}, metadata = {}) {
  const reports = {
    iosNative: report({ runtime: "native", platform: "ios", surface: "native" }),
    iosReactNative: report({
      runtime: "react-native-app",
      platform: "ios",
      surface: "react-native",
    }),
    androidNative: report({ runtime: "native", platform: "android", surface: "native" }),
    androidReactNative: report({
      runtime: "react-native-app",
      platform: "android",
      surface: "react-native",
    }),
    ...overrides,
  };
  const outDir = join(tempRoot, "out");

  for (const [key, value] of Object.entries(reports)) {
    writeJson(join(tempRoot, `${key}.json`), value);
  }

  execFileSync("node", [
    "./packages/sdk/scripts/assemble-mobile-smoke-evidence.mjs",
    "--ios-native-report", join(tempRoot, "iosNative.json"),
    "--ios-react-native-report", join(tempRoot, "iosReactNative.json"),
    "--android-native-report", join(tempRoot, "androidNative.json"),
    "--android-react-native-report", join(tempRoot, "androidReactNative.json"),
    "--commit", "abcdef0",
    "--source", metadata.source ?? "github-workflow",
    "--workflow", metadata.workflow ?? "mobile-smoke",
    "--workflow-url", metadata.workflowUrl ?? "https://github.com/0xbow/privacy-pools-sdk-rs/actions/runs/123",
    "--out-dir", outDir,
  ], {
    cwd: join(import.meta.dirname, "..", "..", ".."),
  });

  return {
    smoke: JSON.parse(readFileSync(join(outDir, "mobile-smoke.json"), "utf8")),
    parity: JSON.parse(readFileSync(join(outDir, "mobile-parity.json"), "utf8")),
  };
}

test("assemble-mobile-smoke-evidence rolls up four passing reports", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "mobile-smoke-assemble-"));

  try {
    const { smoke, parity } = runAssembler(tempRoot);

    assert.equal(smoke.source, "github-workflow");
    assert.equal(smoke.workflow, "mobile-smoke");
    assert.equal(smoke.ios, "passed");
    assert.equal(smoke.android, "passed");
    assert.deepEqual(smoke.surfaces, {
      iosNative: "passed",
      iosReactNative: "passed",
      androidNative: "passed",
      androidReactNative: "passed",
    });
    assert.equal(parity.totalChecks, 16);
    assert.equal(parity.failed, 0);
    assert.equal(parity.source, "github-workflow");
    assert.equal(parity.workflow, "mobile-smoke");
    assert.equal(parity.ios.native.surface, "native");
    assert.equal(parity.android.reactNative.surface, "react-native");
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("assemble-mobile-smoke-evidence supports explicit local metadata", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "mobile-smoke-assemble-"));

  try {
    const { smoke, parity } = runAssembler(
      tempRoot,
      {},
      {
        source: "local-xtask",
        workflow: "mobile-smoke-local",
        workflowUrl: "local://mobile-smoke-local",
      },
    );

    assert.equal(smoke.source, "local-xtask");
    assert.equal(smoke.workflow, "mobile-smoke-local");
    assert.equal(smoke.run_url, "local://mobile-smoke-local");
    assert.equal(parity.source, "local-xtask");
    assert.equal(parity.workflow, "mobile-smoke-local");
    assert.equal(parity.run_url, "local://mobile-smoke-local");
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("assemble-mobile-smoke-evidence marks a platform failed when one native report fails", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "mobile-smoke-assemble-"));

  try {
    const { smoke } = runAssembler(tempRoot, {
      iosNative: report({
        runtime: "native",
        platform: "ios",
        surface: "native",
        parityOverrides: { totalChecks: 1, passed: 0, failed: 1, failedChecks: ["boom"] },
      }),
    });

    assert.equal(smoke.ios, "failed");
    assert.equal(smoke.surfaces.iosNative, "failed");
    assert.equal(smoke.surfaces.iosReactNative, "passed");
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("assemble-mobile-smoke-evidence marks malformed smoke booleans as failed", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "mobile-smoke-assemble-"));

  try {
    const { smoke } = runAssembler(tempRoot, {
      androidReactNative: report({
        runtime: "react-native-app",
        platform: "android",
        surface: "react-native",
        smokeOverrides: { wrongRootRejected: false },
      }),
    });

    assert.equal(smoke.android, "failed");
    assert.equal(smoke.surfaces.androidReactNative, "failed");
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("assemble-mobile-smoke-evidence marks a platform failed when one react native report fails", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "mobile-smoke-assemble-"));

  try {
    const { smoke } = runAssembler(tempRoot, {
      androidReactNative: report({
        runtime: "react-native-app",
        platform: "android",
        surface: "react-native",
        parityOverrides: { totalChecks: 1, passed: 0, failed: 1, failedChecks: ["boom"] },
      }),
    });

    assert.equal(smoke.android, "failed");
    assert.equal(smoke.surfaces.androidNative, "passed");
    assert.equal(smoke.surfaces.androidReactNative, "failed");
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("assemble-mobile-smoke-evidence marks malformed surface reports as failed", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "mobile-smoke-assemble-"));

  try {
    const { smoke } = runAssembler(tempRoot, {
      iosReactNative: {
        generatedAt: "2026-01-01T00:00:00.000Z",
        runtime: "react-native-app",
        platform: "ios",
        surface: "react-native",
        smoke: {
          backend: "arkworks",
          commitmentVerified: true,
        },
        parity: {
          totalChecks: 0,
          passed: 0,
          failed: 0,
          failedChecks: [],
        },
        benchmark: {
          samples: [],
        },
      },
    });

    assert.equal(smoke.ios, "failed");
    assert.equal(smoke.surfaces.iosNative, "passed");
    assert.equal(smoke.surfaces.iosReactNative, "failed");
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});
