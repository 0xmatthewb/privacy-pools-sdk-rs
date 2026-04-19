import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const options = parseArgs(process.argv.slice(2));
const requiredSmokeKeys = [
  "commitmentVerified",
  "withdrawalVerified",
  "executionSubmitted",
  "signedManifestVerified",
  "wrongSignedManifestPublicKeyRejected",
  "tamperedSignedManifestArtifactsRejected",
  "tamperedProofRejected",
  "handleKindMismatchRejected",
  "staleVerifiedProofHandleRejected",
  "staleCommitmentSessionRejected",
  "staleWithdrawalSessionRejected",
  "wrongRootRejected",
  "wrongChainIdRejected",
  "wrongCodeHashRejected",
  "wrongSignerRejected",
];

const reports = {
  iosNative: readJson(options.iosNativeReport),
  iosReactNative: readJson(options.iosReactNativeReport),
  androidNative: readJson(options.androidNativeReport),
  androidReactNative: readJson(options.androidReactNativeReport),
};

const smokeEvidence = {
  commit: options.commit,
  source: options.source,
  workflow: options.workflow,
  run_url: options.workflowUrl,
  ios: platformStatus(reports.iosNative, reports.iosReactNative),
  android: platformStatus(reports.androidNative, reports.androidReactNative),
  surfaces: {
    iosNative: surfaceStatus(reports.iosNative),
    iosReactNative: surfaceStatus(reports.iosReactNative),
    androidNative: surfaceStatus(reports.androidNative),
    androidReactNative: surfaceStatus(reports.androidReactNative),
  },
};

const parityEvidence = {
  commit: options.commit,
  source: options.source,
  workflow: options.workflow,
  run_url: options.workflowUrl,
  totalChecks:
    platformSummary(reports.iosNative, reports.iosReactNative).totalChecks +
    platformSummary(reports.androidNative, reports.androidReactNative).totalChecks,
  passed:
    platformSummary(reports.iosNative, reports.iosReactNative).passed +
    platformSummary(reports.androidNative, reports.androidReactNative).passed,
  failed:
    platformSummary(reports.iosNative, reports.iosReactNative).failed +
    platformSummary(reports.androidNative, reports.androidReactNative).failed,
  ios: platformSummary(reports.iosNative, reports.iosReactNative),
  android: platformSummary(reports.androidNative, reports.androidReactNative),
};

mkdirSync(options.outDir, { recursive: true });
writeJson(resolve(options.outDir, "mobile-smoke.json"), smokeEvidence);
writeJson(resolve(options.outDir, "mobile-parity.json"), parityEvidence);

function parseArgs(rawArgs) {
  const parsed = {
    iosNativeReport: "",
    iosReactNativeReport: "",
    androidNativeReport: "",
    androidReactNativeReport: "",
    commit: "",
    source: "",
    workflow: "",
    workflowUrl: "",
    outDir: "",
  };

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    switch (arg) {
      case "--ios-native-report":
        parsed.iosNativeReport = resolve(rawArgs[++index] ?? "");
        break;
      case "--ios-react-native-report":
        parsed.iosReactNativeReport = resolve(rawArgs[++index] ?? "");
        break;
      case "--android-native-report":
        parsed.androidNativeReport = resolve(rawArgs[++index] ?? "");
        break;
      case "--android-react-native-report":
        parsed.androidReactNativeReport = resolve(rawArgs[++index] ?? "");
        break;
      case "--commit":
        parsed.commit = rawArgs[++index] ?? "";
        break;
      case "--source":
        parsed.source = rawArgs[++index] ?? "";
        break;
      case "--workflow":
        parsed.workflow = rawArgs[++index] ?? "";
        break;
      case "--workflow-url":
        parsed.workflowUrl = rawArgs[++index] ?? "";
        break;
      case "--out-dir":
        parsed.outDir = resolve(rawArgs[++index] ?? "");
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  for (const [key, value] of Object.entries(parsed)) {
    if (!value) {
      throw new Error(`${key} is required`);
    }
  }

  return parsed;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function surfaceStatus(report) {
  return report.parity?.failed === 0 && allSmokeChecksPassed(report) ? "passed" : "failed";
}

function platformStatus(nativeReport, reactNativeReport) {
  return [nativeReport, reactNativeReport].every((report) => surfaceStatus(report) === "passed")
    ? "passed"
    : "failed";
}

function platformSummary(nativeReport, reactNativeReport) {
  const native = nativeReport;
  const reactNative = reactNativeReport;
  return {
    totalChecks:
      Number(native.parity?.totalChecks ?? 0) + Number(reactNative.parity?.totalChecks ?? 0),
    passed: Number(native.parity?.passed ?? 0) + Number(reactNative.parity?.passed ?? 0),
    failed: Number(native.parity?.failed ?? 0) + Number(reactNative.parity?.failed ?? 0),
    native,
    reactNative,
  };
}

function allSmokeChecksPassed(report) {
  const smoke = report.smoke ?? {};
  if (typeof smoke.backend !== "string" || smoke.backend.length === 0) {
    return false;
  }

  return requiredSmokeKeys.every((key) => smoke[key] === true);
}
