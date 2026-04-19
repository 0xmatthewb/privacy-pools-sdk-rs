import { readFileSync } from "node:fs";

import { buildBenchmarkReport, withdrawalManifestPath, artifactsRoot, writeReport } from "./benchmark-common.mjs";

const options = parseArgs(process.argv.slice(2));
const rawReport = JSON.parse(readFileSync(options.input, "utf8"));

const samples = rawReport?.benchmark?.samples;
if (!Array.isArray(samples) || samples.length === 0) {
  throw new Error(`${options.input} is missing benchmark.samples`);
}

const report = buildBenchmarkReport({
  deviceLabel: options.deviceLabel,
  deviceModel: options.deviceModel,
  deviceClass: options.deviceClass,
  samples,
  artifactResolutionMs: Number(rawReport.benchmark.artifactResolutionMs ?? 0),
  bundleVerificationMs: Number(rawReport.benchmark.bundleVerificationMs ?? 0),
  sessionPreloadMs: Number(rawReport.benchmark.sessionPreloadMs ?? 0),
  peakResidentMemoryBytes: rawReport.benchmark.peakResidentMemoryBytes ?? null,
  manifestPath: withdrawalManifestPath,
  artifactsRootPath: artifactsRoot,
});
report.runtime = rawReport.runtime;
report.platform = rawReport.platform;
writeReport(options.report, report);
console.log(`wrote react native benchmark report to ${options.report}`);

function parseArgs(rawArgs) {
  const parsed = {
    input: "",
    report: "",
    deviceLabel: "",
    deviceModel: "",
    deviceClass: "",
  };

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    switch (arg) {
      case "--input":
        parsed.input = rawArgs[++index] ?? "";
        break;
      case "--report":
        parsed.report = rawArgs[++index] ?? "";
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

  for (const [key, value] of Object.entries(parsed)) {
    if (!value) {
      throw new Error(`${key} is required`);
    }
  }

  return parsed;
}
