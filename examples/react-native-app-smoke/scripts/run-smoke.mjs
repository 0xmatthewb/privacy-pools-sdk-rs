import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import process from "node:process";

const APP_NAME = "PrivacyPoolsRnAppSmoke";
const PACKAGE_NAME = "com.privacypoolsrnappsmoke";
const IOS_BUNDLE_ID = "org.reactjs.native.example.PrivacyPoolsRnAppSmoke";
const REPORT_DIRECTORY = "privacy-pools-smoke";
const REPORT_FILE_NAME = "report.json";
const STATUS_FILE_NAME = "report-status.json";
const EXECUTION_FIXTURE_FILE_NAME = "mobile-execution-fixture.json";

const args = parseArgs(process.argv.slice(2));
const workspaceRoot = resolve(args.workspace);
const tarball = resolve(args.tarball);
const templateRoot = join(
  workspaceRoot,
  "examples/react-native-app-smoke/fixture-template",
);
const appParent = join(workspaceRoot, "target/react-native-app-smoke", args.platform);
const appRoot = join(appParent, APP_NAME);
const npmCache = process.env.npm_config_cache
  ? resolve(process.env.npm_config_cache)
  : join(workspaceRoot, "target/react-native-app-smoke/.npm-cache");
const totalTimeoutMs = Number.parseInt(
  process.env.PRIVACY_POOLS_RN_APP_SMOKE_TIMEOUT_MS ??
    (args.platform === "android" ? "900000" : "600000"),
  10,
);
const idleTimeoutMs = Number.parseInt(
  process.env.PRIVACY_POOLS_RN_APP_SMOKE_IDLE_TIMEOUT_MS ?? "240000",
  10,
);

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : error);
  process.exit(1);
});

async function main() {
  if (!existsSync(templateRoot)) {
    throw new Error(`fixture template does not exist: ${templateRoot}`);
  }
  if (!existsSync(tarball)) {
    throw new Error(`packed React Native SDK tarball does not exist: ${tarball}`);
  }

  rmSync(appParent, { recursive: true, force: true });
  mkdirSync(appParent, { recursive: true });
  mkdirSync(npmCache, { recursive: true });

  copyTemplateApp();
  installJavaScriptDependencies();
  copyFixtureAssets();

  const executionServers = await startExecutionFixtureServers();
  try {
    writeExecutionFixture(executionServers.fixture);

    if (process.env.PRIVACY_POOLS_RN_APP_SMOKE_PREPARE_ONLY === "1") {
      return;
    }

    const report =
      args.platform === "android"
        ? runAndroidSmoke()
        : args.platform === "ios"
          ? runIosSmoke()
          : unsupportedPlatform(args.platform);
    writeReport(report);
  } finally {
    await executionServers.stop();
  }
}

function parseArgs(rawArgs) {
  const [platform, ...rest] = rawArgs;
  const parsed = { platform, workspace: "", tarball: "", report: "" };

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--workspace") {
      parsed.workspace = rest[++index] ?? "";
    } else if (arg === "--tarball") {
      parsed.tarball = rest[++index] ?? "";
    } else if (arg === "--report") {
      parsed.report = rest[++index] ?? "";
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!parsed.platform || !["ios", "android"].includes(parsed.platform)) {
    throw new Error(
      "usage: run-smoke.mjs ios|android --workspace <path> --tarball <path> [--report <path>]",
    );
  }
  if (!parsed.workspace || !parsed.tarball) {
    throw new Error("missing --workspace or --tarball");
  }

  return parsed;
}

function copyTemplateApp() {
  cpSync(templateRoot, appRoot, { recursive: true });
}

function installJavaScriptDependencies() {
  run("npm", ["ci", "--ignore-scripts"], {
    cwd: appRoot,
  });
  run(
    "npm",
    [
      "install",
      "--ignore-scripts",
      tarball,
    ],
    { cwd: appRoot },
  );
}

function copyFixtureAssets() {
  const fixturesRoot = join(workspaceRoot, "fixtures");
  const androidAssetsRoot = join(
    appRoot,
    "android/app/src/main/assets/privacy-pools-fixtures",
  );
  const iosFixturesRoot = join(
    appRoot,
    "ios",
    APP_NAME,
    "privacy-pools-fixtures",
  );

  for (const destination of [androidAssetsRoot, iosFixturesRoot]) {
    rmSync(destination, { recursive: true, force: true });
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(fixturesRoot, destination, { recursive: true });
  }

  const requiredFixtures = [
    join(androidAssetsRoot, "artifacts", "withdraw.vkey.json"),
    join(iosFixturesRoot, "artifacts", "withdraw.vkey.json"),
  ];
  for (const path of requiredFixtures) {
    if (!existsSync(path)) {
      throw new Error(`missing smoke fixture asset: ${path}`);
    }
  }
}

async function startExecutionFixtureServers() {
  const hosts =
    args.platform === "android"
      ? { bindHost: "0.0.0.0", publicHost: "10.0.2.2" }
      : { bindHost: "127.0.0.1", publicHost: "127.0.0.1" };
  const withdrawalFixture = JSON.parse(
    readFileSync(
      join(workspaceRoot, "fixtures", "vectors", "withdrawal-circuit-input.json"),
      "utf8",
    ),
  );
  const fixtureServerScript = join(
    workspaceRoot,
    "packages/sdk/scripts/start-mobile-execution-fixture-servers.mjs",
  );
  const child = spawn(
    "node",
    [
      fixtureServerScript,
      "--platform",
      args.platform,
      "--bind-host",
      hosts.bindHost,
      "--public-host",
      hosts.publicHost,
      "--state-root",
      String(withdrawalFixture.stateWitness.root),
      "--asp-root",
      String(withdrawalFixture.aspWitness.root),
    ],
    {
      cwd: workspaceRoot,
      env: childEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  child.stderr.on("data", (chunk) => {
    process.stderr.write(chunk);
  });

  const fixture = await new Promise((resolve, reject) => {
    let stdout = "";
    let settled = false;

    const finish = (callback, value) => {
      if (settled) {
        return;
      }
      settled = true;
      child.stdout.removeAllListeners("data");
      child.removeAllListeners("exit");
      child.removeAllListeners("error");
      callback(value);
    };

    child.on("error", (error) => {
      finish(reject, error);
    });

    child.on("exit", (code, signal) => {
      finish(
        reject,
        new Error(
          `mobile execution fixture server exited before producing fixture JSON (code=${code ?? "null"}, signal=${signal ?? "null"})`,
        ),
      );
    });

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      const newlineIndex = stdout.indexOf("\n");
      if (newlineIndex === -1) {
        return;
      }

      const line = stdout.slice(0, newlineIndex).trim();
      if (!line) {
        return;
      }

      try {
        finish(resolve, JSON.parse(line));
      } catch (error) {
        finish(reject, error);
      }
    });
  });

  return {
    fixture,
    async stop() {
      if (child.exitCode != null || child.signalCode != null) {
        return;
      }

      child.kill("SIGTERM");
      await new Promise((resolve) => {
        const timeout = setTimeout(() => {
          child.kill("SIGKILL");
        }, 5_000);
        child.once("exit", () => {
          clearTimeout(timeout);
          resolve();
        });
      });
    },
  };
}

function writeExecutionFixture(fixture) {
  const destination =
    args.platform === "android"
      ? join(
          appRoot,
          "android/app/src/main/assets/privacy-pools-fixtures/vectors",
          EXECUTION_FIXTURE_FILE_NAME,
        )
      : join(
          appRoot,
          "ios",
          APP_NAME,
          "privacy-pools-fixtures",
          "vectors",
          EXECUTION_FIXTURE_FILE_NAME,
        );
  mkdirSync(dirname(destination), { recursive: true });
  writeJson(destination, fixture);
}

function runAndroidSmoke() {
  run(
    "./gradlew",
    [":app:installRelease", "-PreactNativeArchitectures=x86_64", "--stacktrace"],
    { cwd: join(appRoot, "android") },
  );
  resetAndroidAppState();
  run("adb", ["shell", "am", "start", "-W", "-n", `${PACKAGE_NAME}/.MainActivity`], {
    cwd: appRoot,
  });
  return waitForAndroidReport();
}

function resetAndroidAppState() {
  runAllowFailure("adb", ["shell", "am", "force-stop", PACKAGE_NAME], { cwd: appRoot });
  runAllowFailure("adb", ["shell", "pm", "clear", PACKAGE_NAME], { cwd: appRoot });
  runAllowFailure("adb", ["shell", "rm", "-rf", androidReportRoot()], { cwd: appRoot });
}

function waitForAndroidReport() {
  const statusPath = androidStatusPath();
  const reportPath = androidReportPath();
  return waitForReport(statusPath, reportPath, "android");
}

function runIosSmoke() {
  runPods();

  const udid = selectIosSimulator();
  runAllowFailure("xcrun", ["simctl", "boot", udid], { cwd: appRoot });
  run("xcrun", ["simctl", "bootstatus", udid, "-b"], { cwd: appRoot });

  const derivedDataPath = join(appParent, "DerivedData");
  run(
    "xcodebuild",
    [
      "-workspace",
      join(appRoot, "ios", `${APP_NAME}.xcworkspace`),
      "-scheme",
      APP_NAME,
      "-configuration",
      "Release",
      "-sdk",
      "iphonesimulator",
      "-destination",
      `id=${udid}`,
      "-derivedDataPath",
      derivedDataPath,
      "CODE_SIGNING_ALLOWED=NO",
      "build",
    ],
    { cwd: appRoot },
  );

  const appBundle = join(
    derivedDataPath,
    "Build/Products/Release-iphonesimulator",
    `${APP_NAME}.app`,
  );
  runAllowFailure("xcrun", ["simctl", "terminate", udid, IOS_BUNDLE_ID], { cwd: appRoot });
  runAllowFailure("xcrun", ["simctl", "uninstall", udid, IOS_BUNDLE_ID], { cwd: appRoot });
  run("xcrun", ["simctl", "install", udid, appBundle], { cwd: appRoot });
  return waitForIosReport(udid);
}

function waitForIosReport(udid) {
  run("xcrun", ["simctl", "launch", udid, IOS_BUNDLE_ID], { cwd: appRoot });

  const containerPath = capture("xcrun", [
    "simctl",
    "get_app_container",
    udid,
    IOS_BUNDLE_ID,
    "data",
  ], { cwd: appRoot }).trim();
  const statusPath = join(
    containerPath,
    "Library",
    "Application Support",
    REPORT_DIRECTORY,
    STATUS_FILE_NAME,
  );
  const reportPath = join(
    containerPath,
    "Library",
    "Application Support",
    REPORT_DIRECTORY,
    REPORT_FILE_NAME,
  );
  return waitForReport(statusPath, reportPath, "ios");
}

function waitForReport(statusPath, reportPath, platform) {
  const startedAt = Date.now();
  let lastUpdateAt = startedAt;
  let lastFingerprint = "";

  while (Date.now() - startedAt < totalTimeoutMs) {
    const status =
      platform === "android"
        ? readAndroidJson(statusPath)
        : readHostJson(statusPath);
    if (status?.updatedAt && Number.isFinite(status.updatedAt)) {
      lastUpdateAt = Math.max(lastUpdateAt, Number(status.updatedAt));
    }

    const fingerprint = JSON.stringify(status ?? {});
    if (status && fingerprint !== lastFingerprint) {
      const detail = status.message ? ` (${status.message})` : "";
      console.log(`[${platform}] smoke status: ${status.status}${detail}`);
      lastFingerprint = fingerprint;
    }

    if (status?.status === "success") {
      const report =
        platform === "android"
          ? readAndroidJson(reportPath)
          : readHostJson(reportPath);
      if (!report) {
        throw new Error(`${platform} smoke reported success without ${reportPath}`);
      }
      return report;
    }
    if (status?.status === "error") {
      throw new Error(status.message ?? `${platform} smoke app reported failure`);
    }
    if (Date.now() - lastUpdateAt > idleTimeoutMs) {
      throw new Error(
        `${platform} smoke stopped updating ${statusPath} for ${idleTimeoutMs}ms`,
      );
    }
    sleep(2_000);
  }

  throw new Error(
    `timed out waiting for ${platform} report at ${statusPath} after ${totalTimeoutMs}ms`,
  );
}

function runPods() {
  const iosRoot = join(appRoot, "ios");
  if (commandExists("bundle")) {
    run("bundle", ["install"], { cwd: appRoot });
    run("bundle", ["exec", "pod", "install"], { cwd: iosRoot });
    return;
  }

  run("pod", ["install"], { cwd: iosRoot });
}

function selectIosSimulator() {
  if (process.env.IOS_SMOKE_UDID) {
    return process.env.IOS_SMOKE_UDID;
  }

  const devices = JSON.parse(capture("xcrun", ["simctl", "list", "devices", "available", "-j"], {
    cwd: appRoot,
  })).devices;
  const allDevices = Object.values(devices).flat();
  const booted = allDevices.find(
    (device) => device.name?.startsWith("iPhone") && device.state === "Booted",
  );
  const available = allDevices.find((device) => device.name?.startsWith("iPhone"));
  const selected = booted ?? available;
  if (!selected?.udid) {
    throw new Error("no available iPhone simulator found");
  }

  return selected.udid;
}

function writeReport(report) {
  if (!args.report) {
    return;
  }

  const reportPath = resolve(args.report);
  mkdirSync(dirname(reportPath), { recursive: true });
  writeJson(reportPath, report);
}

function readHostJson(path) {
  if (!existsSync(path)) {
    return null;
  }

  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(
      `failed to parse JSON at ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function readAndroidJson(path) {
  const result = spawnSync("adb", ["shell", "cat", path], {
    cwd: appRoot,
    env: childEnv(),
    encoding: "utf8",
  });
  if (result.status !== 0) {
    return null;
  }

  const payload = normalizeShellOutput(result.stdout);
  if (!payload) {
    return null;
  }

  try {
    return JSON.parse(payload);
  } catch (error) {
    throw new Error(
      `failed to parse Android JSON at ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function normalizeShellOutput(contents) {
  return contents.replace(/\r/g, "").trim();
}

function androidReportRoot() {
  return `/sdcard/Android/data/${PACKAGE_NAME}/files/${REPORT_DIRECTORY}`;
}

function androidStatusPath() {
  return `${androidReportRoot()}/${STATUS_FILE_NAME}`;
}

function androidReportPath() {
  return `${androidReportRoot()}/${REPORT_FILE_NAME}`;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function unsupportedPlatform(platform) {
  throw new Error(`unsupported platform: ${platform}`);
}

function run(command, commandArgs, options) {
  console.log(`$ ${command} ${commandArgs.join(" ")}`);
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd,
    env: childEnv(),
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${commandArgs.join(" ")} failed`);
  }
}

function runAllowFailure(command, commandArgs, options) {
  spawnSync(command, commandArgs, {
    cwd: options.cwd,
    env: childEnv(),
    stdio: "inherit",
  });
}

function capture(command, commandArgs, options) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd,
    env: childEnv(),
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `${command} ${commandArgs.join(" ")} failed`);
  }
  return result.stdout;
}

function commandExists(command) {
  const result = spawnSync("sh", ["-lc", `command -v ${command}`], {
    encoding: "utf8",
  });
  return result.status === 0;
}

function childEnv() {
  return {
    ...process.env,
    npm_config_cache: npmCache,
    RCT_NO_LAUNCH_PACKAGER: "1",
  };
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}
