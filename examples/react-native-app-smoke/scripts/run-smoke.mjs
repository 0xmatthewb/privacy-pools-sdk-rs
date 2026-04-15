import { spawnSync } from "node:child_process";
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
const SUCCESS_MARKER = "PRIVACY_POOLS_RN_SMOKE_OK";
const ERROR_MARKER = "PRIVACY_POOLS_RN_SMOKE_ERROR";
const CLI_VERSION = "18.0.0";
const RN_VERSION = "0.79.7";

const args = parseArgs(process.argv.slice(2));
const workspaceRoot = resolve(args.workspace);
const tarball = resolve(args.tarball);
const templateRoot = join(workspaceRoot, "examples/react-native-app-smoke");
const appParent = join(workspaceRoot, "target/react-native-app-smoke", args.platform);
const appRoot = join(appParent, APP_NAME);
const npmCache = process.env.npm_config_cache
  ? resolve(process.env.npm_config_cache)
  : join(workspaceRoot, "target/react-native-app-smoke/.npm-cache");

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : error);
  process.exit(1);
});

async function main() {
  if (!existsSync(tarball)) {
    throw new Error(`packed React Native SDK tarball does not exist: ${tarball}`);
  }

  rmSync(appParent, { recursive: true, force: true });
  mkdirSync(appParent, { recursive: true });
  mkdirSync(npmCache, { recursive: true });

  run(
    "npx",
    [
      "--yes",
      `@react-native-community/cli@${CLI_VERSION}`,
      "init",
      APP_NAME,
      "--version",
      RN_VERSION,
      "--skip-install",
    ],
    { cwd: appParent },
  );

  overlaySmokeSources();
  installJavaScriptDependencies();

  if (args.platform === "android") {
    prepareAndroidProject();
    if (process.env.PRIVACY_POOLS_RN_APP_SMOKE_PREPARE_ONLY === "1") {
      return;
    }
    runAndroidSmoke();
  } else if (args.platform === "ios") {
    prepareIosProject();
    if (process.env.PRIVACY_POOLS_RN_APP_SMOKE_PREPARE_ONLY === "1") {
      return;
    }
    runIosSmoke();
  } else {
    throw new Error(`unsupported platform: ${args.platform}`);
  }
}

function parseArgs(rawArgs) {
  const [platform, ...rest] = rawArgs;
  const parsed = { platform, workspace: "", tarball: "" };

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--workspace") {
      parsed.workspace = rest[++index] ?? "";
    } else if (arg === "--tarball") {
      parsed.tarball = rest[++index] ?? "";
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!parsed.platform || !["ios", "android"].includes(parsed.platform)) {
    throw new Error("usage: run-smoke.mjs ios|android --workspace <path> --tarball <path>");
  }
  if (!parsed.workspace || !parsed.tarball) {
    throw new Error("missing --workspace or --tarball");
  }

  return parsed;
}

function overlaySmokeSources() {
  copyTemplate("App.tsx", "App.tsx");
  copyTemplate("index.js", "index.js");
  copyTemplate("src/smoke.ts", "src/smoke.ts");

  const appJsonPath = join(appRoot, "app.json");
  writeJson(appJsonPath, {
    name: APP_NAME,
    displayName: "Privacy Pools RN Smoke",
  });

  const packageJsonPath = join(appRoot, "package.json");
  const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
  packageJson.name = "privacy-pools-rn-app-smoke";
  packageJson.scripts = {
    android: "react-native run-android",
    ios: "react-native run-ios",
    start: "react-native start",
    typecheck: "tsc --noEmit --project tsconfig.json",
  };
  writeJson(packageJsonPath, packageJson);
}

function installJavaScriptDependencies() {
  run("npm", ["install", "--no-package-lock", "--ignore-scripts"], {
    cwd: appRoot,
  });
  run(
    "npm",
    [
      "install",
      "--no-package-lock",
      "--ignore-scripts",
      "--no-save",
      tarball,
    ],
    { cwd: appRoot },
  );
}

function prepareAndroidProject() {
  const mainApplicationPath = findFile(
    join(appRoot, "android/app/src/main/java"),
    "MainApplication.kt",
  );
  const packageName = readPackageName(mainApplicationPath);
  const androidNativeRoot = dirname(mainApplicationPath);

  writeTemplate(
    "native/android/PrivacyPoolsSmokeFixturesModule.kt",
    join(androidNativeRoot, "PrivacyPoolsSmokeFixturesModule.kt"),
    { "{{PACKAGE}}": packageName },
  );
  writeTemplate(
    "native/android/PrivacyPoolsSmokeFixturesPackage.kt",
    join(androidNativeRoot, "PrivacyPoolsSmokeFixturesPackage.kt"),
    { "{{PACKAGE}}": packageName },
  );

  let mainApplication = readFileSync(mainApplicationPath, "utf8");
  if (!mainApplication.includes("PrivacyPoolsSmokeFixturesPackage()")) {
    mainApplication = mainApplication.replace(
      "PackageList(this).packages.apply {\n",
      "PackageList(this).packages.apply {\n              add(PrivacyPoolsSmokeFixturesPackage())\n",
    );
    writeFileSync(mainApplicationPath, mainApplication);
  }

  const gradlePropertiesPath = join(appRoot, "android/gradle.properties");
  let gradleProperties = readFileSync(gradlePropertiesPath, "utf8");
  gradleProperties = gradleProperties.replace("newArchEnabled=true", "newArchEnabled=false");
  writeFileSync(gradlePropertiesPath, gradleProperties);

  const assetsRoot = join(appRoot, "android/app/src/main/assets/privacy-pools-fixtures");
  rmSync(assetsRoot, { recursive: true, force: true });
  mkdirSync(dirname(assetsRoot), { recursive: true });
  cpSync(join(workspaceRoot, "fixtures"), assetsRoot, { recursive: true });
}

function prepareIosProject() {
  const iosAppRoot = join(appRoot, "ios", APP_NAME);
  copyTemplate(
    "native/ios/PrivacyPoolsSmokeFixtures.swift",
    `ios/${APP_NAME}/PrivacyPoolsSmokeFixtures.swift`,
  );
  copyTemplate(
    "native/ios/PrivacyPoolsSmokeFixtures.m",
    `ios/${APP_NAME}/PrivacyPoolsSmokeFixtures.m`,
  );

  const fixturesRoot = join(iosAppRoot, "privacy-pools-fixtures");
  rmSync(fixturesRoot, { recursive: true, force: true });
  cpSync(join(workspaceRoot, "fixtures"), fixturesRoot, { recursive: true });

  patchXcodeProject(join(appRoot, "ios", `${APP_NAME}.xcodeproj/project.pbxproj`));
}

function runAndroidSmoke() {
  run("./gradlew", [":app:installRelease", "-PreactNativeArchitectures=x86_64", "--stacktrace"], {
    cwd: join(appRoot, "android"),
  });
  run("adb", ["logcat", "-c"], { cwd: appRoot });
  run("adb", ["shell", "am", "force-stop", PACKAGE_NAME], { cwd: appRoot });
  run("adb", ["shell", "am", "start", "-W", "-n", `${PACKAGE_NAME}/.MainActivity`], {
    cwd: appRoot,
  });
  waitForAndroidMarker();
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
  run("xcrun", ["simctl", "install", udid, appBundle], { cwd: appRoot });
  waitForIosMarker(udid);
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

function waitForAndroidMarker() {
  const deadline = Date.now() + 240_000;
  let lastLog = "";

  while (Date.now() < deadline) {
    const log = capture("adb", ["logcat", "-d"], { cwd: appRoot });
    lastLog = log;
    if (log.includes(SUCCESS_MARKER)) {
      return;
    }
    if (log.includes(ERROR_MARKER)) {
      throw new Error(logTail(log));
    }
    sleep(2_000);
  }

  throw new Error(`timed out waiting for ${SUCCESS_MARKER}\n${logTail(lastLog)}`);
}

function waitForIosMarker(udid) {
  run("xcrun", ["simctl", "launch", udid, IOS_BUNDLE_ID], { cwd: appRoot });

  const deadline = Date.now() + 240_000;
  let lastLog = "";
  while (Date.now() < deadline) {
    const log = capture(
      "xcrun",
      [
        "simctl",
        "spawn",
        udid,
        "log",
        "show",
        "--style",
        "compact",
        "--last",
        "5m",
        "--predicate",
        `eventMessage CONTAINS "${SUCCESS_MARKER}" OR eventMessage CONTAINS "${ERROR_MARKER}"`,
      ],
      { cwd: appRoot },
    );
    lastLog = log;
    if (log.includes(SUCCESS_MARKER)) {
      return;
    }
    if (log.includes(ERROR_MARKER)) {
      throw new Error(logTail(log));
    }
    sleep(2_000);
  }

  throw new Error(`timed out waiting for ${SUCCESS_MARKER}\n${logTail(lastLog)}`);
}

function selectIosSimulator() {
  if (process.env.IOS_SMOKE_UDID) {
    return process.env.IOS_SMOKE_UDID;
  }

  const devices = JSON.parse(capture("xcrun", ["simctl", "list", "devices", "available", "-j"], {
    cwd: appRoot,
  })).devices;
  const allDevices = Object.values(devices).flat();
  const booted = allDevices.find((device) =>
    device.name?.startsWith("iPhone") && device.state === "Booted"
  );
  const available = allDevices.find((device) => device.name?.startsWith("iPhone"));
  const selected = booted ?? available;
  if (!selected?.udid) {
    throw new Error("no available iPhone simulator found");
  }

  return selected.udid;
}

function patchXcodeProject(projectPath) {
  let project = readFileSync(projectPath, "utf8");
  if (project.includes("PrivacyPoolsSmokeFixtures.swift")) {
    return;
  }

  project = project.replace(
    "/* Begin PBXBuildFile section */\n",
    `/* Begin PBXBuildFile section */
\t\tE90000000000000000000001 /* PrivacyPoolsSmokeFixtures.swift in Sources */ = {isa = PBXBuildFile; fileRef = E90000000000000000000002 /* PrivacyPoolsSmokeFixtures.swift */; };
\t\tE90000000000000000000003 /* PrivacyPoolsSmokeFixtures.m in Sources */ = {isa = PBXBuildFile; fileRef = E90000000000000000000004 /* PrivacyPoolsSmokeFixtures.m */; };
\t\tE90000000000000000000005 /* privacy-pools-fixtures in Resources */ = {isa = PBXBuildFile; fileRef = E90000000000000000000006 /* privacy-pools-fixtures */; };
`,
  );
  project = project.replace(
    "/* Begin PBXFileReference section */\n",
    `/* Begin PBXFileReference section */
\t\tE90000000000000000000002 /* PrivacyPoolsSmokeFixtures.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = PrivacyPoolsSmokeFixtures.swift; sourceTree = "<group>"; };
\t\tE90000000000000000000004 /* PrivacyPoolsSmokeFixtures.m */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = PrivacyPoolsSmokeFixtures.m; sourceTree = "<group>"; };
\t\tE90000000000000000000006 /* privacy-pools-fixtures */ = {isa = PBXFileReference; lastKnownFileType = folder; path = "privacy-pools-fixtures"; sourceTree = "<group>"; };
`,
  );
  project = project.replace(
    /(\t{4}[A-F0-9]+ \/\* AppDelegate\.swift \*\/,\n)/,
    `$1\t\t\t\tE90000000000000000000002 /* PrivacyPoolsSmokeFixtures.swift */,\n\t\t\t\tE90000000000000000000004 /* PrivacyPoolsSmokeFixtures.m */,\n\t\t\t\tE90000000000000000000006 /* privacy-pools-fixtures */,\n`,
  );
  project = project.replace(
    /(\t{4}[A-F0-9]+ \/\* AppDelegate\.swift in Sources \*\/,\n)/,
    `$1\t\t\t\tE90000000000000000000001 /* PrivacyPoolsSmokeFixtures.swift in Sources */,\n\t\t\t\tE90000000000000000000003 /* PrivacyPoolsSmokeFixtures.m in Sources */,\n`,
  );
  project = project.replace(
    /(\t{4}[A-F0-9]+ \/\* LaunchScreen\.storyboard in Resources \*\/,\n)/,
    `$1\t\t\t\tE90000000000000000000005 /* privacy-pools-fixtures in Resources */,\n`,
  );

  writeFileSync(projectPath, project);
}

function copyTemplate(source, destination) {
  const destinationPath = join(appRoot, destination);
  mkdirSync(dirname(destinationPath), { recursive: true });
  cpSync(join(templateRoot, source), destinationPath);
}

function writeTemplate(source, destination, replacements) {
  let contents = readFileSync(join(templateRoot, source), "utf8");
  for (const [from, to] of Object.entries(replacements)) {
    contents = contents.split(from).join(to);
  }
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, contents);
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function findFile(root, filename) {
  const result = spawnSync("find", [root, "-name", filename, "-type", "f"], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `failed to find ${filename}`);
  }

  const first = result.stdout.trim().split("\n").find(Boolean);
  if (!first) {
    throw new Error(`could not find ${filename} under ${root}`);
  }

  return first;
}

function readPackageName(path) {
  const contents = readFileSync(path, "utf8");
  const match = contents.match(/^package\s+([^\s]+)/m);
  if (!match) {
    throw new Error(`could not read package name from ${path}`);
  }
  return match[1];
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

function logTail(log) {
  return log.split("\n").slice(-80).join("\n");
}
