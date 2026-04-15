import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(packageRoot, "../..");
const generatedRoot = resolve(packageRoot, "src/browser/generated");
const generatedTextFiles = [
  "src/browser/generated/privacy_pools_sdk_web.d.ts",
  "src/browser/generated/privacy_pools_sdk_web.js",
  "src/browser/generated/privacy_pools_sdk_web_bg.wasm.d.ts",
];
const generatedWasm = resolve(
  generatedRoot,
  "privacy_pools_sdk_web_bg.wasm",
);

function runGit(args) {
  return execFileSync("git", args, {
    cwd: packageRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
}

runGit(["diff", "--exit-code", "--", ...generatedTextFiles]);

const untracked = runGit([
  "ls-files",
  "--others",
  "--exclude-standard",
  "--",
  "src/browser/generated",
]).trim();

if (untracked.length > 0) {
  throw new Error(`generated directory contains untracked files:\n${untracked}`);
}

if (!existsSync(generatedWasm)) {
  throw new Error(`missing generated WASM: ${generatedWasm}`);
}

const wasm = readFileSync(generatedWasm);
assertWasmHasNoCustomSections(wasm);
assertWasmHasNoHostPaths(wasm);

function assertWasmHasNoCustomSections(bytes) {
  if (bytes.length < 8 || bytes.subarray(0, 4).toString("binary") !== "\0asm") {
    throw new Error("generated WASM has an invalid header");
  }

  let cursor = 8;
  while (cursor < bytes.length) {
    const sectionId = bytes[cursor];
    cursor += 1;

    const payloadLength = readWasmU32(bytes, () => cursor, (value) => {
      cursor = value;
    });
    const payloadEnd = cursor + payloadLength;

    if (payloadEnd > bytes.length) {
      throw new Error("generated WASM has a truncated section");
    }

    if (sectionId === 0) {
      throw new Error("generated WASM contains a custom section");
    }

    cursor = payloadEnd;
  }
}

function readWasmU32(bytes, getCursor, setCursor) {
  let cursor = getCursor();
  let result = 0;

  for (let byteIndex = 0; byteIndex < 5; byteIndex += 1) {
    if (cursor >= bytes.length) {
      throw new Error("generated WASM has a truncated unsigned LEB128 value");
    }

    const byte = bytes[cursor];
    cursor += 1;
    result |= (byte & 0x7f) << (byteIndex * 7);

    if ((byte & 0x80) === 0) {
      setCursor(cursor);
      return result >>> 0;
    }
  }

  throw new Error("generated WASM has an invalid unsigned LEB128 value");
}

function assertWasmHasNoHostPaths(bytes) {
  const text = bytes.toString("utf8");
  const forbidden = [
    workspaceRoot,
    process.env.CARGO_HOME,
    process.env.HOME ? `${process.env.HOME}/.cargo` : undefined,
    "/home/runner/",
    "/Users/",
  ].filter(Boolean);

  const leaked = forbidden.find((path) => text.includes(path));
  if (leaked) {
    throw new Error(`generated WASM contains host-specific path: ${leaked}`);
  }
}
