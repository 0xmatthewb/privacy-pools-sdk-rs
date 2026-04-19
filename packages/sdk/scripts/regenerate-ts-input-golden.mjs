import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  calculateContext,
  generateDepositSecrets,
  generateMasterKeys,
  getCommitment,
} from "@0xbow/privacy-pools-core-sdk";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(scriptDir, "..");
const workspaceRoot = join(packageRoot, "..", "..");
const outputPath = join(
  workspaceRoot,
  "fixtures",
  "vectors",
  "withdrawal-input-ts-serialized.json",
);
const fixturePath = join(
  workspaceRoot,
  "fixtures",
  "vectors",
  "withdrawal-circuit-input.json",
);
const cryptoFixturePath = join(
  workspaceRoot,
  "fixtures",
  "vectors",
  "crypto-compatibility.json",
);
const pinnedPackagePath = join(
  packageRoot,
  "node_modules",
  "@0xbow",
  "privacy-pools-core-sdk",
  "package.json",
);

assert.ok(
  existsSync(pinnedPackagePath),
  "missing pinned @0xbow/privacy-pools-core-sdk@1.2.0 baseline; run npm ci in packages/sdk",
);
const pinnedPackage = JSON.parse(readFileSync(pinnedPackagePath, "utf8"));
assert.equal(
  pinnedPackage.version,
  "1.2.0",
  `expected @0xbow/privacy-pools-core-sdk@1.2.0, found ${pinnedPackage.version}`,
);

const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const cryptoFixture = JSON.parse(readFileSync(cryptoFixturePath, "utf8"));
const withdrawal = {
  processooor: "0x1111111111111111111111111111111111111111",
  data: "0x1234",
};

const keys = generateMasterKeys(cryptoFixture.mnemonic);
const depositSecrets = generateDepositSecrets(keys, BigInt(cryptoFixture.scope), 0n);
const commitment = getCommitment(
  BigInt(fixture.existingValue),
  BigInt(fixture.label),
  depositSecrets.nullifier,
  depositSecrets.secret,
);
const context = BigInt(calculateContext(withdrawal, BigInt(cryptoFixture.scope)));

const normalized = {
  withdrawnValue: [fixture.withdrawalAmount],
  stateRoot: [fixture.stateWitness.root],
  stateTreeDepth: [String(fixture.stateWitness.depth)],
  ASPRoot: [fixture.aspWitness.root],
  ASPTreeDepth: [String(fixture.aspWitness.depth)],
  context: [context.toString()],
  label: [fixture.label],
  existingValue: [commitment.preimage.value.toString()],
  existingNullifier: [commitment.preimage.precommitment.nullifier.toString()],
  existingSecret: [commitment.preimage.precommitment.secret.toString()],
  newNullifier: [fixture.newNullifier],
  newSecret: [fixture.newSecret],
  stateSiblings: fixture.stateWitness.siblings.map(String),
  stateIndex: [String(fixture.stateWitness.index)],
  ASPSiblings: fixture.aspWitness.siblings.map(String),
  ASPIndex: [String(fixture.aspWitness.index)],
};

const sortedNormalized = Object.fromEntries(
  Object.entries(normalized).sort(([left], [right]) => left.localeCompare(right)),
);

writeFileSync(outputPath, `${JSON.stringify(sortedNormalized)}\n`);
console.log(`wrote ${outputPath}`);
