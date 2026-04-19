import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";

const options = parseArgs(process.argv.slice(2));
const subject = resolve(options.subject);
const result = verifySubjectAttestation(subject, options);

mkdirSync(dirname(options.out), { recursive: true });
writeFileSync(options.out, `${JSON.stringify(result, null, 2)}\n`);

function parseArgs(rawArgs) {
  const parsed = {
    out: "",
    repo: "",
    signerWorkflow: "",
    subject: "",
    subjectPath: "",
  };

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    switch (arg) {
      case "--out":
        parsed.out = resolve(rawArgs[++index] ?? "");
        break;
      case "--repo":
        parsed.repo = rawArgs[++index] ?? "";
        break;
      case "--signer-workflow":
        parsed.signerWorkflow = rawArgs[++index] ?? "";
        break;
      case "--subject":
        parsed.subject = rawArgs[++index] ?? "";
        break;
      case "--subject-path":
        parsed.subjectPath = (rawArgs[++index] ?? "").replaceAll("\\", "/");
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!parsed.out) {
    throw new Error("--out is required");
  }
  if (!parsed.repo) {
    throw new Error("--repo is required");
  }
  if (!parsed.signerWorkflow) {
    throw new Error("--signer-workflow is required");
  }
  if (!parsed.subject) {
    throw new Error("--subject is required");
  }
  if (!parsed.subjectPath) {
    throw new Error("--subject-path is required");
  }

  return parsed;
}

function verifySubjectAttestation(subject, options) {
  const sha256 = sha256File(subject);
  const command = spawnSync(
    "gh",
    [
      "attestation",
      "verify",
      subject,
      "--repo",
      options.repo,
      "--signer-workflow",
      options.signerWorkflow,
      "--format",
      "json",
    ],
    {
      encoding: "utf8",
      env: process.env,
    },
  );

  if (command.status !== 0) {
    const stderr = command.stderr?.trim();
    const stdout = command.stdout?.trim();
    throw new Error(
      [
        `gh attestation verify failed for ${subject}`,
        stderr || stdout || `exit status ${command.status}`,
      ].join(": "),
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(command.stdout);
  } catch (error) {
    throw new Error(
      `failed to parse gh attestation verify output for ${subject}: ${error.message}`,
    );
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error(`gh attestation verify returned no attestations for ${subject}`);
  }

  const matched = parsed
    .flatMap((entry) =>
      Array.isArray(entry?.verificationResult?.statement?.subject)
        ? entry.verificationResult.statement.subject.map((subjectEntry) => ({
            predicateType: entry?.verificationResult?.statement?.predicateType ?? null,
            name: subjectEntry?.name ?? null,
            sha256: subjectEntry?.digest?.sha256 ?? null,
          }))
        : [],
    )
    .find((entry) => entry.sha256 === sha256);

  if (!matched) {
    throw new Error(
      `verified attestation output did not include sha256 ${sha256} for ${subject}`,
    );
  }

  return {
    verified: true,
    verifiedAt: new Date().toISOString(),
    repo: options.repo,
    signerWorkflow: options.signerWorkflow,
    subjectPath: options.subjectPath,
    subjectSha256: sha256,
    attestedSubjectName: matched.name,
    attestedSubjectBasename: matched.name ? basename(matched.name) : null,
    predicateType: matched.predicateType,
    verificationCount: parsed.length,
  };
}

function sha256File(path) {
  const digest = createHash("sha256");
  digest.update(readFileSync(path));
  return digest.digest("hex");
}
