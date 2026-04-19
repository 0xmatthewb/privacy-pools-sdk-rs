import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";

const options = parseArgs(process.argv.slice(2));

mkdirSync(dirname(options.out), { recursive: true });

const records = options.subjects.map((subjectPath) => {
  const absoluteSubject = resolve(subjectPath);
  const stats = statSync(absoluteSubject);
  if (!stats.isFile()) {
    throw new Error(`attestation subject must be a file: ${absoluteSubject}`);
  }

  const relativeSubject = relative(options.stripPrefix, absoluteSubject);
  if (
    !relativeSubject ||
    relativeSubject.startsWith("..") ||
    relativeSubject.includes(`..${process.platform === "win32" ? "\\\\" : "/"}`)
  ) {
    throw new Error(
      `subject ${absoluteSubject} is not contained by strip prefix ${options.stripPrefix}`,
    );
  }

  return {
    subjectPath: join(options.targetPrefix, relativeSubject).replaceAll("\\", "/"),
    sha256: sha256File(absoluteSubject),
    attestationUrl: options.attestationUrl,
    workflowRunUrl: options.workflowRunUrl,
    verificationPath: join(
      options.verificationPrefix,
      `${basename(relativeSubject)}.verified.json`,
    ).replaceAll("\\", "/"),
  };
});

writeFileSync(options.out, `${JSON.stringify(records, null, 2)}\n`);

function parseArgs(rawArgs) {
  const parsed = {
    out: "",
    stripPrefix: "",
    targetPrefix: "",
    attestationUrl: "",
    workflowRunUrl: "",
    verificationPrefix: "",
    subjects: [],
  };

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    switch (arg) {
      case "--out":
        parsed.out = resolve(rawArgs[++index] ?? "");
        break;
      case "--strip-prefix":
        parsed.stripPrefix = resolve(rawArgs[++index] ?? "");
        break;
      case "--target-prefix":
        parsed.targetPrefix = (rawArgs[++index] ?? "").replaceAll("\\", "/").replace(/\/+$/, "");
        break;
      case "--attestation-url":
        parsed.attestationUrl = rawArgs[++index] ?? "";
        break;
      case "--workflow-run-url":
        parsed.workflowRunUrl = rawArgs[++index] ?? "";
        break;
      case "--verification-prefix":
        parsed.verificationPrefix = (rawArgs[++index] ?? "")
          .replaceAll("\\", "/")
          .replace(/^\/+/, "")
          .replace(/\/+$/, "");
        break;
      case "--subject":
        parsed.subjects.push(rawArgs[++index] ?? "");
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!parsed.out) {
    throw new Error("--out is required");
  }
  if (!parsed.stripPrefix) {
    throw new Error("--strip-prefix is required");
  }
  if (!parsed.targetPrefix) {
    throw new Error("--target-prefix is required");
  }
  if (!parsed.attestationUrl) {
    throw new Error("--attestation-url is required");
  }
  if (!parsed.workflowRunUrl) {
    throw new Error("--workflow-run-url is required");
  }
  if (!parsed.verificationPrefix) {
    throw new Error("--verification-prefix is required");
  }
  if (parsed.subjects.length === 0) {
    throw new Error("at least one --subject is required");
  }

  return parsed;
}

function sha256File(path) {
  const digest = createHash("sha256");
  digest.update(readFileSync(path));
  return digest.digest("hex");
}
