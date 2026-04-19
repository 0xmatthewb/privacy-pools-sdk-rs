import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const testDir = fileURLToPath(new URL(".", import.meta.url));
export const workspaceRoot = join(testDir, "..", "..", "..");
export const fixturesRoot = join(workspaceRoot, "fixtures");

export function readFixtureText(relativePath) {
  return readFileSync(join(fixturesRoot, relativePath), "utf8");
}

export function readFixtureJson(relativePath) {
  return JSON.parse(readFixtureText(relativePath));
}

export function createFixtureServer(options = {}) {
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const filename = url.pathname.replace(/^\/+/, "");
    try {
      let bytes = options.overrides?.get(filename) ?? readFileSync(join(fixturesRoot, filename));
      if (options.mutate) {
        bytes = Buffer.from(options.mutate(filename, bytes) ?? bytes);
      }
      response.statusCode = 200;
      response.setHeader("content-type", "application/octet-stream");
      response.end(bytes);
    } catch {
      response.statusCode = 404;
      response.end("not found");
    }
  });

  return {
    rootUrl: "",
    async start() {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      this.rootUrl = `http://127.0.0.1:${address.port}/artifacts/`;
    },
    async stop() {
      await new Promise((resolve, reject) =>
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        }),
      );
    },
  };
}

export function manifestArtifactFilenames(...manifestJsonTexts) {
  return [...new Set(
    manifestJsonTexts.flatMap((manifestJson) => {
      const manifest = JSON.parse(manifestJson);
      return Array.isArray(manifest.artifacts)
        ? manifest.artifacts.map((artifact) => `artifacts/${artifact.filename}`)
        : [];
    }),
  )].sort();
}

export function manifestArtifactFixturePaths(...manifestJsonTexts) {
  return manifestArtifactFilenames(...manifestJsonTexts).map((filename) =>
    join(fixturesRoot, filename),
  );
}

export function assertFixtureFilesExist(...paths) {
  for (const path of paths) {
    if (!existsSync(path)) {
      throw new Error(`missing browser fixture file: ${path}`);
    }
  }
}

export function preflightFixtureArtifacts(...manifestJsonTexts) {
  assertFixtureFilesExist(...manifestArtifactFixturePaths(...manifestJsonTexts));
}

export function readManifestArtifactBytes(manifestJson) {
  const manifest = JSON.parse(manifestJson);
  return manifest.artifacts.map((artifact) => ({
    kind: artifact.kind,
    bytes: readFileSync(join(fixturesRoot, "artifacts", artifact.filename)),
  }));
}

export async function assertFixtureServerArtifacts(rootUrl, ...manifestJsonTexts) {
  for (const filename of manifestArtifactFilenames(...manifestJsonTexts)) {
    const url = new URL(filename.replace(/^artifacts\//, ""), rootUrl);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`missing browser artifact: ${url}`);
    }
  }
}
