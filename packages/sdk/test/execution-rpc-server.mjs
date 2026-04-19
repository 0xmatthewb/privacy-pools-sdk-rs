import { createExecutionRpcFixtureServer } from "./execution-fixture.mjs";

const options = JSON.parse(process.argv[2] ?? "{}");
const server = createExecutionRpcFixtureServer(options);

await server.start();
process.stdout.write(`${JSON.stringify({ url: server.url })}\n`);

let stopping = false;
async function stopAndExit(code) {
  if (stopping) {
    return;
  }
  stopping = true;
  try {
    await server.stop();
  } finally {
    process.exit(code);
  }
}

process.on("SIGINT", () => {
  void stopAndExit(0);
});
process.on("SIGTERM", () => {
  void stopAndExit(0);
});
