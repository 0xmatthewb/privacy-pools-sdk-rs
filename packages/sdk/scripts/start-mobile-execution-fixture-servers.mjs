import {
  buildMobileExecutionFixture,
  createExecutionRpcFixtureServer,
  createExecutionSignerFixtureServer,
} from "../test/execution-fixture.mjs";

const options = parseArgs(process.argv.slice(2));

const validRpcServer = createExecutionRpcFixtureServer({
  stateRoot: options.stateRoot,
  aspRoot: options.aspRoot,
  bindHost: options.bindHost,
  publicHost: options.publicHost,
});
const wrongRootRpcServer = createExecutionRpcFixtureServer({
  stateRoot: options.wrongRootStateRoot,
  aspRoot: options.aspRoot,
  bindHost: options.bindHost,
  publicHost: options.publicHost,
});
const signerServer = createExecutionSignerFixtureServer({
  bindHost: options.bindHost,
  publicHost: options.publicHost,
});
const wrongSignerServer = createExecutionSignerFixtureServer({
  wrongSigner: true,
  bindHost: options.bindHost,
  publicHost: options.publicHost,
});

await Promise.all([
  validRpcServer.start(),
  wrongRootRpcServer.start(),
  signerServer.start(),
  wrongSignerServer.start(),
]);

process.stdout.write(
  `${JSON.stringify(
    buildMobileExecutionFixture({
      platform: options.platform,
      validRpcUrl: validRpcServer.url,
      wrongRootRpcUrl: wrongRootRpcServer.url,
      signerUrl: signerServer.url,
      wrongSignerUrl: wrongSignerServer.url,
    }),
  )}\n`,
);

let stopping = false;
async function stopAndExit(code) {
  if (stopping) {
    return;
  }
  stopping = true;
  await Promise.allSettled([
    validRpcServer.stop(),
    wrongRootRpcServer.stop(),
    signerServer.stop(),
    wrongSignerServer.stop(),
  ]);
  process.exit(code);
}

process.on("SIGINT", () => {
  void stopAndExit(0);
});
process.on("SIGTERM", () => {
  void stopAndExit(0);
});

function parseArgs(rawArgs) {
  const parsed = {
    platform: "",
    bindHost: "127.0.0.1",
    publicHost: "127.0.0.1",
    stateRoot: "",
    aspRoot: "",
    wrongRootStateRoot: "999",
  };

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    switch (arg) {
      case "--platform":
        parsed.platform = rawArgs[++index] ?? "";
        break;
      case "--bind-host":
        parsed.bindHost = rawArgs[++index] ?? "";
        break;
      case "--public-host":
        parsed.publicHost = rawArgs[++index] ?? "";
        break;
      case "--state-root":
        parsed.stateRoot = rawArgs[++index] ?? "";
        break;
      case "--asp-root":
        parsed.aspRoot = rawArgs[++index] ?? "";
        break;
      case "--wrong-root-state-root":
        parsed.wrongRootStateRoot = rawArgs[++index] ?? "";
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  for (const key of [
    "platform",
    "bindHost",
    "publicHost",
    "stateRoot",
    "aspRoot",
    "wrongRootStateRoot",
  ]) {
    if (!parsed[key]) {
      throw new Error(`${key} is required`);
    }
  }

  return parsed;
}
