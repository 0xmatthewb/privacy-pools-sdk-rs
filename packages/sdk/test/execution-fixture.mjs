import { createServer } from "node:http";

import {
  decodeFunctionData,
  encodeFunctionResult,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
} from "viem";
import { mnemonicToAccount } from "viem/accounts";

const POOL_ABI = [
  {
    type: "function",
    name: "ENTRYPOINT",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "currentRoot",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "currentRootIndex",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint32" }],
  },
  {
    type: "function",
    name: "roots",
    stateMutability: "view",
    inputs: [{ name: "index", type: "uint256" }],
    outputs: [{ type: "uint256" }],
  },
];

const ENTRYPOINT_ABI = [
  {
    type: "function",
    name: "latestRoot",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
];

export const EXECUTION_SIGNER_MNEMONIC =
  "test test test test test test test test test test test junk";
export const WRONG_EXECUTION_SIGNER_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ACCOUNT = mnemonicToAccount(EXECUTION_SIGNER_MNEMONIC);
const WRONG_ACCOUNT = mnemonicToAccount(WRONG_EXECUTION_SIGNER_MNEMONIC);
const POOL_BYTECODE = "0x60006000556001600055";
const ENTRYPOINT_BYTECODE = "0x60016000556002600055";

export const EXECUTION_FIXTURE = {
  chainId: 1,
  caller: ACCOUNT.address.toLowerCase(),
  poolAddress: "0x2222222222222222222222222222222222222222",
  entrypointAddress: "0x1111111111111111111111111111111111111111",
  poolBytecode: POOL_BYTECODE,
  entrypointBytecode: ENTRYPOINT_BYTECODE,
  poolCodeHash: keccak256(POOL_BYTECODE),
  entrypointCodeHash: keccak256(ENTRYPOINT_BYTECODE),
  estimatedGas: 210000n,
  nonce: 7n,
  gasPrice: 1_500_000_000n,
  transactionHash: `0x${"ab".repeat(32)}`,
  blockHash: `0x${"cd".repeat(32)}`,
  blockNumber: 128n,
  transactionIndex: 0n,
  gasUsed: 123456n,
};

export function strictExecutionPolicy() {
  return {
    expectedChainId: EXECUTION_FIXTURE.chainId,
    caller: EXECUTION_FIXTURE.caller,
    expectedPoolCodeHash: EXECUTION_FIXTURE.poolCodeHash,
    expectedEntrypointCodeHash: EXECUTION_FIXTURE.entrypointCodeHash,
    mode: "strict",
  };
}

export async function signFinalizedTransactionRequest(request) {
  return signFinalizedTransactionRequestWithAccount(ACCOUNT, request);
}

export async function signFinalizedTransactionRequestWithWrongSigner(request) {
  return signFinalizedTransactionRequestWithAccount(WRONG_ACCOUNT, request);
}

async function signFinalizedTransactionRequestWithAccount(account, request) {
  return account.signTransaction({
    to: request.to,
    nonce: request.nonce,
    chainId: request.chainId,
    gas: BigInt(request.gasLimit),
    value: BigInt(request.value),
    data: request.data,
    gasPrice: request.gasPrice ? BigInt(request.gasPrice) : undefined,
    maxFeePerGas: request.maxFeePerGas ? BigInt(request.maxFeePerGas) : undefined,
    maxPriorityFeePerGas: request.maxPriorityFeePerGas
      ? BigInt(request.maxPriorityFeePerGas)
      : undefined,
  });
}

export function buildMobileExecutionFixture({
  platform,
  validRpcUrl,
  wrongRootRpcUrl,
  signerUrl,
  wrongSignerUrl,
} = {}) {
  if (!platform || !["ios", "android"].includes(platform)) {
    throw new Error("buildMobileExecutionFixture requires platform ios|android");
  }
  for (const [key, value] of Object.entries({
    validRpcUrl,
    wrongRootRpcUrl,
    signerUrl,
    wrongSignerUrl,
  })) {
    if (!value) {
      throw new Error(`buildMobileExecutionFixture requires ${key}`);
    }
  }

  return {
    platform,
    validRpcUrl,
    wrongRootRpcUrl,
    signerUrl,
    wrongSignerUrl,
    expectedChainId: EXECUTION_FIXTURE.chainId,
    caller: EXECUTION_FIXTURE.caller,
    poolAddress: EXECUTION_FIXTURE.poolAddress,
    entrypointAddress: EXECUTION_FIXTURE.entrypointAddress,
    expectedPoolCodeHash: EXECUTION_FIXTURE.poolCodeHash,
    expectedEntrypointCodeHash: EXECUTION_FIXTURE.entrypointCodeHash,
  };
}

export function createExecutionRpcFixtureServer({
  stateRoot,
  aspRoot,
  rootHistory = [],
  bindHost = "127.0.0.1",
  publicHost = bindHost,
  port = 0,
} = {}) {
  if (stateRoot === undefined || aspRoot === undefined) {
    throw new Error(
      "createExecutionRpcFixtureServer requires explicit stateRoot and aspRoot fixture values",
    );
  }

  const requests = [];
  const rawTransactions = [];
  let lastSubmittedTransaction = null;
  let origin = "";

  const server = createServer(async (request, response) => {
    try {
      const body = await readJson(request);
      const payloads = Array.isArray(body) ? body : [body];
      const replies = await Promise.all(payloads.map((payload) =>
        handleRpcPayload(payload, {
          stateRoot: BigInt(stateRoot),
          aspRoot: BigInt(aspRoot),
          rootHistory: rootHistory.map((value) => BigInt(value)),
          requests,
          rawTransactions,
          setLastSubmittedTransaction(transaction) {
            lastSubmittedTransaction = transaction;
          },
          lastSubmittedTransaction,
        }),
      ));
      const replyBody = Array.isArray(body) ? replies : replies[0];
      response.statusCode = 200;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(replyBody));
    } catch (error) {
      response.statusCode = 500;
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32000, message: String(error.message ?? error) },
        }),
      );
    }
  });

  return {
    get url() {
      return origin;
    },
    requests,
    rawTransactions,
    async start() {
      await listen(server, port, bindHost);
      const address = server.address();
      origin = `http://${publicHost}:${address.port}`;
    },
    async stop() {
      await close(server);
    },
  };
}

export function createExecutionSignerFixtureServer({
  wrongSigner = false,
  bindHost = "127.0.0.1",
  publicHost = bindHost,
  port = 0,
} = {}) {
  let origin = "";

  const server = createServer(async (request, response) => {
    try {
      if (request.method !== "POST") {
        response.statusCode = 405;
        response.end("method not allowed");
        return;
      }
      const requestJson = await readJson(request);
      const signedTransaction = wrongSigner
        ? await signFinalizedTransactionRequestWithWrongSigner(requestJson)
        : await signFinalizedTransactionRequest(requestJson);
      response.statusCode = 200;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ signedTransaction }));
    } catch (error) {
      response.statusCode = 500;
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          error: String(error?.message ?? error),
        }),
      );
    }
  });

  return {
    get url() {
      return origin;
    },
    async start() {
      await listen(server, port, bindHost);
      const address = server.address();
      origin = `http://${publicHost}:${address.port}`;
    },
    async stop() {
      await close(server);
    },
  };
}

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function handleRpcPayload(
  payload,
  {
    stateRoot,
    aspRoot,
    rootHistory,
    requests,
    rawTransactions,
    setLastSubmittedTransaction,
    lastSubmittedTransaction,
  },
) {
  const { id = null, method, params = [] } = payload ?? {};
  requests.push({ method, params });

  try {
    switch (method) {
      case "eth_chainId":
        return ok(id, hexQuantity(BigInt(EXECUTION_FIXTURE.chainId)));
      case "eth_getCode":
        return ok(
          id,
          bytecodeForAddress(params[0] ?? "0x0000000000000000000000000000000000000000"),
        );
      case "eth_call":
        return ok(id, handleEthCall(params[0] ?? {}, { stateRoot, aspRoot, rootHistory }));
      case "eth_estimateGas":
        return ok(id, hexQuantity(EXECUTION_FIXTURE.estimatedGas));
      case "eth_getTransactionCount":
        return ok(id, hexQuantity(EXECUTION_FIXTURE.nonce));
      case "eth_feeHistory":
      case "eth_maxPriorityFeePerGas":
        return error(id, -32000, `${method} unsupported in execution test fixture`);
      case "eth_gasPrice":
        return ok(id, hexQuantity(EXECUTION_FIXTURE.gasPrice));
      case "eth_sendRawTransaction": {
        const signedTransaction = String(params[0] ?? "0x");
        rawTransactions.push(signedTransaction);
        setLastSubmittedTransaction({
          parsed: parseTransaction(signedTransaction),
          from: await recoverTransactionAddress({
            serializedTransaction: signedTransaction,
          }),
        });
        return ok(id, EXECUTION_FIXTURE.transactionHash);
      }
      case "eth_getTransactionReceipt":
        return ok(id, {
          transactionHash: EXECUTION_FIXTURE.transactionHash,
          transactionIndex: hexQuantity(EXECUTION_FIXTURE.transactionIndex),
          blockHash: EXECUTION_FIXTURE.blockHash,
          blockNumber: hexQuantity(EXECUTION_FIXTURE.blockNumber),
          from: lastSubmittedTransaction?.from ?? EXECUTION_FIXTURE.caller,
          to:
            lastSubmittedTransaction?.parsed.to ??
            EXECUTION_FIXTURE.poolAddress,
          cumulativeGasUsed: hexQuantity(EXECUTION_FIXTURE.gasUsed),
          gasUsed: hexQuantity(EXECUTION_FIXTURE.gasUsed),
          contractAddress: null,
          logs: [],
          logsBloom: `0x${"0".repeat(512)}`,
          status: "0x1",
          effectiveGasPrice: hexQuantity(EXECUTION_FIXTURE.gasPrice),
          type: "0x0",
        });
      case "eth_blockNumber":
        return ok(id, hexQuantity(EXECUTION_FIXTURE.blockNumber));
      case "eth_getBlockByNumber":
        if ((params[0] ?? "").toString().toLowerCase() === "latest" && rawTransactions.length === 0) {
          return error(id, -32000, "latest block fee data unsupported in execution test fixture");
        }
        return ok(id, {
          hash: EXECUTION_FIXTURE.blockHash,
          number: hexQuantity(EXECUTION_FIXTURE.blockNumber),
          baseFeePerGas: hexQuantity(1n),
          timestamp: hexQuantity(1n),
          transactions: [EXECUTION_FIXTURE.transactionHash],
        });
      case "eth_getTransactionByHash":
        return ok(id, {
          hash: EXECUTION_FIXTURE.transactionHash,
          nonce: hexQuantity(
            BigInt(
              lastSubmittedTransaction?.parsed.nonce ?? EXECUTION_FIXTURE.nonce,
            ),
          ),
          blockHash: EXECUTION_FIXTURE.blockHash,
          blockNumber: hexQuantity(EXECUTION_FIXTURE.blockNumber),
          transactionIndex: hexQuantity(EXECUTION_FIXTURE.transactionIndex),
          from: lastSubmittedTransaction?.from ?? EXECUTION_FIXTURE.caller,
          to:
            lastSubmittedTransaction?.parsed.to ??
            EXECUTION_FIXTURE.poolAddress,
          value: hexQuantity(lastSubmittedTransaction?.parsed.value ?? 0n),
          gas: hexQuantity(
            lastSubmittedTransaction?.parsed.gas ?? EXECUTION_FIXTURE.estimatedGas,
          ),
          gasPrice: hexQuantity(
            lastSubmittedTransaction?.parsed.gasPrice ??
              lastSubmittedTransaction?.parsed.maxFeePerGas ??
              EXECUTION_FIXTURE.gasPrice,
          ),
          input: lastSubmittedTransaction?.parsed.data ?? "0x",
          chainId: hexQuantity(
            BigInt(
              lastSubmittedTransaction?.parsed.chainId ?? EXECUTION_FIXTURE.chainId,
            ),
          ),
          type:
            lastSubmittedTransaction?.parsed.type === "eip1559" ? "0x2" : "0x0",
          v: "0x1b",
          r: `0x${"11".repeat(32)}`,
          s: `0x${"22".repeat(32)}`,
        });
      default:
        return error(id, -32601, `unsupported rpc method: ${method}`);
    }
  } catch (rpcError) {
    return error(id, -32000, String(rpcError.message ?? rpcError));
  }
}

function handleEthCall(call, { stateRoot, aspRoot, rootHistory }) {
  const to = normalizeAddress(call.to ?? "0x0000000000000000000000000000000000000000");
  const data = String(call.data ?? "0x");

  if (to === EXECUTION_FIXTURE.poolAddress) {
    try {
      const decoded = decodeFunctionData({ abi: POOL_ABI, data });
      switch (decoded.functionName) {
        case "ENTRYPOINT":
          return encodeFunctionResult({
            abi: POOL_ABI,
            functionName: "ENTRYPOINT",
            result: [EXECUTION_FIXTURE.entrypointAddress],
          });
        case "currentRoot":
          return encodeFunctionResult({
            abi: POOL_ABI,
            functionName: "currentRoot",
            result: [stateRoot],
          });
        case "currentRootIndex":
          return encodeFunctionResult({
            abi: POOL_ABI,
            functionName: "currentRootIndex",
            result: [0],
          });
        case "roots": {
          const index = Number(decoded.args?.[0] ?? 0n);
          const historicalRoot = rootHistory[index] ?? stateRoot;
          return encodeFunctionResult({
            abi: POOL_ABI,
            functionName: "roots",
            result: [historicalRoot],
          });
        }
        default:
          return "0x";
      }
    } catch {
      return "0x";
    }
  }

  if (to === EXECUTION_FIXTURE.entrypointAddress) {
    try {
      const decoded = decodeFunctionData({ abi: ENTRYPOINT_ABI, data });
      if (decoded.functionName === "latestRoot") {
        return encodeFunctionResult({
          abi: ENTRYPOINT_ABI,
          functionName: "latestRoot",
          result: [aspRoot],
        });
      }
    } catch {
      return "0x";
    }
  }

  return "0x";
}

function bytecodeForAddress(address) {
  const normalized = normalizeAddress(address);
  if (normalized === EXECUTION_FIXTURE.poolAddress) {
    return EXECUTION_FIXTURE.poolBytecode;
  }
  if (normalized === EXECUTION_FIXTURE.entrypointAddress) {
    return EXECUTION_FIXTURE.entrypointBytecode;
  }
  return "0x";
}

function normalizeAddress(value) {
  return `0x${String(value).slice(2).toLowerCase()}`;
}

function hexQuantity(value) {
  return `0x${BigInt(value).toString(16)}`;
}

function ok(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function error(id, code, message) {
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message },
  };
}

async function listen(server, port, host) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

async function close(server) {
  await new Promise((resolve, reject) =>
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    }),
  );
}
