const BROWSER_UNAVAILABLE_MESSAGE =
  "Browser proving support is still in progress. The Rust web binding foundation exists, but the browser prover backend is not ready yet.";

export function getRuntimeCapabilities() {
  return {
    runtime: "browser",
    provingAvailable: false,
    verificationAvailable: false,
    workerAvailable: true,
    reason: BROWSER_UNAVAILABLE_MESSAGE,
  };
}

export class BrowserRuntimeUnavailableError extends Error {
  constructor(message = BROWSER_UNAVAILABLE_MESSAGE) {
    super(message);
    this.name = "BrowserRuntimeUnavailableError";
  }
}

export class PrivacyPoolsSdkClient {
  async getVersion() {
    throw new BrowserRuntimeUnavailableError();
  }

  async getStableBackendName() {
    throw new BrowserRuntimeUnavailableError();
  }

  async fastBackendSupportedOnTarget() {
    throw new BrowserRuntimeUnavailableError();
  }

  async deriveMasterKeys() {
    throw new BrowserRuntimeUnavailableError();
  }

  async deriveDepositSecrets() {
    throw new BrowserRuntimeUnavailableError();
  }

  async deriveWithdrawalSecrets() {
    throw new BrowserRuntimeUnavailableError();
  }

  async getCommitment() {
    throw new BrowserRuntimeUnavailableError();
  }

  async calculateWithdrawalContext() {
    throw new BrowserRuntimeUnavailableError();
  }

  async generateMerkleProof() {
    throw new BrowserRuntimeUnavailableError();
  }

  async buildCircuitMerkleWitness() {
    throw new BrowserRuntimeUnavailableError();
  }

  async buildWithdrawalCircuitInput() {
    throw new BrowserRuntimeUnavailableError();
  }

  async getArtifactStatuses() {
    throw new BrowserRuntimeUnavailableError();
  }

  async resolveVerifiedArtifactBundle() {
    throw new BrowserRuntimeUnavailableError();
  }

  async verifyArtifactBytes() {
    throw new BrowserRuntimeUnavailableError();
  }

  async prepareWithdrawalCircuitSession() {
    throw new BrowserRuntimeUnavailableError();
  }

  async prepareWithdrawalCircuitSessionFromBytes() {
    throw new BrowserRuntimeUnavailableError();
  }

  async removeWithdrawalCircuitSession() {
    throw new BrowserRuntimeUnavailableError();
  }

  async proveWithdrawal() {
    throw new BrowserRuntimeUnavailableError();
  }

  async proveWithdrawalWithSession() {
    throw new BrowserRuntimeUnavailableError();
  }

  async verifyWithdrawalProof() {
    throw new BrowserRuntimeUnavailableError();
  }

  async verifyWithdrawalProofWithSession() {
    throw new BrowserRuntimeUnavailableError();
  }
}

export function createPrivacyPoolsSdkClient() {
  return new PrivacyPoolsSdkClient();
}

export function createWorkerClient(worker) {
  return new WorkerPrivacyPoolsSdkClient(worker);
}

class WorkerPrivacyPoolsSdkClient {
  #worker;
  #nextId = 1;
  #pending = new Map();

  constructor(worker) {
    this.#worker = worker;
    this.#worker.addEventListener("message", (event) => {
      const message = event.data ?? {};
      const pending = this.#pending.get(message.id);
      if (!pending) {
        return;
      }
      this.#pending.delete(message.id);
      if (message.ok) {
        pending.resolve(message.result);
      } else {
        pending.reject(
          new BrowserRuntimeUnavailableError(
            message.error ?? BROWSER_UNAVAILABLE_MESSAGE,
          ),
        );
      }
    });
  }

  async getRuntimeCapabilities() {
    return this.#send("getRuntimeCapabilities");
  }

  async deriveMasterKeys(mnemonic) {
    return this.#send("deriveMasterKeys", { mnemonic });
  }

  async proveWithdrawal(...args) {
    return this.#send("proveWithdrawal", args);
  }

  async verifyWithdrawalProof(...args) {
    return this.#send("verifyWithdrawalProof", args);
  }

  #send(method, params = null) {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#worker.postMessage({ id, method, params });
    });
  }
}
