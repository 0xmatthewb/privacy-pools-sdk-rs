import {
  dangerouslyExportCommitmentPreimage,
  dangerouslyExportFinalizedPreflightedTransaction,
  dangerouslyExportMasterKeys,
  dangerouslyExportPreflightedTransaction,
  dangerouslyExportSecret,
  dangerouslyExportSubmittedPreflightedTransaction,
} from "./runtime.mjs";

export {
  dangerouslyExportCommitmentPreimage,
  dangerouslyExportFinalizedPreflightedTransaction,
  dangerouslyExportMasterKeys,
  dangerouslyExportPreflightedTransaction,
  dangerouslyExportSecret,
  dangerouslyExportSubmittedPreflightedTransaction,
};

export function createWorkerDebugClient(worker) {
  return new WorkerDangerousExportClient(worker);
}

class WorkerDangerousExportClient {
  #worker;
  #nextId = 1;
  #pending = new Map();

  constructor(worker) {
    this.#worker = worker;
    const onMessage = (message) => {
      const pending = this.#pending.get(message?.id);
      if (!pending || message?.status) {
        return;
      }

      this.#pending.delete(message.id);
      if (message.ok) {
        pending.resolve(message.result);
        return;
      }

      pending.reject(deserializeWorkerError(message.error));
    };

    if (typeof worker?.addEventListener === "function") {
      worker.addEventListener("message", (event) => onMessage(event.data));
      return;
    }

    if (typeof worker?.on === "function") {
      worker.on("message", onMessage);
      return;
    }

    throw new Error("worker debug client requires a Worker-compatible transport");
  }

  dangerouslyExportMasterKeys(handle) {
    return this.#send("dangerouslyExportMasterKeys", [handle]);
  }

  dangerouslyExportCommitmentPreimage(handle) {
    return this.#send("dangerouslyExportCommitmentPreimage", [handle]);
  }

  dangerouslyExportSecret(handle) {
    return this.#send("dangerouslyExportSecret", [handle]);
  }

  dangerouslyExportPreflightedTransaction(handle) {
    return this.#send("dangerouslyExportPreflightedTransaction", [handle]);
  }

  dangerouslyExportFinalizedPreflightedTransaction(handle) {
    return this.#send("dangerouslyExportFinalizedPreflightedTransaction", [handle]);
  }

  dangerouslyExportSubmittedPreflightedTransaction(handle) {
    return this.#send("dangerouslyExportSubmittedPreflightedTransaction", [handle]);
  }

  #send(method, params = []) {
    const id = `debug-${this.#nextId++}`;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#worker.postMessage({ id, method, params });
    });
  }
}

function deserializeWorkerError(error) {
  const instance = new Error(error?.message ?? String(error ?? "worker error"));
  instance.name = error?.name ?? "Error";
  return instance;
}
