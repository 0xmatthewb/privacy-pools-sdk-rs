const BROWSER_UNAVAILABLE_MESSAGE =
  "Browser proving support is still in progress. The Rust web binding foundation exists, but the browser prover backend is not ready yet.";

function capabilities() {
  return {
    runtime: "browser-worker",
    provingAvailable: false,
    verificationAvailable: false,
    workerAvailable: true,
    reason: BROWSER_UNAVAILABLE_MESSAGE,
  };
}

self.onmessage = (event) => {
  const { id, method } = event.data ?? {};
  if (method === "getRuntimeCapabilities") {
    self.postMessage({ id, ok: true, result: capabilities() });
    return;
  }

  self.postMessage({
    id,
    ok: false,
    error: BROWSER_UNAVAILABLE_MESSAGE,
  });
};
