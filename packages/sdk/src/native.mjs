import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const nativePath = fileURLToPath(
  new URL("../privacy_pools_sdk_node.node", import.meta.url),
);

export const native = require(nativePath);
