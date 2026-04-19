import {
  TESTING_SURFACE_DISABLED_ERROR,
  TESTING_SURFACE_ENABLED,
} from "./build-flags";

if (!TESTING_SURFACE_ENABLED) {
  throw new Error(TESTING_SURFACE_DISABLED_ERROR);
}

export * from "./index";
