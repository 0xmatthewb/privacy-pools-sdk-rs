import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./test",
  testMatch: /.*\.playwright\.mjs/,
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 2 : 0,
  forbidOnly: !!process.env.CI,
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    browserName: "chromium",
  },
});
