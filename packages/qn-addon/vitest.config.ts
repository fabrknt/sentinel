import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    testTimeout: 10000,
    env: {
      NODE_ENV: "test",
      DB_PATH: ":memory:",
      QN_BASIC_AUTH_USERNAME: "testuser",
      QN_BASIC_AUTH_PASSWORD: "testpass",
    },
  },
});
