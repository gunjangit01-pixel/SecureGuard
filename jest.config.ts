import type { Config } from "jest";

const config: Config = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/__tests__/**/*.test.ts"],
  moduleNameMapper: {
    // Alias @/* → root, matching tsconfig paths
    "^@/(.*)$": "<rootDir>/$1",
  },
  transform: {
    "^.+\\.tsx?$": ["ts-jest", { tsconfig: { module: "commonjs" } }],
  },
  // Don't transpile node_modules except next/server (needed for NextRequest/NextResponse)
  transformIgnorePatterns: ["node_modules/(?!(next)/)"],
};

export default config;
