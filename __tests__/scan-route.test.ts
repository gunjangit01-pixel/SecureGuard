/**
 * __tests__/scan-route.test.ts
 *
 * Unit + integration tests for the OSV Scanner API route.
 * Run:  npx jest
 */

// ─── child_process mock ───────────────────────────────────────────────────────
const mockExecFn = jest.fn();
jest.mock("child_process", () => ({ exec: mockExecFn }));

// promisify mock: wraps our mockExecFn into a promise-based function
jest.mock("util", () => ({
  promisify: (fn: unknown) => {
    if (fn === mockExecFn) {
      return async (cmd: string, opts: unknown) =>
        new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
          mockExecFn(cmd, opts, (err: unknown, stdout: string, stderr: string) => {
            if (err) {
              const error = err as { stdout?: string; stderr?: string; message?: string };
              reject(
                Object.assign(new Error(error.message ?? "exec error"), {
                  stdout: error.stdout ?? stdout ?? "",
                  stderr: error.stderr ?? stderr ?? "",
                })
              );
            } else {
              resolve({ stdout, stderr });
            }
          });
        });
    }
    return fn;
  },
}));

// ─── fs mock ──────────────────────────────────────────────────────────────────
jest.mock("fs", () => ({
  existsSync: jest.fn(() => true),
  mkdirSync: jest.fn(),
  rmSync: jest.fn(),
}));

// ─── os mock ──────────────────────────────────────────────────────────────────
jest.mock("os", () => ({ tmpdir: () => "C:\\Temp" }));

// ─── crypto mock ──────────────────────────────────────────────────────────────
jest.mock("crypto", () => ({
  randomBytes: () => ({ toString: () => "abc123" }),
}));

// ─── next/server mock ─────────────────────────────────────────────────────────
jest.mock("next/server", () => {
  class MockNextRequest {
    private _body: unknown;
    __setBody(b: unknown) { this._body = b; }
    async json() {
      if (this._body === undefined) throw new SyntaxError("No body");
      return this._body;
    }
  }
  return {
    NextRequest: MockNextRequest,
    NextResponse: {
      json(data: unknown, init?: { status?: number }) {
        return {
          _data: data,
          _status: init?.status ?? 200,
          async json() { return data; },
        };
      },
    },
  };
});

// ─── Imports ──────────────────────────────────────────────────────────────────
import * as fs from "fs";
import * as pathModule from "path";
import * as routeModule from "../app/api/scan/route";

const mockExistsSync = fs.existsSync as jest.MockedFunction<typeof fs.existsSync>;

// ─── Request helper ───────────────────────────────────────────────────────────
function makeRequest(body: unknown) {
  const { NextRequest } = jest.requireMock("next/server");
  const req = new NextRequest("http://localhost/api/scan");
  req.__setBody(body);
  return req as unknown as import("next/server").NextRequest;
}

// ─── exec helpers ─────────────────────────────────────────────────────────────
function execOk(stdout: string, stderr = "") {
  mockExecFn.mockImplementation(
    (_cmd: unknown, _opts: unknown, cb: (e: null, o: string, s: string) => void) =>
      cb(null, stdout, stderr)
  );
}

function execFailWithStdout(stdout: string, message = "exit 1") {
  mockExecFn.mockImplementation(
    (_cmd: unknown, _opts: unknown, cb: (e: unknown, o: string, s: string) => void) =>
      cb({ message, stdout, stderr: "" }, stdout, "")
  );
}

function execFailEmpty(message = "command not found") {
  mockExecFn.mockImplementation(
    (_cmd: unknown, _opts: unknown, cb: (e: unknown, o: string, s: string) => void) =>
      cb({ message, stdout: "", stderr: message }, "", message)
  );
}

// ─── OSV payload builders ─────────────────────────────────────────────────────
interface VulnDef {
  id: string;
  dbSeverity?: string;
  cvssScore?: number;
  cvssType?: "CVSS_V3" | "CVSS_V2";
  fixed?: string;
  summary?: string;
}

function buildVuln(def: VulnDef, pkgName: string) {
  return {
    id: def.id,
    summary: def.summary ?? "",
    database_specific: def.dbSeverity ? { severity: def.dbSeverity } : {},
    severity:
      def.cvssScore !== undefined
        ? [{ type: def.cvssType ?? "CVSS_V3", score: String(def.cvssScore) }]
        : [],
    affected: def.fixed
      ? [{ package: { name: pkgName, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: def.fixed }] }] }]
      : [],
  };
}

function buildOsvJson(
  sourcePath: string,
  packages: Array<{ name: string; version?: string; vulns: VulnDef[] }>
): string {
  const pkgEntries = packages.map(({ name, version = "1.0.0", vulns }) => ({
    package: { name, version, ecosystem: "npm" },
    groups: [],
    vulnerabilities: vulns.map((v) => buildVuln(v, name)),
  }));
  return JSON.stringify({
    results: pkgEntries.length
      ? [{ source: { path: sourcePath, type: "lockfile" }, packages: pkgEntries }]
      : [],
    experimental_config: {},
  });
}

const DEFAULT_SOURCE = "D:\\project\\package-lock.json";

// ═════════════════════════════════════════════════════════════════════════════
// 1. isGitHubUrl
// ═════════════════════════════════════════════════════════════════════════════

describe("isGitHubUrl", () => {
  const { isGitHubUrl } = routeModule;

  test("recognises https github URL", () => {
    expect(isGitHubUrl("https://github.com/org/repo")).toBe(true);
  });
  test("recognises http github URL", () => {
    expect(isGitHubUrl("http://github.com/org/repo")).toBe(true);
  });
  test("recognises URL with .git suffix", () => {
    expect(isGitHubUrl("https://github.com/org/repo.git")).toBe(true);
  });
  test("recognises URL with sub-path", () => {
    expect(isGitHubUrl("https://github.com/org/repo/tree/main/src")).toBe(true);
  });
  test("rejects local path", () => {
    expect(isGitHubUrl("D:\\some\\path")).toBe(false);
  });
  test("rejects relative path", () => {
    expect(isGitHubUrl(".")).toBe(false);
  });
  test("rejects gitlab URL", () => {
    expect(isGitHubUrl("https://gitlab.com/org/repo")).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 2. normaliseGitHubUrl
// ═════════════════════════════════════════════════════════════════════════════

describe("normaliseGitHubUrl", () => {
  const { normaliseGitHubUrl } = routeModule;

  test("strips .git suffix", () => {
    expect(normaliseGitHubUrl("https://github.com/org/repo.git")).toBe("https://github.com/org/repo");
  });
  test("strips trailing slash", () => {
    expect(normaliseGitHubUrl("https://github.com/org/repo/")).toBe("https://github.com/org/repo");
  });
  test("strips sub-path (tree/main/...)", () => {
    expect(normaliseGitHubUrl("https://github.com/org/repo/tree/main/src")).toBe("https://github.com/org/repo");
  });
  test("leaves clean URL unchanged", () => {
    expect(normaliseGitHubUrl("https://github.com/org/repo")).toBe("https://github.com/org/repo");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 3. Severity normalisation
// ═════════════════════════════════════════════════════════════════════════════

describe("normaliseSeverity (exported)", () => {
  const { normaliseSeverity } = routeModule;

  const vuln = (dbSev?: string, cvss?: number, type = "CVSS_V3") => ({
    id: "CVE-TEST",
    database_specific: dbSev ? { severity: dbSev } : {},
    severity: cvss !== undefined ? [{ type, score: String(cvss) }] : [],
  });

  test("database_specific CRITICAL", () => expect(normaliseSeverity(vuln("CRITICAL"))).toBe("critical"));
  test("database_specific HIGH",     () => expect(normaliseSeverity(vuln("HIGH"))).toBe("high"));
  test("database_specific MEDIUM",   () => expect(normaliseSeverity(vuln("MEDIUM"))).toBe("medium"));
  test("database_specific LOW",      () => expect(normaliseSeverity(vuln("LOW"))).toBe("low"));
  test("CVSS 9.8 → critical",        () => expect(normaliseSeverity(vuln(undefined, 9.8))).toBe("critical"));
  test("CVSS 9.0 boundary → critical",() => expect(normaliseSeverity(vuln(undefined, 9.0))).toBe("critical"));
  test("CVSS 7.5 → high",            () => expect(normaliseSeverity(vuln(undefined, 7.5))).toBe("high"));
  test("CVSS 7.0 boundary → high",   () => expect(normaliseSeverity(vuln(undefined, 7.0))).toBe("high"));
  test("CVSS 5.0 → medium",          () => expect(normaliseSeverity(vuln(undefined, 5.0))).toBe("medium"));
  test("CVSS 4.0 boundary → medium", () => expect(normaliseSeverity(vuln(undefined, 4.0))).toBe("medium"));
  test("CVSS 2.1 → low",             () => expect(normaliseSeverity(vuln(undefined, 2.1))).toBe("low"));
  test("CVSS_V2 9.0 → critical",     () => expect(normaliseSeverity(vuln(undefined, 9.0, "CVSS_V2"))).toBe("critical"));
  test("no info → medium fallback",  () => expect(normaliseSeverity(vuln())).toBe("medium"));
});

// ═════════════════════════════════════════════════════════════════════════════
// 4. Fix extraction
// ═════════════════════════════════════════════════════════════════════════════

describe("extractFix (exported)", () => {
  const { extractFix } = routeModule;

  test("returns upgrade message when fixed version present", () => {
    const vuln = { id: "CVE-1", affected: [{ package: { name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] };
    expect(extractFix(vuln, "lodash")).toBe("Upgrade lodash to 4.17.21");
  });

  test("returns advisory fallback when no fixed version", () => {
    expect(extractFix({ id: "CVE-2" }, "axios")).toBe("Review advisory for fix details");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 5. Score computation
// ═════════════════════════════════════════════════════════════════════════════

describe("computeScore (exported)", () => {
  const { computeScore } = routeModule;

  test("0 vulns → 100", () => expect(computeScore(0, 0, 0, 0)).toBe(100));
  test("1 critical → 75", () => expect(computeScore(1, 0, 0, 0)).toBe(75));
  test("1 high → 90",    () => expect(computeScore(0, 1, 0, 0)).toBe(90));
  test("1 medium → 96",  () => expect(computeScore(0, 0, 1, 0)).toBe(96));
  test("1 low → 99",     () => expect(computeScore(0, 0, 0, 1)).toBe(99));
  test("floors at 0",    () => expect(computeScore(10, 0, 0, 0)).toBe(0));
  test("1C+1H+1M+1L = 60", () => expect(computeScore(1, 1, 1, 1)).toBe(60));
});

// ═════════════════════════════════════════════════════════════════════════════
// 6. Path validation
// ═════════════════════════════════════════════════════════════════════════════

describe("Path validation (POST handler)", () => {
  beforeEach(() => { jest.clearAllMocks(); });

  test("returns 500 when path does not exist on disk", async () => {
    mockExistsSync.mockReturnValue(false);
    const res = await routeModule.POST(makeRequest({ path: "D:\\no\\such\\path" }));
    expect(res._status).toBe(500);
    const data = await res.json() as { error: string };
    expect(data.error).toMatch(/not found/i);
  });

  test("valid existing path → 200 ok", async () => {
    mockExistsSync.mockReturnValue(true);
    execOk(buildOsvJson(DEFAULT_SOURCE, []));
    const res = await routeModule.POST(makeRequest({ path: "D:\\UCOHACK\\SecureGuard" }));
    expect(res._status).toBe(200);
    const data = await res.json() as { ok: boolean };
    expect(data.ok).toBe(true);
  });

  test("defaults to cwd when no path key", async () => {
    mockExistsSync.mockReturnValue(true);
    execOk(buildOsvJson(DEFAULT_SOURCE, []));
    const res = await routeModule.POST(makeRequest({}));
    const data = await res.json() as { scannedPath: string };
    expect(data.scannedPath).toBe(pathModule.resolve("."));
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 7. GitHub URL cloning
// ═════════════════════════════════════════════════════════════════════════════

describe("GitHub URL scanning (POST handler)", () => {
  beforeEach(() => { jest.clearAllMocks(); mockExistsSync.mockReturnValue(true); });

  test("clones then scans when a GitHub URL is provided", async () => {
    // First exec call = git clone (succeeds), second = osv-scanner
    mockExecFn
      .mockImplementationOnce(
        (_cmd: unknown, _opts: unknown, cb: (e: null, o: string, s: string) => void) =>
          cb(null, "", "")
      )
      .mockImplementationOnce(
        (_cmd: unknown, _opts: unknown, cb: (e: null, o: string, s: string) => void) =>
          cb(null, buildOsvJson("C:\\Temp\\secureguard-clone-abc123\\package-lock.json", []), "")
      );

    const res = await routeModule.POST(makeRequest({ path: "https://github.com/org/bankrepo" }));
    expect(res._status).toBe(200);
    const data = await res.json() as { ok: boolean; isRemote: boolean; scannedPath: string };
    expect(data.ok).toBe(true);
    expect(data.isRemote).toBe(true);
    expect(data.scannedPath).toBe("https://github.com/org/bankrepo");
  });

  test("returns 500 when git clone fails", async () => {
    mockExecFn.mockImplementationOnce(
      (_cmd: unknown, _opts: unknown, cb: (e: unknown, o: string, s: string) => void) =>
        cb({ message: "Repository not found", stdout: "", stderr: "fatal: repository not found" }, "", "")
    );
    const res = await routeModule.POST(makeRequest({ path: "https://github.com/org/private-repo" }));
    expect(res._status).toBe(500);
    const data = await res.json() as { error: string };
    expect(data.error).toMatch(/failed to clone/i);
  });

  test("strips .git and sub-paths from GitHub URL in scannedPath label", async () => {
    mockExecFn
      .mockImplementationOnce((_: unknown, __: unknown, cb: (e: null, o: string, s: string) => void) => cb(null, "", ""))
      .mockImplementationOnce((_: unknown, __: unknown, cb: (e: null, o: string, s: string) => void) =>
        cb(null, buildOsvJson(DEFAULT_SOURCE, []), "")
      );
    const res = await routeModule.POST(makeRequest({ path: "https://github.com/org/repo.git" }));
    const data = await res.json() as { scannedPath: string };
    expect(data.scannedPath).toBe("https://github.com/org/repo");
  });

  test("local path sets isRemote=false", async () => {
    mockExistsSync.mockReturnValue(true);
    execOk(buildOsvJson(DEFAULT_SOURCE, []));
    const res = await routeModule.POST(makeRequest({ path: "D:\\UCOHACK\\SecureGuard" }));
    const data = await res.json() as { isRemote: boolean };
    expect(data.isRemote).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. exec / output edge cases
// ═════════════════════════════════════════════════════════════════════════════

describe("POST handler — exec / output edge cases", () => {
  beforeEach(() => { jest.clearAllMocks(); mockExistsSync.mockReturnValue(true); });

  test("500 when exec fails with empty stdout", async () => {
    execFailEmpty("osv-scanner not found");
    const res = await routeModule.POST(makeRequest({ path: "." }));
    expect(res._status).toBe(500);
    const data = await res.json() as { error: string };
    expect(data.error).toMatch(/osv-scanner failed/i);
  });

  test("200 when exec exits non-zero but stdout has JSON", async () => {
    const json = buildOsvJson(DEFAULT_SOURCE, [{ name: "lodash", vulns: [{ id: "CVE-NZ", dbSeverity: "HIGH", fixed: "4.17.21" }] }]);
    execFailWithStdout(json);
    const res = await routeModule.POST(makeRequest({ path: "." }));
    expect(res._status).toBe(200);
    const data = await res.json() as { vulnerabilities: unknown[] };
    expect(data.vulnerabilities).toHaveLength(1);
  });

  test("500 when stdout has no JSON", async () => {
    execOk("plain text warning no braces");
    const res = await routeModule.POST(makeRequest({ path: "." }));
    expect(res._status).toBe(500);
    const data = await res.json() as { error: string };
    expect(data.error).toMatch(/no json output/i);
  });

  test("strips warning prefix before JSON", async () => {
    const json = buildOsvJson(DEFAULT_SOURCE, [{ name: "express", vulns: [{ id: "CVE-WARN", dbSeverity: "MEDIUM" }] }]);
    execOk(`Warning: plugin risk notice\n${json}`);
    const res = await routeModule.POST(makeRequest({ path: "." }));
    expect(res._status).toBe(200);
    const data = await res.json() as { vulnerabilities: unknown[] };
    expect(data.vulnerabilities).toHaveLength(1);
  });

  test("deduplicates identical vuln+pkg combination", async () => {
    const def: VulnDef = { id: "CVE-DUP", dbSeverity: "HIGH" };
    execOk(buildOsvJson(DEFAULT_SOURCE, [{ name: "lodash", vulns: [def, def] }]));
    const res = await routeModule.POST(makeRequest({ path: "." }));
    const data = await res.json() as { vulnerabilities: unknown[] };
    expect(data.vulnerabilities).toHaveLength(1);
  });

  test("500 when request body cannot be parsed", async () => {
    const badReq = { json: async () => { throw new SyntaxError("bad json"); } } as unknown as import("next/server").NextRequest;
    const res = await routeModule.POST(badReq);
    expect(res._status).toBe(500);
  });

  test("correct counts for mixed-severity results", async () => {
    const json = buildOsvJson(DEFAULT_SOURCE, [
      { name: "a", vulns: [{ id: "CVE-C1", dbSeverity: "CRITICAL" }, { id: "CVE-C2", dbSeverity: "CRITICAL" }] },
      { name: "b", vulns: [{ id: "CVE-H1", dbSeverity: "HIGH" }] },
      { name: "c", vulns: [{ id: "CVE-L1", dbSeverity: "LOW" }] },
    ]);
    execOk(json);
    const res = await routeModule.POST(makeRequest({ path: "." }));
    const data = await res.json() as { counts: Record<string, number>; totalIssues: number };
    expect(data.counts).toEqual({ critical: 2, high: 1, medium: 0, low: 1 });
    expect(data.totalIssues).toBe(4);
  });

  test("file field is basename of lockfile source path", async () => {
    const json = JSON.stringify({
      results: [{
        source: { path: "D:\\project\\sub\\yarn.lock", type: "lockfile" },
        packages: [{ package: { name: "express", version: "4.0.0", ecosystem: "npm" }, groups: [], vulnerabilities: [buildVuln({ id: "CVE-FILE", dbSeverity: "LOW" }, "express")] }],
      }],
    });
    execOk(json);
    const res = await routeModule.POST(makeRequest({ path: "." }));
    const data = await res.json() as { vulnerabilities: Array<{ file: string }> };
    expect(data.vulnerabilities[0].file).toBe("yarn.lock");
  });

  test("clean scan returns ok=true, empty list, score=100", async () => {
    execOk(buildOsvJson(DEFAULT_SOURCE, []));
    const res = await routeModule.POST(makeRequest({ path: "." }));
    const data = await res.json() as { ok: boolean; vulnerabilities: unknown[]; score: number };
    expect(data.ok).toBe(true);
    expect(data.vulnerabilities).toHaveLength(0);
    expect(data.score).toBe(100);
  });
});
