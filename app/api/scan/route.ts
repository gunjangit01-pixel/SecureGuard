import { exec } from "child_process";
import { promisify } from "util";
import { NextRequest, NextResponse } from "next/server";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import * as crypto from "crypto";

const execAsync = promisify(exec);

// ─────────────────────────────────────────────
// OSV SCANNER JSON OUTPUT TYPES
// ─────────────────────────────────────────────

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type: string; events?: Array<{ fixed?: string; introduced?: string }> }>;
  }>;
  database_specific?: { severity?: string };
}

interface OsvPackage {
  package: { name: string; version: string; ecosystem: string };
  vulnerabilities: OsvVuln[];
  groups: Array<{ ids: string[]; max_severity?: string }>;
}

interface OsvSource {
  path: string;
  type: string;
}

interface OsvResult {
  source: OsvSource;
  packages: OsvPackage[];
}

interface OsvOutput {
  results: OsvResult[];
  experimental_config?: unknown;
}

// ─────────────────────────────────────────────
// SEVERITY NORMALISATION
// ─────────────────────────────────────────────

export function normaliseSeverity(vuln: OsvVuln): "critical" | "high" | "medium" | "low" {
  const dbSev = vuln.database_specific?.severity?.toLowerCase();
  if (dbSev === "critical") return "critical";
  if (dbSev === "high") return "high";
  if (dbSev === "medium") return "medium";
  if (dbSev === "low") return "low";

  const cvss = vuln.severity?.find(
    (s) => s.type === "CVSS_V3" || s.type === "CVSS_V2"
  );
  if (cvss) {
    const score = parseFloat(cvss.score);
    if (!isNaN(score)) {
      if (score >= 9.0) return "critical";
      if (score >= 7.0) return "high";
      if (score >= 4.0) return "medium";
      return "low";
    }
  }
  return "medium";
}

// ─────────────────────────────────────────────
// FIX EXTRACTION
// ─────────────────────────────────────────────

export function extractFix(vuln: OsvVuln, pkgName: string): string {
  const affected = vuln.affected?.[0];
  const fixedEvent = affected?.ranges
    ?.flatMap((r) => r.events ?? [])
    .find((e) => e.fixed !== undefined);
  if (fixedEvent?.fixed) {
    return `Upgrade ${pkgName} to ${fixedEvent.fixed}`;
  }
  return "Review advisory for fix details";
}

// ─────────────────────────────────────────────
// SCORING
// ─────────────────────────────────────────────

export function computeScore(
  critical: number,
  high: number,
  medium: number,
  low: number
): number {
  const penalty = critical * 25 + high * 10 + medium * 4 + low * 1;
  return Math.max(0, Math.min(100, 100 - penalty));
}

// ─────────────────────────────────────────────
// GITHUB URL DETECTION
// ─────────────────────────────────────────────

const GITHUB_URL_RE = /^https?:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(\/.*)?$/;

export function isGitHubUrl(input: string): boolean {
  return GITHUB_URL_RE.test(input.trim());
}

/** Normalise a GitHub URL to its bare https clone URL (strip trailing slashes, .git suffix). */
export function normaliseGitHubUrl(input: string): string {
  let url = input.trim().replace(/\.git$/, "").replace(/\/$/, "");
  // Strip any sub-path (e.g. /tree/main/src) — clone needs the repo root
  const match = url.match(GITHUB_URL_RE);
  if (match) {
    url = `https://github.com/${match[1]}/${match[2]}`;
  }
  return url;
}

// ─────────────────────────────────────────────
// SAFE LOCAL PATH VALIDATION
// ─────────────────────────────────────────────

export function validateScanPath(rawPath: string): string {
  const resolved = path.resolve(rawPath);
  if (resolved.length < 3) throw new Error("Invalid path");
  if (!fs.existsSync(resolved)) throw new Error(`Path not found: ${resolved}`);
  return resolved;
}

// ─────────────────────────────────────────────
// OSV RUNNER (shared)
// ─────────────────────────────────────────────

interface NormalisedVuln {
  id: string;
  pkg: string;
  severity: "critical" | "high" | "medium" | "low";
  type: "CVE" | "Misconfiguration";
  fix: string;
  file: string;
  summary: string;
}

async function runOsvScanner(scanPath: string): Promise<{
  vulns: NormalisedVuln[];
  counts: Record<"critical" | "high" | "medium" | "low", number>;
  score: number;
}> {
  const command = `"osv-scanner" scan --format=json "${scanPath}"`;

  let stdout = "";
  let stderr = "";

  try {
    const result = await execAsync(command, { timeout: 180_000 });
    stdout = result.stdout;
    stderr = result.stderr;
  } catch (err: unknown) {
    // osv-scanner exits non-zero when vulnerabilities ARE found — still get JSON on stdout
    const execErr = err as { stdout?: string; stderr?: string; message?: string };
    stdout = execErr.stdout ?? "";
    stderr = execErr.stderr ?? "";

    if (!stdout.trim()) {
      throw Object.assign(new Error(`osv-scanner failed: ${execErr.message ?? "Unknown error"}`), {
        isExecFailure: true,
        stderr,
      });
    }
  }

  const jsonStart = stdout.indexOf("{");
  if (jsonStart === -1) {
    throw Object.assign(new Error("No JSON output from osv-scanner"), { stderr });
  }

  const osvData: OsvOutput = JSON.parse(stdout.slice(jsonStart));
  const vulns: NormalisedVuln[] = [];

  for (const result of osvData.results ?? []) {
    const sourceFile = result.source?.path ?? "unknown";
    for (const pkgEntry of result.packages ?? []) {
      const pkgName = pkgEntry.package?.name ?? "unknown";
      for (const vuln of pkgEntry.vulnerabilities ?? []) {
        const id = vuln.id ?? vuln.aliases?.[0] ?? "UNKNOWN";
        const severity = normaliseSeverity(vuln);
        const fix = extractFix(vuln, pkgName);
        const type: "CVE" | "Misconfiguration" = "CVE";
        const summary = vuln.summary ?? "";

        if (!vulns.some((v) => v.id === id && v.pkg === pkgName)) {
          vulns.push({ id, pkg: pkgName, severity, type, fix, file: path.basename(sourceFile), summary });
        }
      }
    }
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulns) counts[v.severity]++;
  const score = computeScore(counts.critical, counts.high, counts.medium, counts.low);

  return { vulns, counts, score };
}

// ─────────────────────────────────────────────
// API ROUTE HANDLER
// ─────────────────────────────────────────────

export async function POST(req: NextRequest) {
  let cloneDir: string | null = null;

  try {
    const body = await req.json();
    const input: string = (body?.path ?? ".").trim();

    let scanPath: string;
    let repoLabel: string;
    let isRemote = false;

    // ── Branch 1: GitHub URL ──────────────────────────────────────────────
    if (isGitHubUrl(input)) {
      isRemote = true;
      const cloneUrl = normaliseGitHubUrl(input);
      repoLabel = cloneUrl;

      // Create an isolated temp directory for this clone
      const uid = crypto.randomBytes(6).toString("hex");
      cloneDir = path.join(os.tmpdir(), `secureguard-clone-${uid}`);
      fs.mkdirSync(cloneDir, { recursive: true });

      // Shallow clone (depth=1) to keep it fast
      try {
        await execAsync(
          `git clone --depth=1 --single-branch "${cloneUrl}" "${cloneDir}"`,
          { timeout: 120_000 }
        );
      } catch (cloneErr: unknown) {
        const e = cloneErr as { message?: string };
        return NextResponse.json(
          { error: `Failed to clone repository: ${e.message ?? cloneUrl}` },
          { status: 500 }
        );
      }

      scanPath = cloneDir;

    // ── Branch 2: Local path ──────────────────────────────────────────────
    } else {
      scanPath = validateScanPath(input);
      repoLabel = scanPath;
    }

    // ── Run OSV scanner ───────────────────────────────────────────────────
    let result: Awaited<ReturnType<typeof runOsvScanner>>;
    try {
      result = await runOsvScanner(scanPath);
    } catch (err: unknown) {
      const e = err as Error & { isExecFailure?: boolean; stderr?: string };
      return NextResponse.json(
        { error: e.message, stderr: e.stderr ?? "" },
        { status: 500 }
      );
    }

    return NextResponse.json({
      ok: true,
      scannedPath: repoLabel,
      isRemote,
      vulnerabilities: result.vulns,
      counts: result.counts,
      score: result.score,
      totalIssues: result.vulns.length,
    });

  } catch (err: unknown) {
    const e = err as Error;
    return NextResponse.json({ error: e.message ?? "Unexpected error" }, { status: 500 });
  } finally {
    // Always clean up the cloned directory
    if (cloneDir && fs.existsSync(cloneDir)) {
      fs.rmSync(cloneDir, { recursive: true, force: true });
    }
  }
}
