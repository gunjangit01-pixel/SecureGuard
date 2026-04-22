"use client";

import { useState, useEffect } from "react";

// ─────────────────────────────────────────────
// OSV SCAN RESPONSE TYPES
// ─────────────────────────────────────────────
type OsvScanResponse = {
  ok: boolean;
  scannedPath?: string;
  vulnerabilities?: Vulnerability[];
  counts?: SeverityCount;
  score?: number;
  totalIssues?: number;
  error?: string;
};

// ─────────────────────────────────────────────
// TYPE DEFINITIONS
// ─────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "low";

type VulnType = "CVE" | "Misconfiguration";

type Vulnerability = {
  id: string;
  pkg: string;
  severity: Severity;
  type: VulnType;
  fix: string;
  file: string;
};

type ScanHistory = {
  date: string;
  repo: string;
  critical: number;
  high: number;
  medium: number;
  score: number;
};

type SeverityStyle = {
  bg: string;
  text: string;
  bar: string;
  badge: string;
};

type SeverityStyleMap = Record<Severity, SeverityStyle>;

type SeverityCount = Record<Severity, number>;

// ─────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────

const SEVERITY_STYLES: SeverityStyleMap = {
  critical: { bg: "#1a0505", text: "#ff4d4d", bar: "#ff2222", badge: "#2d0808" },
  high: { bg: "#1a0e05", text: "#ff8c00", bar: "#ff6a00", badge: "#2d1a08" },
  medium: { bg: "#161205", text: "#f0c040", bar: "#e6a800", badge: "#2a2208" },
  low: { bg: "#051a0a", text: "#40c070", bar: "#22b050", badge: "#082d14" },
};

const MOCK_VULNERABILITIES: Vulnerability[] = [
  { id: "CVE-2024-3912", pkg: "lodash", severity: "critical", type: "CVE", fix: "Upgrade to 4.17.21", file: "package.json" },
  { id: "GHSA-7f3x-x4pr", pkg: "axios", severity: "high", type: "CVE", fix: "Upgrade to 1.6.0", file: "package.json" },
  { id: "INSEC-001", pkg: "config.yaml", severity: "critical", type: "Misconfiguration", fix: "Remove hardcoded DB_PASSWORD", file: "config/db.yaml" },
  { id: "INSEC-002", pkg: "server.js", severity: "high", type: "Misconfiguration", fix: "Disable debug mode", file: "src/server.js" },
  { id: "CVE-2023-4863", pkg: "sharp", severity: "high", type: "CVE", fix: "Upgrade to 0.32.6", file: "package.json" },
  { id: "INSEC-003", pkg: "nginx.conf", severity: "medium", type: "Misconfiguration", fix: "Enforce TLSv1.2+", file: "infra/nginx.conf" },
  { id: "CVE-2024-0001", pkg: "express", severity: "medium", type: "CVE", fix: "Upgrade to 4.18.3", file: "package.json" },
  { id: "INSEC-004", pkg: "Dockerfile", severity: "low", type: "Misconfiguration", fix: "Run as non-root user", file: "Dockerfile" },
];

const SCAN_HISTORY: ScanHistory[] = [
  { date: "Apr 21, 09:14", repo: "core-banking-api", critical: 2, high: 3, medium: 1, score: 38 },
  { date: "Apr 20, 18:02", repo: "payment-service", critical: 0, high: 2, medium: 4, score: 72 },
  { date: "Apr 20, 11:30", repo: "auth-module", critical: 1, high: 1, medium: 2, score: 55 },
  { date: "Apr 19, 15:44", repo: "core-banking-api", critical: 3, high: 4, medium: 3, score: 21 },
];

const SEVERITY_COUNTS: SeverityCount = { critical: 2, high: 3, medium: 1, low: 1 };
const TOTAL_ISSUES: number = Object.values(SEVERITY_COUNTS).reduce((a: number, b: number) => a + b, 0);
const TABS: string[] = ["overview", "vulnerabilities", "history", "ci/cd"];

// ─────────────────────────────────────────────
// HELPER: score ring color
// ─────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score > 70) return "#22b050";
  if (score > 40) return "#e6a800";
  return "#ff2222";
}

// ─────────────────────────────────────────────
// SUB-COMPONENT: Score ring SVG
// ─────────────────────────────────────────────

type ScoreRingProps = {
  score: number;
};

function ScoreRing({ score }: ScoreRingProps) {
  const RADIUS: number = 54;
  const CIRCUMFERENCE: number = 2 * Math.PI * RADIUS;
  const dashLength: number = (score / 100) * CIRCUMFERENCE;
  const color: string = scoreColor(score);

  return (
    <svg width="110" height="110" viewBox="0 0 130 130">
      <circle
        cx="65" cy="65" r={RADIUS}
        fill="none" stroke="#1e1e1e" strokeWidth="10"
      />
      <circle
        cx="65" cy="65" r={RADIUS}
        fill="none"
        stroke={color}
        strokeWidth="10"
        strokeDasharray={`${dashLength} ${CIRCUMFERENCE - dashLength}`}
        strokeDashoffset={CIRCUMFERENCE * 0.25}
        strokeLinecap="round"
        style={{ transition: "stroke-dasharray 1.2s ease, stroke 0.5s" }}
      />
      <text
        x="65" y="60"
        textAnchor="middle"
        fill={color}
        fontSize="28"
        fontWeight="700"
        fontFamily="'DM Mono', monospace"
      >
        {score}
      </text>
      <text
        x="65" y="80"
        textAnchor="middle"
        fill="#555"
        fontSize="11"
        fontFamily="'DM Mono', monospace"
      >
        / 100
      </text>
    </svg>
  );
}

// ─────────────────────────────────────────────
// SUB-COMPONENT: Scan input bar
// ─────────────────────────────────────────────

type ScanInputProps = {
  onScan: (path: string) => Promise<void>;
};

function ScanInput({ onScan }: ScanInputProps) {
  const [value, setValue] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);

  const handleScan = async (): Promise<void> => {
    if (!value.trim() || loading) return;
    setLoading(true);
    try {
      await onScan(value.trim());
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === "Enter") handleScan();
  };

  const isGitHub = /^https?:\/\/github\.com\//i.test(value.trim());
  const hasValue = value.trim().length > 0;

  return (
    <div style={{ marginBottom: "28px" }}>
      <div style={{ display: "flex", gap: "10px" }}>
        <div style={{ flex: 1, position: "relative" }}>
          <input
            value={value}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="https://github.com/org/repo  or  D:\local\path"
            style={{
              width: "100%",
              background: "#111",
              border: `1px solid ${hasValue ? (isGitHub ? "#1a3d1a" : "#2a2a1a") : "#2a2a2a"}`,
              borderRadius: "8px",
              color: "#e0e0e0",
              padding: "12px 16px",
              paddingRight: hasValue ? "90px" : "16px",
              fontSize: "13px",
              fontFamily: "'DM Mono', monospace",
              outline: "none",
              boxSizing: "border-box",
              transition: "border-color 0.2s",
            }}
          />
          {hasValue && (
            <span style={{
              position: "absolute",
              right: "10px",
              top: "50%",
              transform: "translateY(-50%)",
              fontSize: "9px",
              fontWeight: 700,
              letterSpacing: "0.06em",
              padding: "3px 8px",
              borderRadius: "4px",
              background: isGitHub ? "#0a2d0a" : "#2a2a10",
              color: isGitHub ? "#40c070" : "#c0a030",
              fontFamily: "'DM Mono', monospace",
              pointerEvents: "none",
            }}>
              {isGitHub ? "🌐 GITHUB" : "📁 LOCAL"}
            </span>
          )}
        </div>
        <button
          onClick={handleScan}
          disabled={loading}
          style={{
            background: loading ? "#1a1a1a" : "#cc2200",
            color: loading ? "#555" : "#fff",
            border: "none",
            borderRadius: "8px",
            padding: "12px 24px",
            fontSize: "12px",
            fontWeight: 600,
            cursor: loading ? "not-allowed" : "pointer",
            fontFamily: "'DM Mono', monospace",
            letterSpacing: "0.04em",
            transition: "background 0.2s",
            minWidth: "110px",
            flexShrink: 0,
          }}
        >
          {loading ? "Scanning…" : "▶ Scan"}
        </button>
      </div>
      <div style={{
        marginTop: "7px",
        display: "flex",
        gap: "20px",
        fontSize: "9px",
        color: "#333",
        fontFamily: "'DM Mono', monospace",
        letterSpacing: "0.04em",
      }}>
        <span>🌐 GitHub — paste any public repo URL to clone &amp; scan</span>
        <span>📁 Local — paste an absolute folder path on this machine</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// SUB-COMPONENT: Severity stat card
// ─────────────────────────────────────────────

type SeverityCardProps = {
  severity: Severity;
  count: number;
  total: number;
  active: boolean;
  onClick: () => void;
};

function SeverityCard({ severity, count, total, active, onClick }: SeverityCardProps) {
  const style: SeverityStyle = SEVERITY_STYLES[severity];
  const barWidth: number = Math.round((count / total) * 100);

  return (
    <div
      onClick={onClick}
      style={{
        background: active ? style.bg : "#0e0e0e",
        border: `1px solid ${active ? style.bar + "44" : "#1a1a1a"}`,
        borderRadius: "12px",
        padding: "18px 14px",
        cursor: "pointer",
        transition: "all 0.2s",
      }}
    >
      <div style={{ fontSize: "28px", fontWeight: 700, color: style.text, lineHeight: 1 }}>
        {count}
      </div>
      <div style={{
        fontSize: "9px",
        color: style.text,
        opacity: 0.7,
        textTransform: "uppercase",
        letterSpacing: "0.1em",
        marginTop: "6px",
      }}>
        {severity}
      </div>
      <div style={{ marginTop: "10px", height: "3px", background: "#1a1a1a", borderRadius: "2px" }}>
        <div style={{
          height: "100%",
          background: style.bar,
          width: `${barWidth}%`,
          borderRadius: "2px",
          transition: "width 0.8s ease",
        }} />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// SUB-COMPONENT: Single vulnerability row
// ─────────────────────────────────────────────

type VulnRowProps = {
  vuln: Vulnerability;
};

function VulnRow({ vuln }: VulnRowProps) {
  const style: SeverityStyle = SEVERITY_STYLES[vuln.severity];

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "80px 1fr 130px 150px 1fr",
        gap: "12px",
        alignItems: "center",
        padding: "12px 16px",
        borderBottom: "1px solid #141414",
        fontSize: "11px",
        fontFamily: "'DM Mono', monospace",
        transition: "background 0.15s",
        cursor: "default",
      }}
      onMouseEnter={(e: React.MouseEvent<HTMLDivElement>) => {
        (e.currentTarget as HTMLDivElement).style.background = "#111";
      }}
      onMouseLeave={(e: React.MouseEvent<HTMLDivElement>) => {
        (e.currentTarget as HTMLDivElement).style.background = "transparent";
      }}
    >
      <span style={{
        background: style.badge,
        color: style.text,
        borderRadius: "4px",
        padding: "3px 6px",
        fontSize: "9px",
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        textAlign: "center",
      }}>
        {vuln.severity}
      </span>
      <span style={{ color: "#e0e0e0", fontWeight: 500 }}>{vuln.id}</span>
      <span style={{ color: "#555", fontSize: "10px" }}>{vuln.type}</span>
      <span style={{ color: "#666", fontSize: "10px" }}>{vuln.file}</span>
      <span style={{ color: "#40c070", fontSize: "10px" }}>→ {vuln.fix}</span>
    </div>
  );
}

// ─────────────────────────────────────────────
// SUB-COMPONENT: Scan history row
// ─────────────────────────────────────────────

type HistoryRowProps = {
  scan: ScanHistory;
};

function HistoryRow({ scan }: HistoryRowProps) {
  const color: string = scoreColor(scan.score);

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "130px 1fr 50px 50px 50px 90px",
      gap: "12px",
      alignItems: "center",
      padding: "9px 12px",
      background: "#090909",
      borderRadius: "8px",
      fontSize: "10px",
      fontFamily: "'DM Mono', monospace",
      marginBottom: "8px",
    }}>
      <span style={{ color: "#444" }}>{scan.date}</span>
      <span style={{ color: "#aaa", fontWeight: 500 }}>{scan.repo}</span>
      <span style={{ color: "#ff4d4d" }}>C:{scan.critical}</span>
      <span style={{ color: "#ff8c00" }}>H:{scan.high}</span>
      <span style={{ color: "#f0c040" }}>M:{scan.medium}</span>
      <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
        <div style={{ flex: 1, height: "3px", background: "#1a1a1a", borderRadius: "2px" }}>
          <div style={{
            height: "100%",
            width: `${scan.score}%`,
            background: color,
            borderRadius: "2px",
          }} />
        </div>
        <span style={{ color: "#444", minWidth: "22px", textAlign: "right" }}>{scan.score}</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// MAIN PAGE COMPONENT
// ─────────────────────────────────────────────

export default function SecureGuardPage() {
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [animatedScore, setAnimatedScore] = useState<number>(0);

  // Live scan state
  const [liveVulns, setLiveVulns] = useState<Vulnerability[] | null>(null);
  const [liveCounts, setLiveCounts] = useState<SeverityCount | null>(null);
  const [liveScore, setLiveScore] = useState<number | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanInfo, setScanInfo] = useState<string | null>(null);

  // Animate score ring on mount (or after scan)
  function animateScore(target: number) {
    setAnimatedScore(0);
    let current = 0;
    const interval = setInterval(() => {
      current++;
      setAnimatedScore(current);
      if (current >= target) clearInterval(interval);
    }, 18);
  }

  useEffect(() => {
    const timer = setTimeout(() => animateScore(38), 500);
    return () => clearTimeout(timer);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Active data — live results override mock data
  const activeVulns: Vulnerability[] = liveVulns ?? MOCK_VULNERABILITIES;
  const activeCounts: SeverityCount = liveCounts ?? SEVERITY_COUNTS;
  const activeTotal: number = Object.values(activeCounts).reduce((a, b) => a + b, 0);

  // Filtered vulnerability list
  const filteredVulns: Vulnerability[] =
    filter === "all"
      ? activeVulns
      : activeVulns.filter((v: Vulnerability) => v.severity === filter);

  const handleFilterToggle = (sev: Severity): void => {
    setFilter((prev: Severity | "all") => (prev === sev ? "all" : sev));
  };

  const handleScan = async (inputPath: string): Promise<void> => {
    setScanError(null);
    setScanInfo(null);
    setLiveVulns(null);
    setLiveCounts(null);
    setLiveScore(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: inputPath }),
      });
      const data: OsvScanResponse = await res.json();

      if (!res.ok || data.error) {
        setScanError(data.error ?? "Scan failed");
        return;
      }

      const vulns = (data.vulnerabilities ?? []) as Vulnerability[];
      const counts = data.counts ?? { critical: 0, high: 0, medium: 0, low: 0 };
      const score = data.score ?? 100;

      setLiveVulns(vulns);
      setLiveCounts(counts);
      setLiveScore(score);
      setScanInfo(
        vulns.length === 0
          ? `✓ No vulnerabilities found in ${data.scannedPath}`
          : `Found ${vulns.length} issue(s) in ${data.scannedPath}`
      );
      animateScore(score);
      setFilter("all");
    } catch (err: unknown) {
      setScanError((err as Error).message ?? "Network error");
    }
  };

  return (
    <div style={{
      background: "#0a0a0a",
      minHeight: "100vh",
      color: "#e0e0e0",
      fontFamily: "'DM Mono', monospace",
    }}>

      {/* Google Fonts */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@700;800&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
        @keyframes slideIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
      `}</style>

      {/* ── Header ── */}
      <header style={{
        borderBottom: "1px solid #1a1a1a",
        padding: "0 28px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        height: "52px",
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{
            width: "26px", height: "26px",
            background: "#cc2200",
            borderRadius: "6px",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: "13px",
          }}>⬡</div>
          <span style={{
            fontFamily: "'Syne', sans-serif",
            fontWeight: 800,
            fontSize: "15px",
            letterSpacing: "0.02em",
            color: "#fff",
          }}>SecureGuard</span>
          <span style={{
            background: "#1a0505",
            color: "#ff4d4d",
            fontSize: "9px",
            fontWeight: 700,
            padding: "2px 7px",
            borderRadius: "3px",
            letterSpacing: "0.08em",
          }}>UCO BANK</span>
        </div>

        {/* Nav tabs */}
        <nav style={{ display: "flex", gap: "4px" }}>
          {TABS.map((tab: string) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                background: activeTab === tab ? "#161616" : "transparent",
                color: activeTab === tab ? "#fff" : "#555",
                border: `1px solid ${activeTab === tab ? "#2a2a2a" : "transparent"}`,
                borderRadius: "6px",
                padding: "5px 13px",
                fontSize: "10px",
                fontFamily: "'DM Mono', monospace",
                cursor: "pointer",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                transition: "all 0.15s",
              }}
            >
              {tab}
            </button>
          ))}
        </nav>

        {/* Live status */}
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div style={{
            width: "7px", height: "7px",
            background: "#22b050",
            borderRadius: "50%",
            animation: "pulse 2s infinite",
          }} />
          <span style={{ fontSize: "10px", color: "#555" }}>Live · core-banking-api</span>
        </div>
      </header>

      {/* ── Main Content ── */}
      <main style={{ padding: "28px", maxWidth: "1060px", margin: "0 auto" }}>

        {/* Page title */}
        <div style={{ marginBottom: "24px", animation: "slideIn 0.4s ease" }}>
          <h1 style={{
            fontFamily: "'Syne', sans-serif",
            fontWeight: 800,
            fontSize: "26px",
            letterSpacing: "-0.02em",
            color: "#fff",
            marginBottom: "4px",
          }}>
            Dependency Security Scanner
          </h1>
          <p style={{ fontSize: "11px", color: "#444", letterSpacing: "0.04em" }}>
            Static analysis · CVE detection · Misconfiguration audit · CI/CD pipeline
          </p>
        </div>

        {/* Scan input */}
        <ScanInput onScan={handleScan} />

        {/* Scan result banners */}
        {scanError && (
          <div style={{
            marginBottom: "16px", padding: "10px 14px",
            background: "#1a0505", border: "1px solid #3d0a0a",
            borderRadius: "8px", fontSize: "11px",
            color: "#ff6b6b", fontFamily: "'DM Mono', monospace",
          }}>
            ✕ {scanError}
          </div>
        )}
        {scanInfo && !scanError && (
          <div style={{
            marginBottom: "16px", padding: "10px 14px",
            background: "#051a0a", border: "1px solid #0a3d1a",
            borderRadius: "8px", fontSize: "11px",
            color: "#40c070", fontFamily: "'DM Mono', monospace",
          }}>
            {scanInfo}{liveScore !== null ? ` — security score: ${liveScore}/100` : ""}
          </div>
        )}

        {/* Score + Severity cards */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "130px 1fr",
          gap: "14px",
          marginBottom: "24px",
          animation: "slideIn 0.5s ease",
        }}>
          {/* Score ring card */}
          <div style={{
            background: "#0e0e0e",
            border: "1px solid #1a1a1a",
            borderRadius: "12px",
            padding: "18px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
          }}>
            <ScoreRing score={animatedScore} />
            <div style={{
              fontSize: "9px", color: "#333",
              marginTop: "2px", letterSpacing: "0.08em",
            }}>
              SECURITY SCORE
            </div>
          </div>

          {/* Severity cards grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "10px" }}>
            {(Object.entries(activeCounts) as [Severity, number][]).map(
              ([sev, count]: [Severity, number]) => (
                <SeverityCard
                  key={sev}
                  severity={sev}
                  count={count}
                  total={activeTotal}
                  active={filter === sev}
                  onClick={() => handleFilterToggle(sev)}
                />
              )
            )}
          </div>
        </div>

        {/* Findings table */}
        <div style={{
          background: "#0e0e0e",
          border: "1px solid #1a1a1a",
          borderRadius: "12px",
          overflow: "hidden",
          marginBottom: "20px",
          animation: "slideIn 0.6s ease",
        }}>
          {/* Table header bar */}
          <div style={{
            padding: "14px 16px 10px",
            borderBottom: "1px solid #1a1a1a",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <span style={{ fontSize: "12px", fontWeight: 500, color: "#fff" }}>Findings</span>
              <span style={{
                background: "#1a0505", color: "#ff4d4d",
                fontSize: "9px", padding: "2px 8px", borderRadius: "3px",
              }}>
                {filteredVulns.length} issues
              </span>
              {filter !== "all" && (
                <span
                  onClick={() => setFilter("all")}
                  style={{ fontSize: "9px", color: "#555", cursor: "pointer", textDecoration: "underline" }}
                >
                  clear filter
                </span>
              )}
            </div>

            {/* Filter buttons */}
            <div style={{ display: "flex", gap: "6px" }}>
              {(["all", "critical", "high", "medium", "low"] as const).map(
                (f: Severity | "all") => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    style={{
                      background: filter === f ? "#1a1a1a" : "transparent",
                      color: filter === f ? "#e0e0e0" : "#444",
                      border: `1px solid ${filter === f ? "#2a2a2a" : "transparent"}`,
                      borderRadius: "4px",
                      padding: "3px 10px",
                      fontSize: "9px",
                      fontFamily: "'DM Mono', monospace",
                      cursor: "pointer",
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                    }}
                  >
                    {f}
                  </button>
                )
              )}
            </div>
          </div>

          {/* Column headers */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "80px 1fr 130px 150px 1fr",
            gap: "12px",
            padding: "7px 16px",
            fontSize: "9px",
            color: "#333",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            borderBottom: "1px solid #141414",
          }}>
            <span>Severity</span>
            <span>ID</span>
            <span>Type</span>
            <span>File</span>
            <span>Fix</span>
          </div>

          {/* Rows */}
          {filteredVulns.map((vuln: Vulnerability) => (
            <VulnRow key={vuln.id} vuln={vuln} />
          ))}
        </div>

        {/* Scan history */}
        <div style={{
          background: "#0e0e0e",
          border: "1px solid #1a1a1a",
          borderRadius: "12px",
          padding: "18px",
          animation: "slideIn 0.7s ease",
        }}>
          <div style={{ fontSize: "12px", fontWeight: 500, color: "#fff", marginBottom: "14px" }}>
            Recent scans
          </div>
          {SCAN_HISTORY.map((scan: ScanHistory) => (
            <HistoryRow key={`${scan.repo}-${scan.date}`} scan={scan} />
          ))}
        </div>

        {/* CI/CD hint */}
        <div style={{
          marginTop: "20px",
          padding: "14px",
          background: "#0e0e0e",
          border: "1px solid #1a1a1a",
          borderRadius: "8px",
          display: "flex",
          alignItems: "center",
          gap: "12px",
        }}>
          <span style={{ fontSize: "15px" }}>⚡</span>
          <span style={{ fontSize: "10px", color: "#444" }}>
            CI/CD integration ready — add{" "}
            <code style={{
              color: "#777",
              background: "#141414",
              padding: "2px 6px",
              borderRadius: "3px",
            }}>
              secureguard scan
            </code>{" "}
            to your GitHub Actions workflow to auto-block PRs with critical findings.
          </span>
        </div>
      </main>
    </div>
  );
}
