import * as fs from "fs/promises";
import * as path from "path";
import crypto from "crypto";

export interface NormalisedVuln {
  id: string;
  pkg: string;
  severity: "critical" | "high" | "medium" | "low";
  type: "CVE" | "Misconfiguration" | "Secret";
  fix: string;
  file: string;
  summary: string;
  line?: number;
  snippet?: string;
}

const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  ".vscode",
  "__tests__"
]);

// A mapping of regex patterns to vulnerability metadata
const RULES = [
  // Secrets
  {
    id: "SEC-AWS-KEY",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    summary: "AWS Access Key found",
    severity: "critical" as const,
    type: "Secret" as const,
    fix: 'aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")'
  },
  {
    id: "SEC-GENERIC-SECRET",
    regex: /(api_key|secret|token|password)\s*=\s*['"][a-zA-Z0-9\-_]{16,}['"]/gi,
    summary: "Hardcoded secret or API key found",
    severity: "high" as const,
    type: "Secret" as const,
    fix: 'api_key = os.environ.get("SECRET_KEY")'
  },
  {
    id: "SEC-PRIVATE-KEY",
    regex: /-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----/g,
    summary: "Private Key found in code",
    severity: "critical" as const,
    type: "Secret" as const,
    fix: 'private_key = os.getenv("PRIVATE_KEY_CONTENT")'
  },
  
  // Misconfigurations
  {
    id: "MISCONF-INSECURE-HASH",
    regex: /(hashlib\.md5\(|crypto\.createHash\(['"]md5['"]\)|hashlib\.sha1\()/g,
    summary: "Insecure hashing algorithm used (MD5/SHA1)",
    severity: "medium" as const,
    type: "Misconfiguration" as const,
    fix: "hashlib.sha256(data.encode()).hexdigest()"
  },
  {
    id: "MISCONF-EVAL",
    regex: /\beval\(/g,
    summary: "Usage of eval() can lead to arbitrary code execution",
    severity: "high" as const,
    type: "Misconfiguration" as const,
    fix: "json.loads(data)"
  },
  {
    id: "MISCONF-SHELL-TRUE",
    regex: /shell\s*=\s*True/g,
    summary: "Command injection risk via shell=True",
    severity: "high" as const,
    type: "Misconfiguration" as const,
    fix: 'subprocess.run(["echo", user_input], check=True)'
  },
  {
    id: "MISCONF-YAML-LOAD",
    regex: /yaml\.load\(/g,
    summary: "Insecure YAML deserialization",
    severity: "critical" as const,
    type: "Misconfiguration" as const,
    fix: "yaml.safe_load(data)"
  },
  {
    id: "MISCONF-PICKLE",
    regex: /pickle\.loads?\(/g,
    summary: "Insecure object deserialization via pickle",
    severity: "critical" as const,
    type: "Misconfiguration" as const,
    fix: "json.loads(data)"
  }
];

export async function runStaticScanner(baseDir: string): Promise<NormalisedVuln[]> {
  const vulns: NormalisedVuln[] = [];
  const filesToScan: string[] = [];

  async function walk(dir: string) {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        // Skip large files, binaries, images, etc.
        if (
          entry.name.endsWith(".png") ||
          entry.name.endsWith(".jpg") ||
          entry.name.endsWith(".zip") ||
          entry.name.endsWith(".exe") ||
          entry.name.endsWith(".dll")
        ) continue;

        filesToScan.push(fullPath);
      }
    }
  }

  await walk(baseDir);

  for (const filePath of filesToScan) {
    // Avoid scanning ourselves to prevent false positives
    if (filePath.replace(/\\/g, "/").includes("api/scan/scanner.ts")) continue;

    try {
      // Avoid reading huge files
      const stat = await fs.stat(filePath);
      if (stat.size > 2 * 1024 * 1024) continue; // Skip files > 2MB

      const content = await fs.readFile(filePath, "utf-8");
      const lines = content.split(/\r?\n/);
      
      for (const rule of RULES) {
        for (let i = 0; i < lines.length; i++) {
          rule.regex.lastIndex = 0;
          if (rule.regex.test(lines[i])) {
            const vulnId = `${rule.id}-${crypto.createHash("md5").update(filePath).digest("hex").substring(0, 6)}`;
            
            vulns.push({
              id: vulnId,
              pkg: path.basename(filePath),
              severity: rule.severity,
              type: rule.type,
              fix: rule.fix,
              file: path.basename(filePath),
              summary: rule.summary,
              line: i + 1,
              snippet: lines[i].trim()
            });
            break; // Record only the first occurrence of this rule per file to avoid flooding
          }
        }
      }
    } catch {
      // Ignore read errors
      continue;
    }
  }

  return vulns;
}
