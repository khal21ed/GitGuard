import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  ExternalLink,
  FileCode2,
  Github,
  Loader2,
  Search,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
} from "lucide-react";
import "./styles.css";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ||
  "https://localhost:7221";

const severityRank = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

function normalizeSeverity(severity) {
  const normalizedSeverity = String(severity || "LOW").trim().toUpperCase();

  if (normalizedSeverity === "MEDUIM") {
    return "MEDIUM";
  }

  return normalizedSeverity;
}

async function scanRepository({ repositoryUrl, maxCommits }) {
  const response = await fetch(`${API_BASE_URL}/api/Scan/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      repositoryUrl,
      maxCommits: Number(maxCommits),
    }),
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Scan failed with status ${response.status}`);
  }

  return response.json();
}

function getGithubCommitUrl(repositoryUrl, commitSha) {
  if (!repositoryUrl || !commitSha) {
    return "";
  }

  return `${repositoryUrl.replace(/\/$/, "")}/commit/${commitSha}`;
}

function StatCard({ icon: Icon, label, value, tone }) {
  return (
    <section className={`stat-card ${tone || ""}`}>
      <div className="stat-icon">
        <Icon size={20} />
      </div>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
      </div>
    </section>
  );
}

function SeverityPill({ severity }) {
  const normalizedSeverity = normalizeSeverity(severity);

  return (
    <span className={`severity severity-${normalizedSeverity.toLowerCase()}`}>
      {normalizedSeverity}
    </span>
  );
}

function EmptyState({ hasScanned }) {
  return (
    <div className="empty-state">
      {hasScanned ? <ShieldCheck size={34} /> : <Search size={34} />}
      <h2>{hasScanned ? "No secrets found" : "Ready to scan"}</h2>
      <p>
        {hasScanned
          ? "The scan completed without findings for the selected commit range."
          : "Enter a public GitHub repository URL and choose how much history to inspect."}
      </p>
    </div>
  );
}

function ResultsTable({ findings, repositoryUrl }) {
  if (!findings.length) {
    return null;
  }

  return (
    <div className="table-shell">
      <table>
        <colgroup>
          <col className="severity-column" />
          <col className="rule-column" />
          <col className="file-column" />
          <col className="match-column" />
          <col className="entropy-column" />
          <col className="commit-column" />
        </colgroup>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule</th>
            <th>File</th>
            <th>Match</th>
            <th>Entropy</th>
            <th>Commit</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => {
            const commitUrl = getGithubCommitUrl(
              repositoryUrl,
              finding.commitSha,
            );

            return (
              <tr key={`${finding.commitSha}-${finding.filePath}-${index}`}>
                <td>
                  <SeverityPill severity={finding.severity} />
                </td>
                <td>
                  <span className="rule-name">{finding.ruleName}</span>
                </td>
                <td>
                  <span className="file-path">
                    <FileCode2 size={15} />
                    {finding.filePath}
                  </span>
                </td>
                <td>
                  <code className="match-text">{finding.matchedText}</code>
                </td>
                <td>{Number(finding.entropyScore || 0).toFixed(2)}</td>
                <td>
                  {commitUrl ? (
                    <a
                      className="commit-link"
                      href={commitUrl}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {finding.commitSha.slice(0, 7)}
                      <ExternalLink size={14} />
                    </a>
                  ) : (
                    <span className="muted">N/A</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function App() {
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [maxCommits, setMaxCommits] = useState(100);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState("");
  const [isScanning, setIsScanning] = useState(false);

  const findings = useMemo(() => {
    const items = scanResult?.findings || [];

    return [...items].sort((first, second) => {
      return (
        (severityRank[normalizeSeverity(second.severity)] || 0) -
        (severityRank[normalizeSeverity(first.severity)] || 0)
      );
    });
  }, [scanResult]);

  const criticalCount = findings.filter(
    (finding) => normalizeSeverity(finding.severity) === "CRITICAL",
  ).length;

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setScanResult(null);
    setIsScanning(true);

    try {
      const result = await scanRepository({ repositoryUrl, maxCommits });
      setScanResult(result);
    } catch (scanError) {
      setError(scanError.message.replace(/^"|"$/g, ""));
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="hero">
        <div className="hero-copy">
          <div className="brand-mark">
            <ShieldCheck size={24} />
            <span>GitGuard</span>
          </div>
          <h1>Scan GitHub history for exposed secrets.</h1>
          <p>
            Review signature and entropy findings from your backend scanner
            without sending tokens to the browser.
          </p>
        </div>

        <form className="scan-panel" onSubmit={handleSubmit}>
          <label htmlFor="repositoryUrl">Repository URL</label>
          <div className="input-row">
            <Github size={20} />
            <input
              id="repositoryUrl"
              name="repositoryUrl"
              type="url"
              placeholder="https://github.com/owner/repo"
              value={repositoryUrl}
              onChange={(event) => setRepositoryUrl(event.target.value)}
              required
            />
          </div>

          <label htmlFor="maxCommits">Commit limit</label>
          <div className="range-row">
            <SlidersHorizontal size={20} />
            <input
              id="maxCommits"
              name="maxCommits"
              type="range"
              min="10"
              max="300"
              step="10"
              value={maxCommits}
              onChange={(event) => setMaxCommits(event.target.value)}
            />
            <output>{maxCommits}</output>
          </div>

          <button type="submit" disabled={isScanning}>
            {isScanning ? (
              <Loader2 className="spin" size={19} />
            ) : (
              <Search size={19} />
            )}
            {isScanning ? "Scanning..." : "Start scan"}
          </button>

          <p className="form-note">
            API target: <code>{API_BASE_URL}</code>
          </p>
        </form>
      </section>

      {error && (
        <section className="alert">
          <AlertTriangle size={20} />
          <span>{error}</span>
        </section>
      )}

      <section className="stats-grid">
        <StatCard
          icon={ShieldX}
          label="Findings"
          value={findings.length}
          tone={findings.length ? "warning" : "success"}
        />
        <StatCard
          icon={AlertTriangle}
          label="Critical"
          value={criticalCount}
          tone="danger"
        />
        <StatCard
          icon={Clock3}
          label="Commits"
          value={scanResult?.totalCommitsTraversed ?? "-"}
        />
        <StatCard
          icon={FileCode2}
          label="Blobs fetched"
          value={scanResult?.totalBlobsCached ?? "-"}
        />
      </section>

      <section className="results-section">
        <div className="section-heading">
          <div>
            <span>Scan results</span>
            <h2>{scanResult?.repositoryUrl || "No repository scanned yet"}</h2>
          </div>
          {scanResult && (
            <div className="status-chip">
              <CheckCircle2 size={16} />
              Complete
            </div>
          )}
        </div>

        {findings.length ? (
          <ResultsTable
            findings={findings}
            repositoryUrl={scanResult.repositoryUrl}
          />
        ) : (
          <EmptyState hasScanned={Boolean(scanResult)} />
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
