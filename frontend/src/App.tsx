import { useMemo, useState, type ReactNode } from "react";
import { runScan } from "./api";
import type { CalibrationInfo, FuzzResult } from "./types/FuzzResult";
import { SitemapTree } from "./components/SitemapTree";

type View = "overview" | "sitemap" | "findings" | "analysis";

function severityRank(severity: FuzzResult["severity"]) {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  if (severity === "low") return 1;
  return 0;
}

function confidenceClass(score: number | null) {
  if (score === null) return "neutral";
  if (score >= 85) return "very-high";
  if (score >= 70) return "high";
  if (score >= 50) return "medium";
  return "low";
}

function calibrationLabel(calibration: CalibrationInfo | null) {
  if (!calibration) return "Not calibrated";

  switch (calibration.classification) {
    case "normal_404":
      return "Normal 404";
    case "soft_404":
      return "Soft 404";
    case "wildcard":
      return "Wildcard response";
    case "spa_fallback":
      return "SPA fallback";
    case "custom_error":
      return "Custom error";
    case "inconsistent":
      return "Inconsistent responses";
    default:
      return "Unknown";
  }
}

export default function App() {
  const [target, setTarget] = useState("http://127.0.0.1:8000");
  const [recursive, setRecursive] = useState(false);
  const [mutate, setMutate] = useState(false);

  const [view, setView] = useState<View>("overview");

  const [results, setResults] = useState<FuzzResult[]>([]);
  const [calibration, setCalibration] = useState<CalibrationInfo | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selected, setSelected] = useState<FuzzResult | null>(null);
  const [filter, setFilter] = useState("all");

  async function handleScan() {
    if (!target.trim()) {
      setError("Please enter a target URL.");
      return;
    }

    setLoading(true);
    setError(null);
    setSelected(null);

    try {
      const response = await runScan(target.trim(), {
        mode: "dirs",
        recursive,
        mutate,
      });

      setResults(response.results);
      setCalibration(response.calibration ?? null);
      setView("overview");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan request failed.");
    } finally {
      setLoading(false);
    }
  }

  const stats = useMemo(() => {
    const critical = results.filter((r) => r.critical).length;
    const confirmed = results.filter(
      (r) => r.confirmation === "confirmed",
    ).length;

    const highConfidence = results.filter(
      (r) => (r.confidence ?? 0) >= 85,
    ).length;

    const directories = results.filter(
      (r) => r.type === "directory",
    ).length;

    const files = results.filter((r) => r.type === "file").length;

    const traversal = results.filter(
      (r) => r.type === "traversal",
    ).length;

    return {
      total: results.length,
      critical,
      confirmed,
      highConfidence,
      directories,
      files,
      traversal,
    };
  }, [results]);

  const filteredResults = useMemo(() => {
    return [...results]
      .filter((result) => {
        if (filter === "critical") return result.critical;
        if (filter === "confirmed") {
          return result.confirmation === "confirmed";
        }
        if (filter === "high") {
          return (result.confidence ?? 0) >= 85;
        }

        return true;
      })
      .sort((a, b) => {
        const severityDifference =
          severityRank(b.severity) - severityRank(a.severity);

        if (severityDifference !== 0) {
          return severityDifference;
        }

        return (b.confidence ?? 0) - (a.confidence ?? 0);
      });
  }, [results, filter]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">WF</div>

          <div>
            <div className="brand-name">WEB FUZZER</div>
            <div className="brand-version">SECURITY CONSOLE</div>
          </div>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-label">WORKSPACE</div>

          <button
            className={`nav-item ${
              view === "overview" ? "active" : ""
            }`}
            onClick={() => setView("overview")}
          >
            <span>◈</span>
            Overview
          </button>

          <button
            className={`nav-item ${
              view === "sitemap" ? "active" : ""
            }`}
            onClick={() => setView("sitemap")}
          >
            <span>⌘</span>
            Live Sitemap
          </button>

          <button
            className={`nav-item ${
              view === "findings" ? "active" : ""
            }`}
            onClick={() => setView("findings")}
          >
            <span>!</span>
            Findings

            {stats.critical > 0 && <b>{stats.critical}</b>}
          </button>

          <button
            className={`nav-item ${
              view === "analysis" ? "active" : ""
            }`}
            onClick={() => setView("analysis")}
          >
            <span>◌</span>
            Response Analysis
          </button>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-label">INTELLIGENCE</div>

          <div className="pipeline-mini">
            <PipelineStep
              label="Calibration"
              done={calibration !== null}
            />

            <PipelineStep
              label="Discovery"
              done={results.length > 0}
            />

            <PipelineStep
              label="Confidence scoring"
              done={results.some((r) => r.confidence !== null)}
            />

            <PipelineStep
              label="Mutation engine"
              done={mutate && results.length > 0}
            />

            <PipelineStep
              label="Confirmation"
              done={stats.confirmed > 0}
            />
          </div>
        </div>

        <div className="sidebar-footer">
          <div className="status-dot" />
          <span>Engine ready</span>
          <span className="mono">v1.0</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">WEB APPLICATION SECURITY</div>
            <h1>Fuzzer Control Center</h1>
          </div>

          <div className={`engine-status ${loading ? "scanning" : ""}`}>
            <span />
            {loading ? "SCAN IN PROGRESS" : "ENGINE READY"}
          </div>
        </header>

        <section className="target-card">
          <div className="target-heading">
            <div>
              <div className="section-kicker">TARGET</div>

              <h2>Start a security scan</h2>

              <p>
                Discover hidden paths, classify responses and identify
                high-confidence exposures.
              </p>
            </div>

            <div className="scan-mode">
              <span className="mode-dot" />
              DIRECTORY FUZZING
            </div>
          </div>

          <div className="target-row">
            <div className="target-input-wrap">
              <span className="input-prefix">URL</span>

              <input
                className="target-input"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                spellCheck={false}
                placeholder="https://target.example"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !loading) {
                    void handleScan();
                  }
                }}
              />
            </div>

            <button
              className="primary-button"
              onClick={() => void handleScan()}
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="spinner" />
                  SCANNING
                </>
              ) : (
                <>
                  START SCAN
                  <span>→</span>
                </>
              )}
            </button>
          </div>

          <div className="configuration-row">
            <Toggle
              label="Recursive discovery"
              description="Follow discovered directories"
              checked={recursive}
              onChange={setRecursive}
            />

            <Toggle
              label="Mutation engine"
              description="Generate variants from discoveries"
              checked={mutate}
              onChange={setMutate}
            />

            {calibration && (
              <div className="calibration-status">
                <span className="success-mark">✓</span>

                <div>
                  <strong>
                    {calibrationLabel(calibration)}
                  </strong>

                  <small>
                    {calibration.status_code !== null
                      ? `HTTP ${calibration.status_code} · ${
                          calibration.length ?? "—"
                        } bytes`
                      : "Baseline established"}
                  </small>
                </div>
              </div>
            )}
          </div>
        </section>

        {error && (
          <div className="error-banner">
            <span>!</span>

            <div>
              <strong>Scan failed</strong>
              <p>{error}</p>
            </div>
          </div>
        )}

        {view === "overview" && (
          <>
            <section className="stats-grid">
              <StatCard
                label="Discovered paths"
                value={stats.total}
                detail="Total scan results"
              />

              <StatCard
                label="High confidence"
                value={stats.highConfidence}
                detail="Score ≥ 85"
              />

              <StatCard
                label="Confirmed"
                value={stats.confirmed}
                detail="Verified findings"
              />

              <StatCard
                label="Critical"
                value={stats.critical}
                detail="Requires attention"
                critical={stats.critical > 0}
              />
            </section>

            <section className="content-grid">
              <div className="panel intelligence-panel">
                <PanelHeader
                  title="Analysis pipeline"
                  subtitle="How every response moves through the engine"
                />

                <div className="pipeline">
                  <PipelineCard
                    number="01"
                    title="Calibration"
                    description="Establish the target's fake-404 response signature."
                    active={calibration !== null}
                    detail={
                      calibration
                        ? calibrationLabel(calibration)
                        : "Waiting for scan"
                    }
                  />

                  <PipelineCard
                    number="02"
                    title="Discovery"
                    description="Probe paths from the configured wordlist."
                    active={results.length > 0}
                    detail={`${stats.total} responses analysed`}
                  />

                  <PipelineCard
                    number="03"
                    title="Confidence"
                    description="Combine response signals into a 0–100 score."
                    active={results.some(
                      (r) => r.confidence !== null,
                    )}
                    detail={`${stats.highConfidence} high-confidence hits`}
                  />

                  <PipelineCard
                    number="04"
                    title="Mutation"
                    description="Generate follow-up variants from discoveries."
                    active={mutate && results.length > 0}
                    detail={mutate ? "Enabled" : "Disabled"}
                  />

                  <PipelineCard
                    number="05"
                    title="Confirmation"
                    description="Separate candidates from verified findings."
                    active={stats.confirmed > 0}
                    detail={`${stats.confirmed} confirmed`}
                  />
                </div>
              </div>

              <div className="panel calibration-panel">
                <PanelHeader
                  title="False-positive protection"
                  subtitle="Wildcard / soft-404 calibration"
                />

                {calibration ? (
                  <div className="calibration-result">
                    <div className="calibration-icon">✓</div>

                    <div>
                      <div className="calibration-title">
                        {calibrationLabel(calibration)}
                      </div>

                      <p>
                        Random nonexistent paths were analysed before
                        classification. Matching responses can be suppressed
                        as known fake pages.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="empty-analysis">
                    <div className="empty-icon">○</div>

                    <strong>Waiting for calibration</strong>

                    <p>
                      Start a scan to establish the target's baseline
                      response.
                    </p>
                  </div>
                )}

                {calibration && (
                  <div className="baseline-grid">
                    <div>
                      <span>STATUS</span>
                      <strong>
                        {calibration.status_code ?? "—"}
                      </strong>
                    </div>

                    <div>
                      <span>LENGTH</span>
                      <strong>
                        {calibration.length ?? "—"} B
                      </strong>
                    </div>

                    <div>
                      <span>CONSISTENT</span>
                      <strong>
                        {calibration.is_consistent ? "YES" : "NO"}
                      </strong>
                    </div>
                  </div>
                )}
              </div>
            </section>

            <section className="panel recent-panel">
              <PanelHeader
                title="Priority findings"
                subtitle="Highest-confidence results discovered during this scan"
                action={
                  <button
                    className="text-button"
                    onClick={() => setView("findings")}
                  >
                    View all →
                  </button>
                }
              />

              {results.length === 0 ? (
                <EmptyResults />
              ) : (
                <div className="finding-list">
                  {filteredResults.slice(0, 6).map((result) => (
                    <FindingRow
                      key={result.url}
                      result={result}
                      onClick={() => {
                        setSelected(result);
                        setView("analysis");
                      }}
                    />
                  ))}
                </div>
              )}
            </section>
          </>
        )}

        {view === "sitemap" && (
          <section className="panel full-panel">
            <PanelHeader
              title="Live sitemap"
              subtitle={`${stats.total} discovered paths · expandable response structure`}
            />

            <SitemapTree results={results} />
          </section>
        )}

        {view === "findings" && (
          <section className="panel full-panel">
            <PanelHeader
              title="Findings"
              subtitle="Filter and inspect discovered endpoints"
              action={
                <div className="filter-group">
                  {["all", "critical", "confirmed", "high"].map(
                    (item) => (
                      <button
                        key={item}
                        className={
                          filter === item
                            ? "filter active"
                            : "filter"
                        }
                        onClick={() => setFilter(item)}
                      >
                        {item}
                      </button>
                    ),
                  )}
                </div>
              }
            />

            {filteredResults.length === 0 ? (
              <EmptyResults />
            ) : (
              <div className="results-list">
                {filteredResults.map((result) => (
                  <FindingRow
                    key={result.url}
                    result={result}
                    onClick={() => {
                      setSelected(result);
                      setView("analysis");
                    }}
                  />
                ))}
              </div>
            )}
          </section>
        )}

        {view === "analysis" && (
          <section className="analysis-layout">
            <div className="panel full-panel">
              <PanelHeader
                title="Response analysis"
                subtitle="Evidence behind the classification"
              />

              {!selected ? (
                <div className="analysis-placeholder">
                  <div className="placeholder-mark">⌁</div>

                  <h3>Select a finding</h3>

                  <p>
                    Choose an endpoint from the findings view to inspect its
                    signals and classification.
                  </p>

                  <button
                    className="secondary-button"
                    onClick={() => setView("findings")}
                  >
                    Browse findings
                  </button>
                </div>
              ) : (
                <AnalysisView result={selected} />
              )}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

function StatCard({
  label,
  value,
  detail,
  critical = false,
}: {
  label: string;
  value: number;
  detail: string;
  critical?: boolean;
}) {
  return (
    <div className={`stat-card ${critical ? "critical" : ""}`}>
      <span>{label}</span>
      <strong>{value.toLocaleString()}</strong>
      <small>{detail}</small>
    </div>
  );
}

function Toggle({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <button
      type="button"
      className={`toggle-option ${checked ? "enabled" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span className={`switch ${checked ? "on" : ""}`}>
        <span />
      </span>

      <span>
        <strong>{label}</strong>
        <small>{description}</small>
      </span>
    </button>
  );
}

function PipelineStep({
  label,
  done,
}: {
  label: string;
  done: boolean;
}) {
  return (
    <div className={`pipeline-step ${done ? "done" : ""}`}>
      <span>{done ? "✓" : "○"}</span>
      {label}
    </div>
  );
}

function PipelineCard({
  number,
  title,
  description,
  active,
  detail,
}: {
  number: string;
  title: string;
  description: string;
  active: boolean;
  detail: string;
}) {
  return (
    <div className={`pipeline-card ${active ? "active" : ""}`}>
      <div className="pipeline-number">{number}</div>

      <div>
        <strong>{title}</strong>

        <p>{description}</p>

        <small>{detail}</small>
      </div>
    </div>
  );
}

function PanelHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle: string;
  action?: ReactNode;
}) {
  return (
    <div className="panel-header">
      <div>
        <h3>{title}</h3>
        <p>{subtitle}</p>
      </div>

      {action}
    </div>
  );
}

function FindingRow({
  result,
  onClick,
}: {
  result: FuzzResult;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className="finding-row"
      onClick={onClick}
    >
      <div
        className={`severity-indicator ${
          result.severity ?? "low"
        }`}
      />

      <div className="finding-main">
        <div className="finding-path">{result.path}</div>

        <div className="finding-meta">
          <span>{result.type}</span>
          <span>HTTP {result.status_code}</span>
          <span>{result.length.toLocaleString()} B</span>
          <span>{result.response_time.toFixed(0)} ms</span>
        </div>
      </div>

      <div className="finding-confidence">
        <div className="confidence-number">
          {result.confidence ?? "—"}
        </div>

        <div
          className={`confidence-label ${confidenceClass(
            result.confidence,
          )}`}
        >
          confidence
        </div>
      </div>

      <div className="finding-state">
        {result.confirmation && (
          <span
            className={`state-badge ${result.confirmation}`}
          >
            {result.confirmation}
          </span>
        )}

        {result.critical && (
          <span className="critical-badge">
            CRITICAL
          </span>
        )}
      </div>

      <div className="finding-arrow">→</div>
    </button>
  );
}

function AnalysisView({ result }: { result: FuzzResult }) {
  const score = result.confidence ?? 0;
  const signalEntries = Object.entries(result.signals);

  return (
    <div className="analysis-content">
      <div className="analysis-heading">
        <div>
          <div className="path-label">ENDPOINT</div>

          <h2>{result.path}</h2>

          <p>{result.url}</p>
        </div>

        <div className="analysis-badges">
          {result.severity && (
            <span
              className={`severity-badge ${result.severity}`}
            >
              {result.severity}
            </span>
          )}

          {result.confirmation && (
            <span
              className={`state-badge large ${result.confirmation}`}
            >
              {result.confirmation}
            </span>
          )}
        </div>
      </div>

      <div className="confidence-hero">
        <div>
          <span>CONFIDENCE SCORE</span>

          <strong>
            {score}
            <small>/100</small>
          </strong>
        </div>

        <div className="confidence-bar">
          <div
            style={{
              width: `${Math.min(
                100,
                Math.max(0, score),
              )}%`,
            }}
          />
        </div>

        <p>
          Score derived from the response characteristics returned by the
          fuzzer.
        </p>
      </div>

      <div className="analysis-grid">
        <div className="analysis-card">
          <div className="analysis-card-title">
            Response
          </div>

          <DataRow
            label="HTTP status"
            value={`${result.status_code}`}
          />

          <DataRow
            label="Content length"
            value={`${result.length.toLocaleString()} bytes`}
          />

          <DataRow
            label="Response time"
            value={`${result.response_time.toFixed(2)} ms`}
          />

          <DataRow
            label="Resource type"
            value={result.type}
          />

          <DataRow
            label="Resolved URL"
            value={result.resolved_url || "—"}
          />
        </div>

        <div className="analysis-card">
          <div className="analysis-card-title">
            Classification
          </div>

          <DataRow
            label="Confirmation"
            value={result.confirmation ?? "—"}
          />

          <DataRow
            label="Severity"
            value={result.severity ?? "—"}
          />

          <DataRow
            label="Critical exposure"
            value={result.critical ? "YES" : "NO"}
          />

          <DataRow
            label="Confidence"
            value={`${score}/100`}
          />
        </div>
      </div>

      <div className="analysis-card signals-card">
        <div className="analysis-card-title">
          <span className="title-normal">
            SCORING SIGNALS
          </span>

          <span>{signalEntries.length} signals</span>
        </div>

        {signalEntries.length === 0 ? (
          <div className="no-signals">
            No scoring signals were returned for this result.
          </div>
        ) : (
          <div className="signals">
            {signalEntries.map(([name, value]) => (
              <div className="signal" key={name}>
                <div className="signal-info">
                  <span>
                    {name.replace(/_/g, " ")}
                  </span>

                  <strong>{value}</strong>
                </div>

                <div className="signal-bar">
                  <div
                    style={{
                      width: `${Math.min(
                        100,
                        Math.max(0, value),
                      )}%`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {result.note && (
        <div
          className={`evidence-box ${
            result.critical ? "critical" : ""
          }`}
        >
          <div className="evidence-icon">
            {result.critical ? "!" : "i"}
          </div>

          <div>
            <strong>
              {result.critical
                ? "Critical exposure detected"
                : "Classification note"}
            </strong>

            <p>{result.note}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function DataRow({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="data-row">
      <span>{label}</span>

      <strong title={value}>{value}</strong>
    </div>
  );
}

function EmptyResults() {
  return (
    <div className="empty-results">
      <div className="empty-icon">⌁</div>

      <strong>No scan results yet</strong>

      <p>
        Configure a target above and start a scan to populate the analysis
        console.
      </p>
    </div>
  );
}
