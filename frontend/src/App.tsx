import { useState } from "react";
import { runScan } from "./api";
import type { CalibrationInfo, FuzzResult } from "./types/FuzzResult";
import { ResultsTable } from "./components/ResultsTable";
import { SitemapTree } from "./components/SitemapTree";

type View = "tree" | "table";

export default function App() {
  const [target, setTarget] = useState("http://127.0.0.1:8000");
  const [recursive, setRecursive] = useState(false);
  const [mutate, setMutate] = useState(false);
  const [view, setView] = useState<View>("tree");

  const [results, setResults] = useState<FuzzResult[]>([]);
  const [calibration, setCalibration] = useState<CalibrationInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleScan() {
    setLoading(true);
    setError(null);
    try {
      const response = await runScan(target, { mode: "dirs", recursive, mutate });
      setResults(response.results);
      setCalibration(response.calibration ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>Web App Fuzzer</h1>
        <p className="app-subtitle">Directory &amp; traversal discovery with confidence scoring</p>
      </header>

      <section className="scan-panel">
        <div className="scan-row">
          <input
            className="scan-target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="http://127.0.0.1:8000"
            spellCheck={false}
          />
          <button className="scan-button" onClick={handleScan} disabled={loading}>
            {loading ? "Scanning…" : "Scan"}
          </button>
        </div>

        <div className="scan-options">
          <label className="scan-checkbox">
            <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} />
            Recursive
          </label>
          <label className="scan-checkbox">
            <input type="checkbox" checked={mutate} onChange={(e) => setMutate(e.target.checked)} />
            Mutations
          </label>

          {calibration && (
            <span className="calibration-badge" title="How the target responds to nonexistent paths">
              baseline: {calibration.classification}
              {calibration.status_code !== null && ` (${calibration.status_code}, ~${calibration.length}b)`}
            </span>
          )}
        </div>
      </section>

      {error && <p className="error">{error}</p>}

      <div className="view-toggle" role="tablist" aria-label="Result view">
        <button
          role="tab"
          aria-selected={view === "tree"}
          className={view === "tree" ? "view-tab view-tab--active" : "view-tab"}
          onClick={() => setView("tree")}
        >
          Sitemap
        </button>
        <button
          role="tab"
          aria-selected={view === "table"}
          className={view === "table" ? "view-tab view-tab--active" : "view-tab"}
          onClick={() => setView("table")}
        >
          Table
        </button>
      </div>

      {view === "tree" ? <SitemapTree results={results} /> : <ResultsTable results={results} />}
    </div>
  );
}
