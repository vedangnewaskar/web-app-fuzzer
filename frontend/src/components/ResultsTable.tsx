import type { FuzzResult } from "../types/FuzzResult";

interface Props {
  results: FuzzResult[];
}

export function ResultsTable({ results }: Props) {
  if (results.length === 0) {
    return <p className="empty-state">No results yet — run a scan.</p>;
  }

  return (
    <table className="results-table">
      <thead>
        <tr>
          <th>Path</th>
          <th>Status</th>
          <th>Length</th>
          <th>Confidence</th>
          <th>Confirmation</th>
          <th>Severity</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => (
          <tr key={r.url} className={r.critical ? "row-critical" : undefined}>
            <td>{r.path}</td>
            <td>{r.status_code}</td>
            <td>{r.length}</td>
            <td>{r.confidence ?? "—"}</td>
            <td>{r.confirmation ?? "—"}</td>
            <td>{r.severity ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
