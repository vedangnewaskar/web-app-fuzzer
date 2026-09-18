import { useMemo } from "react";
import type { FuzzResult } from "../types/FuzzResult";
import { buildSitemapTree, countResults } from "../utils/sitemap";
import { SitemapNode } from "./SitemapNode";

interface Props {
  results: FuzzResult[];
}

export function SitemapTree({ results }: Props) {
  const root = useMemo(() => buildSitemapTree(results), [results]);

  if (results.length === 0) {
    return <p className="empty-state">No results yet — run a scan.</p>;
  }

  const criticalCount = results.filter((r) => r.critical).length;

  return (
    <div className="sitemap-tree">
      <div className="sitemap-summary">
        <span>{countResults(root)} paths</span>
        {criticalCount > 0 && <span className="sitemap-summary-critical">{criticalCount} critical</span>}
      </div>
      <ul className="sitemap-root" role="tree" aria-label="Discovered site structure">
        {root.children.map((child) => (
          <SitemapNode key={child.path} node={child} depth={0} />
        ))}
      </ul>
    </div>
  );
}
