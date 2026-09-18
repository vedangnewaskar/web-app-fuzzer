import { useState } from "react";
import type { SitemapTreeNode } from "../utils/sitemap";
import { confidenceBand, subtreeHasCritical } from "../utils/sitemap";

interface Props {
  node: SitemapTreeNode;
  depth: number;
}

const CONFIRMATION_LABEL: Record<string, string> = {
  confirmed: "confirmed",
  suspected: "suspected",
  candidate: "candidate",
};

export function SitemapNode({ node, depth }: Props) {
  const hasChildren = node.children.length > 0;
  const critical = node.result?.critical ?? false;
  // Root, and any branch containing a critical finding, start open so
  // the thing most worth seeing is visible without hunting for it.
  // Everything else starts collapsed -- a wide scan shouldn't dump
  // hundreds of rows on screen at once.
  const [expanded, setExpanded] = useState(depth === 0 || subtreeHasCritical(node));

  const result = node.result;

  return (
    <li className="sitemap-node" role="treeitem" aria-expanded={hasChildren ? expanded : undefined}>
      <div className={`sitemap-row${critical ? " sitemap-row--critical" : ""}`}>
        <span className="sitemap-indent" style={{ width: depth * 18 }} aria-hidden="true" />
        {hasChildren ? (
          <button
            type="button"
            className="sitemap-toggle"
            onClick={() => setExpanded((e) => !e)}
            aria-label={expanded ? `Collapse ${node.name}` : `Expand ${node.name}`}
          >
            {expanded ? "\u2212" : "+"}
          </button>
        ) : (
          <span className="sitemap-toggle sitemap-toggle--leaf" aria-hidden="true">
            {"\u00b7"}
          </span>
        )}

        <span className="sitemap-name">{node.name}</span>

        {result && (
          <span className="sitemap-meta">
            {result.status_code > 0 && <span className="sitemap-status">{result.status_code}</span>}
            {typeof result.confidence === "number" && (
              <span className={`badge badge--confidence-${confidenceBand(result.confidence)}`}>
                {result.confidence}
              </span>
            )}
            {result.confirmation && (
              <span className={`badge badge--confirmation-${result.confirmation}`}>
                {CONFIRMATION_LABEL[result.confirmation] ?? result.confirmation}
              </span>
            )}
            {result.severity && (
              <span className={`badge badge--severity-${result.severity}`}>{result.severity}</span>
            )}
          </span>
        )}
      </div>

      {hasChildren && expanded && (
        <ul className="sitemap-children" role="group">
          {node.children.map((child) => (
            <SitemapNode key={child.path} node={child} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}
