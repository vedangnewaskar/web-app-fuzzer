import type { FuzzResult } from "../types/FuzzResult";

/**
 * One node in the hierarchical sitemap tree. A node's own `result` is
 * only set when a scan actually produced a FuzzResult for that exact
 * path -- an intermediate segment can exist purely as structure (e.g.
 * "/admin" might never have been requested directly, only inferred
 * from "/admin/login" existing) and will have `result: undefined`.
 */
export interface SitemapTreeNode {
  name: string; // this segment only, e.g. "login" (not the full path)
  path: string; // full path from the root, e.g. "/admin/login"
  children: SitemapTreeNode[];
  result?: FuzzResult;
}

function makeNode(name: string, path: string): SitemapTreeNode {
  return { name, path, children: [] };
}

/**
 * Turn a flat list of FuzzResults (as returned by the API, however
 * they were produced -- a flat scan, Module 6 recursion, or Module 3
 * mutation follow-up all just contribute paths) into a single rooted
 * tree, splitting each `path` on "/".
 *
 * When two results land on the same exact path (possible if a
 * mutation or recursive sub-scan re-requests something already
 * scanned), the one with the higher confidence wins, so the tree
 * always reflects the most informative result for that path.
 */
export function buildSitemapTree(results: FuzzResult[]): SitemapTreeNode {
  const root = makeNode("/", "/");

  for (const result of results) {
    const segments = result.path.split("/").filter(Boolean);
    let current = root;
    let accumulated = "";

    for (const segment of segments) {
      accumulated += "/" + segment;
      let child = current.children.find((c) => c.name === segment);
      if (!child) {
        child = makeNode(segment, accumulated);
        current.children.push(child);
      }
      current = child;
    }

    if (segments.length === 0) {
      // result.path was "/" itself
      if (!root.result || (result.confidence ?? -1) > (root.result.confidence ?? -1)) {
        root.result = result;
      }
      continue;
    }

    if (!current.result || (result.confidence ?? -1) > (current.result.confidence ?? -1)) {
      current.result = result;
    }
  }

  sortTree(root);
  return root;
}

function sortTree(node: SitemapTreeNode): void {
  node.children.sort((a, b) => a.name.localeCompare(b.name));
  for (const child of node.children) {
    sortTree(child);
  }
}

export type ConfidenceBand = "very_high" | "high" | "medium" | "low" | "very_low";

// Mirrors the backend's default scoring thresholds
// (fuzzer.discovery.scoring.DEFAULT_THRESHOLDS). Kept in sync manually
// since the frontend doesn't currently fetch config from the backend;
// see the Module 5 write-up for this as a known limitation.
export function confidenceBand(confidence: number): ConfidenceBand {
  if (confidence >= 85) return "very_high";
  if (confidence >= 70) return "high";
  if (confidence >= 50) return "medium";
  if (confidence >= 30) return "low";
  return "very_low";
}

/** Total count of nodes in the subtree (including `node` itself) that have a result. */
export function countResults(node: SitemapTreeNode): number {
  let count = node.result ? 1 : 0;
  for (const child of node.children) {
    count += countResults(child);
  }
  return count;
}

/** True if `node` or anything below it is tagged critical -- used to decide default expansion. */
export function subtreeHasCritical(node: SitemapTreeNode): boolean {
  if (node.result?.critical) return true;
  return node.children.some(subtreeHasCritical);
}
