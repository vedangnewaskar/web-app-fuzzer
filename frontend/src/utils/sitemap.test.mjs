// Module 5 tests — Live Sitemap Tree.
//
// Standalone test for buildSitemapTree() using node's built-in TS type
// stripping (no test framework / npm install needed to run this).
// Run with: node --experimental-strip-types --experimental-transform-types src/utils/sitemap.test.mjs
import { buildSitemapTree, confidenceBand, countResults, subtreeHasCritical } from "./sitemap.ts";

let passed = 0;
function check(name, condition) {
  if (!condition) {
    console.error(`FAIL: ${name}`);
    process.exitCode = 1;
  } else {
    passed++;
  }
}

function fr(path, confidence = null, critical = false) {
  return {
    path, url: "http://x" + path, status_code: 200, length: 10, response_time: 0,
    type: "file", resolved_url: "", confidence, signals: {}, severity: null,
    critical, confirmation: null, note: "",
  };
}

// The exact example from the spec.
const results = [
  fr("/admin", 100), fr("/admin/login", 55), fr("/admin/users", 91),
  fr("/api", 67), fr("/api/users", 40), fr("/api/users/1", 30), fr("/api/orders", 20),
];
const tree = buildSitemapTree(results);

check("two top-level children (admin, api)", tree.children.length === 2);
check("top-level sorted alphabetically", tree.children.map((c) => c.name).join(",") === "admin,api");

const admin = tree.children.find((c) => c.name === "admin");
check("admin node carries its own result", admin.result?.confidence === 100);
check("admin has 2 children", admin.children.length === 2);
check("admin children sorted (login, users)", admin.children.map((c) => c.name).join(",") === "login,users");

const api = tree.children.find((c) => c.name === "api");
const apiUsers = api.children.find((c) => c.name === "users");
check("api/users has 1 child", apiUsers.children.length === 1);
check("api/users/1 full path is correct", apiUsers.children[0].path === "/api/users/1");

check("countResults counts every result in the tree", countResults(tree) === 7);

check("confidenceBand bands match backend thresholds", 
  confidenceBand(90) === "very_high" &&
  confidenceBand(75) === "high" &&
  confidenceBand(55) === "medium" &&
  confidenceBand(35) === "low" &&
  confidenceBand(10) === "very_low"
);

check("no critical results -> subtreeHasCritical false", subtreeHasCritical(tree) === false);

const withCritical = buildSitemapTree([...results, fr("/admin/.env", 80, true)]);
check("critical finding detected at root", subtreeHasCritical(withCritical) === true);
check("critical finding detected in admin subtree", subtreeHasCritical(withCritical.children.find((c) => c.name === "admin")) === true);
check("api subtree unaffected by admin's critical finding", subtreeHasCritical(withCritical.children.find((c) => c.name === "api")) === false);

const dup = buildSitemapTree([fr("/x", 20), fr("/x", 80)]);
check("duplicate path resolves to higher confidence", dup.children[0].result.confidence === 80);

const empty = buildSitemapTree([]);
check("empty results produce an empty root", empty.children.length === 0);

console.log(passed > 0 && process.exitCode !== 1 ? `${passed} checks passed` : "SOME CHECKS FAILED");
