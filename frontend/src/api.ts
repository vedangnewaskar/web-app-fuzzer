import type { ScanResponse } from "./types/FuzzResult";

export interface ScanOptions {
  mode?: "dirs" | "traversal";
  recursive?: boolean; // Module 6
  mutate?: boolean; // Module 3
}

export async function runScan(target: string, options: ScanOptions = {}): Promise<ScanResponse> {
  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      mode: options.mode ?? "dirs",
      recursive: options.recursive ?? false,
      mutate: options.mutate ?? false,
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(err.error || "Scan request failed");
  }

  return response.json();
}
