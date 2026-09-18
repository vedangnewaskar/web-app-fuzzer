/**
 * Mirrors fuzzer/core/models.py::FuzzResult.
 * Optional fields match Tier 1 fields that default to null/empty until
 * calibration/scoring/tagging modules populate them.
 */
export interface FuzzResult {
  path: string;
  url: string;
  status_code: number;
  length: number;
  response_time: number;
  type: "file" | "directory" | "traversal" | "unknown";
  resolved_url: string;

  confidence: number | null;
  signals: Record<string, number>;
  severity: "critical" | "high" | "medium" | "low" | null;
  critical: boolean;
  confirmation: "candidate" | "suspected" | "confirmed" | null;
  note: string;
}

export interface CalibrationInfo {
  classification: "normal_404" | "soft_404" | "wildcard" | "spa_fallback" | "custom_error" | "inconsistent";
  is_consistent: boolean;
  status_code: number | null;
  length: number | null;
}

export interface ScanResponse {
  results: FuzzResult[];
  calibration?: CalibrationInfo; // present for directory scans, absent for traversal scans
}
