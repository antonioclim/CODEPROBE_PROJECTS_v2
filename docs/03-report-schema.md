# Report schema notes

## Scope

This document describes the stable report fields that matter for course audit and release comparison. It is not a formal JSON Schema file, but it records the expected structure of CodeProbe `2.2.0` reports.

## File report

A file analysis report has schema version `2.2.0` and includes at least:

```json
{
  "schema_version": "2.2.0",
  "app_version": "2.2.0",
  "filename": "main.py",
  "language": "python",
  "detected_language": "python",
  "input_lines": 120,
  "input_sloc": 92,
  "overall_score": 0.31,
  "verdict": "Moderate AI-style concern — mixed or weak signals",
  "verdict_class": "moderate",
  "reading": "Moderate AI-style concern — mixed or weak signals",
  "reading_class": "moderate",
  "review_trigger": 0.6,
  "review_triggered": false,
  "metrics": [],
  "recommendations": [],
  "generated_at_utc": "2026-05-28T00:00:00Z",
  "engine_fingerprint": "sha256:...",
  "metric_config_digest": "sha256:...",
  "metric_role_summary": {},
  "tool_metadata": {}
}
```

Important interpretation rule: `overall_score` is an AI-style concern score, not a probability. `review_triggered` means that the score crossed the active course review trigger; it does not mean misconduct.

## Project report

A project analysis report has schema version `2.2.0-project` and includes:

```json
{
  "schema_version": "2.2.0-project",
  "app_version": "2.2.0",
  "project_name": "assignment-1",
  "candidate_file_count": 24,
  "included_file_count": 8,
  "excluded_file_count": 16,
  "contributing_file_count": 6,
  "overall_score": 0.27,
  "verdict": "Low AI-style concern",
  "verdict_class": "low",
  "reading": "Low AI-style concern",
  "reading_class": "low",
  "review_trigger": 0.6,
  "review_triggered": false,
  "language_counts": {"python": 6},
  "included_files": [],
  "excluded_files": [],
  "top_concern_files": [],
  "aggregation": {},
  "input_packaging": {
    "source": "zip|file-list",
    "common_root_detected": "repository-main",
    "common_root_stripped": true,
    "common_root_reason": "single common non-source top-level directory; treated as hosted/export ZIP wrapper"
  },
  "generated_at_utc": "2026-05-28T00:00:00Z",
  "engine_fingerprint": "sha256:...",
  "metric_config_digest": "sha256:...",
  "metric_role_summary": {},
  "tool_metadata": {}
}
```

The project aggregate is only as meaningful as its inclusion/exclusion record. Instructors should inspect `included_files`, `excluded_files` and `input_packaging` before interpreting the score. `input_packaging.common_root_stripped` records whether a GitHub/hosted-export wrapper such as `repo-main/` was removed before `.codeprobeignore` evaluation.

## Metadata fields

| Field | Meaning | Authorship evidence? |
|---|---|---:|
| `generated_at_utc` | report generation time in UTC | No |
| `engine_fingerprint` | fingerprint of the loaded `codeprobe_runtime.py` where available | No |
| `metric_config_digest` | digest of the active metric configuration | No |
| `metric_role_summary` | count of configured metrics by group/role | No |
| `tool_metadata` | version, schema and methodological labels | No |
| `engine_metadata` | compatibility alias for tool/engine metadata | No |

## Calibration fields

When a calibration profile is supplied, reports record:

- `calibration_profile_id`;
- `calibration_profile_label`;
- `calibration_profile`;
- `review_policy`;
- `review_trigger`;
- `review_trigger_percent`;
- `review_triggered`;
- `review_trigger_source`.

These fields describe the policy lens used to read the score. They do not convert the score into a statistical probability.

## Backwards compatibility

From v2.2.0 onward, reports include `reading` and `reading_class` as the preferred interpretation fields. The older `verdict` and `verdict_class` keys remain present for compatibility with scripts written before the terminology change was fully reflected in the JSON shape. External scripts should rely on `schema_version` and should not assume that all versions use the same interpretation language. Starting from Phase 1, CodeProbe intentionally uses concern/review terminology rather than probability/verdict terminology.

## Phase 8 manual-review guidance fields

From `2.2.0`, both file and project reports include a structured manual-review layer:

```json
{
  "manual_review_guidance": {
    "scope": "file|project",
    "status": "routine_documentation_only|manual_review_recommended|manual_review_required|not_applicable",
    "status_label": "manual review recommended",
    "defensibility_note": "...",
    "review_trigger_percent": 60.0,
    "review_triggered": false,
    "risk_zones": [],
    "priority_questions": [],
    "recommended_manual_steps": [],
    "evidence_to_request": []
  },
  "risk_zones": [],
  "manual_review_recommendations": []
}
```

These fields are intended for defensible human review. They are not additional proof of AI use. A risk zone identifies where an instructor should inspect code, evidence and explanation; it does not supply a misconduct conclusion.

For file reports, risk zones are usually metric-level objects. For project reports, risk zones may refer to files, input packaging, project filtering, calibration limitations or sample-size limitations. Project risk zones are especially useful for GitHub ZIP exports because they make packaging normalisation and the included/excluded inventory explicit before an aggregate score is interpreted.

## Bounded project-input metadata

Project reports now record the effective hard limits under `input_packaging.limits`. Metadata-only exclusions such as `compression_ratio_exceeded`, `project_total_byte_limit`, `encrypted_zip_entry`, `special_zip_entry` and `nested_ignore_file` are decided before excluded ZIP members are decompressed. The `calibration_scope` field records the report-kind and language domain of the profile that was actually applied.
