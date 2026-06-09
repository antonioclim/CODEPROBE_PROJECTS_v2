"""Version and schema constants for maintainer-facing CodeProbe tooling."""

from __future__ import annotations

APP_NAME = "CodeProbe"
APP_VERSION = "2.2.0"
FILE_REPORT_SCHEMA_VERSION = "2.2.0"
REPORT_SCHEMA_VERSION = FILE_REPORT_SCHEMA_VERSION
PROJECT_REPORT_SCHEMA_VERSION = "2.2.0-project"
CALIBRATION_PROFILE_SCHEMA = "codeprobe-calibration-profile/v1"
ENGINE_DISTRIBUTION = "self-contained-browser-bundle"
METHODOLOGY_LABEL = "heuristic-concern-not-authorship-verdict"


def metadata() -> dict[str, object]:
    """Return release metadata shared by maintenance scripts."""
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "file_report_schema_version": FILE_REPORT_SCHEMA_VERSION,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "project_report_schema_version": PROJECT_REPORT_SCHEMA_VERSION,
        "calibration_profile_schema": CALIBRATION_PROFILE_SCHEMA,
        "engine_distribution": ENGINE_DISTRIBUTION,
        "methodology": METHODOLOGY_LABEL,
    }
