# Command-line and release tools

This folder contains project analysis, calibration, validation and release utilities. Common entry points are `tools/run_local_server.py`, `tools/analyze_project.py`, `tools/check_release.py` and `tools/build_release.py`.


`tools/check_naming.py` validates the naming policy, ordered documentation paths and uncontrolled retired-path references. It is run by `tools/check_release.py`.
