# Command-line and release tools

This folder contains project analysis, calibration, validation and release utilities. Common entry points are `tools/run_local_server.py`, `tools/analyze_project.py`, `tools/check_release.py` and `tools/build_release.py`.


`tools/check_naming.py` validates the naming policy, ordered documentation paths and uncontrolled retired-path references. It is run by `tools/check_release.py`.

`tools/build_release.py` packages only the immutable snapshot authorised by the
strict release manifest. It stages and verifies the required ZIP, checksum and
package audit before publication, then attempts to restore the prior packet
after a detected publication failure. This is not an atomic or crash-recovery
guarantee for three paths.
