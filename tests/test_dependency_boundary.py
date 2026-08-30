from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import check_dependency_boundary as dependency_boundary  # noqa: E402


PRODUCTION_CONFIG = {
    "schema": dependency_boundary.PYODIDE_SCHEMA,
    "pyodide": {
        "mode": "cdn",
        "version": dependency_boundary.PYODIDE_VERSION,
        "loader_url": dependency_boundary.PYODIDE_LOADER_URL,
        "index_url": dependency_boundary.PYODIDE_INDEX_URL,
        "local_loader_url": dependency_boundary.PYODIDE_LOCAL_LOADER_URL,
        "local_index_url": dependency_boundary.PYODIDE_LOCAL_INDEX_URL,
        "expected_loader_sha256": "",
        "require_integrity": False,
    },
    "privacy": {
        "history_enabled_default": False,
        "store_source_in_history": False,
        "clear_pyodide_payload_after_run": True,
    },
}

EXAMPLE_CONFIG = copy.deepcopy(PRODUCTION_CONFIG)
EXAMPLE_CONFIG["pyodide"].update(
    {
        "mode": "local",
        "expected_loader_sha256": dependency_boundary.EXAMPLE_DIGEST_PLACEHOLDER,
        "require_integrity": True,
    }
)


def approved_workflow() -> str:
    checkout_revision, checkout_tag = dependency_boundary.APPROVED_ACTIONS["actions/checkout"]
    python_revision, python_tag = dependency_boundary.APPROVED_ACTIONS["actions/setup-python"]
    node_revision, node_tag = dependency_boundary.APPROVED_ACTIONS["actions/setup-node"]
    return f"""name: Offline boundary
on:
  pull_request:
  push:
permissions:
  contents: read
jobs:
  validate:
    runs-on: ubuntu-24.04
    steps:
      - name: Check out the exact revision
        uses: actions/checkout@{checkout_revision} # {checkout_tag}
        with:
          persist-credentials: false
      - name: Select Python
        uses: actions/setup-python@{python_revision} # {python_tag}
        with:
          python-version: '3.12.13'
      - name: Select Node.js
        uses: actions/setup-node@{node_revision} # {node_tag}
        with:
          node-version: '24.20.0'
          package-manager-cache: false
      - name: Run a local action
        uses: ./.github/actions/example
"""


class DependencyBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        for relative in ("src", "tools", "tests", "app", ".github/workflows"):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        (self.root / "src" / "codeprobe_runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.root / "src" / "main.py").write_text(
            "import json\nimport codeprobe_runtime\n", encoding="utf-8"
        )
        (self.root / "tools" / "helper.py").write_text(
            "from pathlib import Path\n", encoding="utf-8"
        )
        (self.root / "tests" / "test_helper.py").write_text(
            "import unittest\n", encoding="utf-8"
        )
        self.write_json("app/runtime-config.json", PRODUCTION_CONFIG)
        self.write_json("app/runtime-config.example.json", EXAMPLE_CONFIG)
        (self.root / "app" / "loader.js").write_text(
            f'const indexURL = "{dependency_boundary.PYODIDE_INDEX_URL}";\n',
            encoding="utf-8",
        )
        (self.root / "app" / "index.html").write_text(
            '<meta http-equiv="Content-Security-Policy" '
            f'content="script-src \'self\' {dependency_boundary.PYODIDE_ORIGIN}">\n',
            encoding="utf-8",
        )
        (self.root / ".github" / "workflows" / "ci.yml").write_text(
            approved_workflow(), encoding="utf-8"
        )
        local_action = self.root / ".github" / "actions" / "example"
        local_action.mkdir(parents=True)
        (local_action / "action.yml").write_text(
            "name: Example\n"
            "description: Minimal local composite action\n"
            "runs:\n"
            "  using: composite\n"
            "  steps:\n"
            "    - shell: bash\n"
            "      run: echo local\n",
            encoding="utf-8",
        )

    def write_json(self, relative: str, payload: object) -> None:
        (self.root / relative).write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )

    def errors(self) -> list[str]:
        return dependency_boundary.audit_dependency_boundary(self.root)

    def assert_error_contains(self, fragment: str) -> None:
        errors = self.errors()
        self.assertTrue(
            any(fragment in error for error in errors),
            f"expected {fragment!r} in {errors!r}",
        )

    def test_minimal_offline_boundary_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_recognised_python_and_javascript_manifests_are_rejected(self) -> None:
        candidates = (
            "pyproject.toml",
            "requirements-dev.txt",
            "dev-requirements.txt",
            "requirements/ci.in",
            "pylock.ci.toml",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
        )
        for relative in candidates:
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")
                try:
                    self.assert_error_contains("unapproved package manifest")
                finally:
                    path.unlink()

    def test_release_visible_venv_directories_are_not_excluded(self) -> None:
        manifest = self.root / "app" / ".venv" / "requirements.txt"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("requests==2.32.5\n", encoding="utf-8")
        self.assert_error_contains("unapproved package manifest")

        manifest.unlink()
        source = self.root / "app" / "venv" / "unsafe.py"
        source.parent.mkdir(parents=True)
        source.write_text("import requests\n", encoding="utf-8")
        self.assert_error_contains("third-party or unresolved import 'requests'")

    def test_release_excluded_directories_are_not_scanned(self) -> None:
        manifest = self.root / "app" / "DIST" / "requirements.txt"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("requests==2.32.5\n", encoding="utf-8")
        self.assertEqual(self.errors(), [])

    def test_vendored_runtime_requires_a_provenance_inventory(self) -> None:
        vendor_file = self.root / "app" / "vendor" / "pyodide" / "v0.25.0" / "pyodide.js"
        vendor_file.parent.mkdir(parents=True)
        vendor_file.write_text("// runtime\n", encoding="utf-8")
        self.assert_error_contains("no provenance inventory is configured")

    def test_third_party_import_is_rejected(self) -> None:
        (self.root / "src" / "main.py").write_text("import requests\n", encoding="utf-8")
        self.assert_error_contains("third-party or unresolved import 'requests'")

    def test_python_outside_standard_source_areas_is_still_audited(self) -> None:
        path = self.root / "educator" / "helper.pyw"
        path.parent.mkdir()
        path.write_text("import requests\n", encoding="utf-8")
        self.assert_error_contains("third-party or unresolved import 'requests'")

    def test_standard_library_allowlist_is_not_host_version_dependent(self) -> None:
        (self.root / "src" / "main.py").write_text("import tomllib\n", encoding="utf-8")
        self.assert_error_contains("third-party or unresolved import 'tomllib'")

    def test_new_local_package_does_not_silently_become_approved(self) -> None:
        package = self.root / "src" / "requests"
        package.mkdir()
        (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.root / "src" / "main.py").write_text("import requests\n", encoding="utf-8")
        self.assert_error_contains("third-party or unresolved import 'requests'")

    def test_dynamic_python_import_and_package_manager_command_are_rejected(self) -> None:
        (self.root / "tools" / "dynamic.py").write_text(
            "import importlib\n"
            "import subprocess\n"
            "load_module = importlib.import_module\n"
            "load_module('plugin')\n"
            "command = ['python', '-m', 'pip', 'install', 'plugin']\n"
            "subprocess.run(command)\n",
            encoding="utf-8",
        )
        errors = self.errors()
        self.assertTrue(any("dynamic package-loading" in error for error in errors), errors)
        self.assertTrue(any("package-manager command" in error for error in errors), errors)

    def test_dynamic_javascript_package_loader_is_rejected(self) -> None:
        (self.root / "app" / "dynamic.mjs").write_text(
            "await pyodide.loadPackage('numpy');\n", encoding="utf-8"
        )
        self.assert_error_contains("dynamic Pyodide package loading")

    def test_production_integrity_requires_lower_case_sha256(self) -> None:
        for digest in ("", "A" * 64, "a" * 63):
            with self.subTest(digest=digest):
                payload = copy.deepcopy(PRODUCTION_CONFIG)
                payload["pyodide"]["require_integrity"] = True
                payload["pyodide"]["expected_loader_sha256"] = digest
                self.write_json("app/runtime-config.json", payload)
                self.assert_error_contains("SHA-256")
        payload = copy.deepcopy(PRODUCTION_CONFIG)
        payload["pyodide"]["require_integrity"] = True
        payload["pyodide"]["expected_loader_sha256"] = "a" * 64
        self.write_json("app/runtime-config.json", payload)
        self.assertEqual(self.errors(), [])

    def test_example_allows_only_the_documented_placeholder(self) -> None:
        payload = copy.deepcopy(EXAMPLE_CONFIG)
        payload["pyodide"]["expected_loader_sha256"] = "a" * 64
        self.write_json("app/runtime-config.example.json", payload)
        self.assert_error_contains("documented digest placeholder")

    def test_production_local_mode_requires_a_vendored_provenance_inventory(self) -> None:
        payload = copy.deepcopy(PRODUCTION_CONFIG)
        payload["pyodide"].update(
            {
                "mode": "local",
                "expected_loader_sha256": "a" * 64,
                "require_integrity": True,
            }
        )
        self.write_json("app/runtime-config.json", payload)
        self.assert_error_contains("vendored provenance inventory")

    def test_pyodide_schema_version_and_locations_are_strict(self) -> None:
        mutations = (
            ("schema", "other-schema"),
            ("version", "0.26.0"),
            ("loader_url", "https://example.invalid/pyodide.js"),
            ("local_index_url", "../runtime/"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                payload = copy.deepcopy(PRODUCTION_CONFIG)
                if field == "schema":
                    payload["schema"] = value
                else:
                    payload["pyodide"][field] = value
                self.write_json("app/runtime-config.json", payload)
                try:
                    self.assertTrue(self.errors())
                finally:
                    self.write_json("app/runtime-config.json", PRODUCTION_CONFIG)

    def test_unapproved_remote_executable_origin_is_rejected(self) -> None:
        (self.root / "app" / "loader.js").write_text(
            'const loader = "https://evil.example/runtime.js";\n', encoding="utf-8"
        )
        self.assert_error_contains("unapproved remote executable origin")

    def test_bare_cdn_origin_cannot_be_used_to_construct_an_unapproved_url(self) -> None:
        (self.root / "app" / "loader.js").write_text(
            f'const origin = "{dependency_boundary.PYODIDE_ORIGIN}";\n'
            "script.src = origin + '/npm/pkg@latest/file.js';\n",
            encoding="utf-8",
        )
        self.assert_error_contains("unapproved remote executable URL")

    def test_protocol_relative_remote_executable_url_is_rejected(self) -> None:
        (self.root / "app" / "index.html").write_text(
            "<script src=//evil.example/runtime.js></script>\n", encoding="utf-8"
        )
        self.assert_error_contains("protocol-relative remote executable URL")

    def test_workflow_is_required_and_pull_request_target_is_forbidden(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        workflow.unlink()
        self.assert_error_contains("no GitHub Actions workflow exists")
        workflow.write_text(
            approved_workflow().replace("  pull_request:\n", "  pull_request_target:\n"),
            encoding="utf-8",
        )
        self.assert_error_contains("pull_request_target is forbidden")
        workflow.write_text(
            approved_workflow().replace(
                "  pull_request:\n", '  "pull_request_\\u0074arget":\n'
            ),
            encoding="utf-8",
        )
        self.assert_error_contains("escaped YAML key or value is unsupported")
        workflow.write_text(
            approved_workflow().replace(
                "  pull_request:\n  push:\n", "  push:\n    types: [pull_request_target]\n"
            ),
            encoding="utf-8",
        )
        self.assert_error_contains("pull_request_target is forbidden")

    def test_write_permissions_are_rejected(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        variants = (
            approved_workflow().replace("contents: read", "contents: write"),
            approved_workflow().replace("permissions:\n  contents: read", "permissions: write-all"),
            approved_workflow().replace(
                "permissions:\n  contents: read", "permissions: {contents: 'write'}"
            ),
            approved_workflow().replace("contents: read", "contents: *unexpected"),
            approved_workflow().replace("permissions:", '"permissions":', 1),
            approved_workflow().replace(
                "permissions:\n  contents: read", "permissions: {\n  contents: write\n}"
            ),
        )
        for source in variants:
            with self.subTest(source=source.splitlines()[4]):
                workflow.write_text(source, encoding="utf-8")
                if '"permissions"' in source:
                    self.assert_error_contains("quoted YAML mapping key")
                elif "permissions: {\n" in source:
                    self.assert_error_contains("flow-style permissions")
                else:
                    expected = "non-read permission" if "*unexpected" in source else "write permission"
                    self.assert_error_contains(expected)

    def test_workflow_requires_top_level_read_only_permissions(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        source = approved_workflow().replace("permissions:\n  contents: read\n", "")
        source = source.replace(
            "  validate:\n    runs-on:",
            "  validate:\n    permissions:\n      contents: read\n    runs-on:",
        )
        workflow.write_text(source, encoding="utf-8")
        self.assert_error_contains("lacks top-level read-only permissions")

    def test_checkout_must_disable_persisted_credentials(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        for replacement in ("persist-credentials: true", "fetch-depth: 1"):
            with self.subTest(replacement=replacement):
                workflow.write_text(
                    approved_workflow().replace("persist-credentials: false", replacement),
                    encoding="utf-8",
                )
                self.assert_error_contains("persist-credentials: false")
        decoy = approved_workflow().replace(
            "        with:\n          persist-credentials: false",
            '        env:\n          NOTE: "persist-credentials: false"',
            1,
        )
        workflow.write_text(decoy, encoding="utf-8")
        self.assert_error_contains("persist-credentials: false")

    def test_setup_node_must_disable_package_manager_cache(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        for replacement in ("package-manager-cache: true", "check-latest: false"):
            with self.subTest(replacement=replacement):
                workflow.write_text(
                    approved_workflow().replace("package-manager-cache: false", replacement),
                    encoding="utf-8",
                )
                self.assert_error_contains("package-manager-cache: false")
        decoy = approved_workflow().replace(
            "        with:\n          node-version: '24.20.0'\n          package-manager-cache: false",
            '        env:\n          NOTE: "package-manager-cache: false"',
            1,
        )
        workflow.write_text(decoy, encoding="utf-8")
        self.assert_error_contains("package-manager-cache: false")

    def test_remote_action_pin_and_tag_comment_are_exact(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        valid = approved_workflow()
        revision, tag = dependency_boundary.APPROVED_ACTIONS["actions/setup-python"]
        variants = (
            valid.replace(revision, "v7"),
            valid.replace(f"# {tag}", "# v6.0.0", 1),
            valid.replace("actions/setup-python", "third-party/setup-python"),
        )
        expected_fragments = ("incorrect pin", "same-line tag comment", "unapproved remote action")
        for source, expected in zip(variants, expected_fragments):
            with self.subTest(expected=expected):
                workflow.write_text(source, encoding="utf-8")
                self.assert_error_contains(expected)

    def test_quoted_and_flow_style_uses_are_rejected(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        variants = (
            approved_workflow().replace(
                "        uses: actions/setup-python", '        "uses": evil/action'
            ),
            approved_workflow().replace(
                "      - name: Select Python\n        uses: actions/setup-python",
                "      - {uses: evil/action",
            ),
        )
        for source in variants:
            with self.subTest(source=source):
                workflow.write_text(source, encoding="utf-8")
                self.assertTrue(self.errors())

    def test_local_composite_action_is_recursively_audited(self) -> None:
        action = self.root / ".github" / "actions" / "example" / "action.yml"
        action.write_text(
            "name: Unsafe\n"
            "description: Unsafe nested action\n"
            "runs:\n"
            "  using: composite\n"
            "  steps:\n"
            "    - uses: evil/action@main\n",
            encoding="utf-8",
        )
        self.assert_error_contains("unapproved remote action")

    def test_workflow_package_install_command_is_rejected(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        workflow.write_text(
            approved_workflow()
            + "      - name: Install unexpectedly\n"
            + "        run: python -m pip install requests\n",
            encoding="utf-8",
        )
        self.assert_error_contains("package-manager command is forbidden")

    def test_cli_prints_external_runtime_limitation_separately(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            return_code = dependency_boundary.main(["--root", str(self.root)])
        self.assertEqual(return_code, 0)
        rendered = output.getvalue()
        self.assertIn("[PASS] dependency-boundary", rendered)
        self.assertIn("[LIMITATION] external-runtime-assurance", rendered)
        self.assertIn("not audited", rendered)


if __name__ == "__main__":
    unittest.main()
