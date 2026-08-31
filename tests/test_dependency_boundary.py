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
        (self.root / "src" / "codeprobe_runtime.py").write_text(
            "import json\nVALUE = json.dumps(1)\n", encoding="utf-8"
        )
        engine_package = self.root / "src" / "codeprobe_engine"
        engine_package.mkdir()
        (engine_package / "__init__.py").write_text("\n", encoding="utf-8")
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
            "Cargo.toml",
            "conda-lock.yml",
            "constraints",
            "noxfile.py",
            "go.mod",
            "pyproject.toml",
            "requirements-dev.txt",
            "dev-requirements.txt",
            "requirements/ci.in",
            "pylock.ci.toml",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "tox.ini",
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

    def test_unreferenced_source_package_is_rejected(self) -> None:
        package = self.root / "src" / "requests"
        package.mkdir()
        (package / "__init__.py").write_text("import json\n", encoding="utf-8")
        self.assert_error_contains("unapproved source-tree entry src/requests")

    def test_exact_source_inventory_requires_both_expected_entry_types(self) -> None:
        runtime = self.root / "src" / "codeprobe_runtime.py"
        runtime.unlink()
        runtime.mkdir()
        self.assert_error_contains("is missing or is not a regular file")

        runtime.rmdir()
        runtime.write_text("import json\n", encoding="utf-8")
        package = self.root / "src" / "codeprobe_engine"
        (package / "__init__.py").unlink()
        package.rmdir()
        package.write_text("\n", encoding="utf-8")
        self.assert_error_contains("is missing or is not a regular directory")

    def test_standard_library_shadow_modules_are_rejected(self) -> None:
        for relative in ("json.py", "JSON.py", "tools/pathlib.py", "tests/shlex.py"):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.write_text("raise SystemExit(0)\n", encoding="utf-8")
                try:
                    self.assert_error_contains("standard-library shadow module")
                finally:
                    path.unlink()

    def test_standard_library_shadow_packages_are_rejected_case_insensitively(self) -> None:
        for relative in ("json/__init__.py", "tools/PathLib/__init__.py"):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True)
                path.write_text("raise SystemExit(0)\n", encoding="utf-8")
                try:
                    self.assert_error_contains("standard-library shadow package")
                finally:
                    path.unlink()
                    path.parent.rmdir()

    def test_noncanonical_first_party_modules_are_rejected(self) -> None:
        runtime = self.root / "tools" / "codeprobe_runtime.py"
        runtime.write_text("raise RuntimeError('shadow')\n", encoding="utf-8")
        self.assert_error_contains("noncanonical first-party shadow module")

        runtime.unlink()
        engine = self.root / "tests" / "CodeProbe_Engine"
        engine.mkdir()
        (engine / "__init__.py").write_text("\n", encoding="utf-8")
        self.assert_error_contains("noncanonical first-party shadow package")

    def test_packaged_dependency_artefacts_are_rejected(self) -> None:
        for relative in (
            "packages/example.whl",
            "packages/example.egg",
            "cache/x.conda",
            "cache/example.tgz",
            "cache/example.tar.gz",
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"archive")
                try:
                    self.assert_error_contains("unapproved packaged dependency artefact")
                finally:
                    path.unlink()

    def test_manifestless_node_modules_tree_is_rejected(self) -> None:
        candidates = (
            "app/node_modules/example/index.js",
            "app/bower_components/example/index.js",
            "app/jspm_packages/example/index.js",
            "src/codeprobe_engine/thirdparty/example.py",
            "src/codeprobe_engine/_vendor/example.py",
            "__pypackages__/3.10/lib/requests.py",
        )
        for relative in candidates:
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("VALUE = 1\n", encoding="utf-8")
                try:
                    self.assert_error_contains("unapproved vendored dependency directory")
                finally:
                    path.unlink()
                    if relative.startswith("app/"):
                        stop = self.root / "app"
                    elif relative.startswith("src/"):
                        stop = self.root / "src" / "codeprobe_engine"
                    else:
                        stop = self.root
                    parent = path.parent
                    while parent != stop:
                        parent.rmdir()
                        parent = parent.parent

    def test_third_party_import_is_rejected(self) -> None:
        (self.root / "src" / "codeprobe_runtime.py").write_text(
            "import requests\n", encoding="utf-8"
        )
        self.assert_error_contains("third-party or unresolved import 'requests'")

    def test_python_outside_standard_source_areas_is_still_audited(self) -> None:
        path = self.root / "educator" / "helper.pyw"
        path.parent.mkdir()
        path.write_text("import requests\n", encoding="utf-8")
        self.assert_error_contains("third-party or unresolved import 'requests'")

    def test_standard_library_allowlist_is_not_host_version_dependent(self) -> None:
        (self.root / "src" / "codeprobe_runtime.py").write_text(
            "import tomllib\n", encoding="utf-8"
        )
        self.assert_error_contains("third-party or unresolved import 'tomllib'")

    def test_portable_standard_library_shadow_forms_are_rejected(self) -> None:
        variants = (
            self.root / "tools" / "JSON.PY",
            self.root / "tools" / "json.pyc",
            self.root / "tools" / "json.cpython-312-x86_64-linux-gnu.so",
            self.root / "tools" / "Json" / "__INIT__.PY",
        )
        for path in variants:
            with self.subTest(path=path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"shadow")
                self.assert_error_contains("standard-library shadow")
                path.unlink()

    def test_python_310_standard_library_import_is_approved(self) -> None:
        (self.root / "src" / "codeprobe_runtime.py").write_text(
            "import errno\n", encoding="utf-8"
        )
        self.assertEqual(self.errors(), [])

    def test_new_local_package_does_not_silently_become_approved(self) -> None:
        package = self.root / "src" / "requests"
        package.mkdir()
        (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.root / "src" / "codeprobe_runtime.py").write_text(
            "import requests\n", encoding="utf-8"
        )
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

    def test_constructed_python_package_manager_commands_are_rejected(self) -> None:
        variants = (
            "import subprocess\n"
            "command = ['python', '-m', 'pip', 'install', 'plugin']\n"
            "subprocess.run(args=command)\n",
            "import subprocess\n"
            "command = ['python', '-m', 'pip', 'install', 'plugin']\n"
            "alias = command\n"
            "subprocess.run(alias)\n",
            "import subprocess\n"
            "subprocess.run(['py' + 'thon', '-m', 'pi' + 'p', 'in' + 'stall', 'plugin'])\n",
            "import subprocess\n"
            "launch = subprocess.run\n"
            "launch(['python', '-m', 'pip', 'install', 'plugin'])\n",
            "import subprocess as sp\n"
            "first = sp.run\n"
            "launch = first\n"
            "launch(['python', '-m', 'pip', 'install', 'plugin'])\n",
            "import subprocess\n"
            "tool = 'pip'\n"
            "command = f'{tool} install plugin'\n"
            "subprocess.run(command, shell=True)\n",
            "import subprocess\n"
            "tool = ''.join(['pi', 'p'])\n"
            "subprocess.run([tool, 'install', 'plugin'])\n",
            "import subprocess\n"
            "subprocess.run([b'pip', b'install', b'plugin'])\n",
            "import subprocess\n"
            "subprocess.run(args=['install', 'plugin'], executable='pip')\n",
        )
        path = self.root / "tools" / "dynamic_command.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains("package-manager command")

    def test_common_python_package_launch_forms_are_rejected(self) -> None:
        variants = (
            "import subprocess\nimport sys\n"
            "subprocess.run([sys.executable, '-m', 'pip', 'install', 'plugin'])\n",
            "import subprocess\n"
            "subprocess.run(['py', '-m', 'pip', 'install', 'plugin'])\n",
            "import subprocess\n"
            "subprocess.run(['/usr/bin/env', 'pip', 'install', 'plugin'])\n",
            "import os\nos.execvp('pip', ['pip', 'install', 'plugin'])\n",
            "import subprocess\n"
            "subprocess.run('echo ready; pip install plugin', shell=True)\n",
            "import subprocess\n"
            "subprocess.run(['sh', '-c', 'echo ready | pip install plugin'])\n",
            "import subprocess\n"
            "tool = ''.join(map(str, ['pi', 'p']))\n"
            "subprocess.run([tool, 'install', 'plugin'])\n",
        )
        path = self.root / "tools" / "launch_forms.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains("package-manager command")

    def test_python_command_analysis_fails_closed_on_branch_and_outer_ambiguity(self) -> None:
        variants = (
            "import subprocess\ncondition = True\n"
            "if condition:\n    command = ['pip', 'install', 'plugin']\n"
            "else:\n    command = ['echo', 'offline']\n"
            "subprocess.run(command)\n",
            "import subprocess\ncommand = 'echo offline'\n"
            "def launch():\n    subprocess.run(command, shell=True)\n"
            "command = 'pip install plugin'\nlaunch()\n",
        )
        path = self.root / "tools" / "ambiguous_command.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains("static analysis limits")

    def test_python_analysis_depth_is_bounded_without_crashing(self) -> None:
        (self.root / "tools" / "deep_expression.py").write_text(
            "value = root" + ".child" * 1_500 + "\n",
            encoding="utf-8",
        )
        self.assert_error_contains("static analysis limits")

    def test_sequential_safe_reassignment_and_quoted_shell_data_pass(self) -> None:
        (self.root / "tools" / "safe_process.py").write_text(
            "import subprocess\n"
            "command = 'pip install plugin'\n"
            "command = 'echo offline'\n"
            "subprocess.run(command, shell=True)\n"
            "subprocess.run(\"echo 'safe; pip install is unavailable'\", shell=True)\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_dormant_function_assignment_does_not_contaminate_module_scope(self) -> None:
        (self.root / "tools" / "safe_scope.py").write_text(
            "import subprocess\n"
            "command = 'echo offline'\n"
            "def dormant():\n    command = 'pip install plugin'\n    return command\n"
            "subprocess.run(command, shell=True)\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_reflected_dynamic_import_is_rejected(self) -> None:
        variants = (
            "import importlib\n"
            "loader = getattr(importlib, 'import_' + 'module')\n"
            "loader('plugin')\n",
            "import importlib\n"
            "loader = object.__getattribute__(importlib, 'import_module')\n"
            "loader('plugin')\n",
            "import importlib\n"
            "reflect = object.__getattribute__\n"
            "loader = reflect(importlib, 'import_module')\n"
            "loader('plugin')\n",
            "import importlib\n"
            "loader = type(importlib).__getattribute__(importlib, 'import_module')\n"
            "loader('plugin')\n",
        )
        path = self.root / "tools" / "reflection.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains("dynamic package-loading reflection")

    def test_reflected_process_launcher_is_rejected(self) -> None:
        variants = (
            "import subprocess\n"
            "launch = getattr(subprocess, 'r' + 'un')\n"
            "launch(['pip', 'install', 'plugin'])\n",
            "import subprocess\n"
            "launch = object.__getattribute__(subprocess, 'run')\n"
            "launch(['pip', 'install', 'plugin'])\n",
            "import subprocess\n"
            "reflect = object.__getattribute__\n"
            "launch = reflect(subprocess, 'run')\n"
            "launch(['pip', 'install', 'plugin'])\n",
        )
        path = self.root / "tools" / "reflection.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains("dynamic process-execution reflection")

    def test_module_namespace_dictionary_reflection_is_rejected(self) -> None:
        variants = (
            "import importlib\n"
            "loader = importlib.__dict__.get('import_module')\n"
            "loader('plugin')\n",
            "import importlib\n"
            "loader = vars(importlib).get('import_module')\n"
            "loader('plugin')\n",
            "import subprocess\n"
            "launch = subprocess.__dict__.get('run')\n"
            "launch(['pip', 'install', 'plugin'])\n",
        )
        path = self.root / "tools" / "namespace_reflection.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains("namespace lookup")

    def test_module_aliases_do_not_hide_dynamic_loading_or_process_launchers(self) -> None:
        variants = (
            "import importlib\n"
            "module = importlib\n"
            "module.import_module('plugin')\n",
            "import importlib\n"
            "module = importlib\n"
            "getattr(module, 'import_module')('plugin')\n",
            "import importlib\n"
            "module = importlib\n"
            "module.__dict__.get('import_module')('plugin')\n",
            "import subprocess\n"
            "process = subprocess\n"
            "process.run(['pip', 'install', 'plugin'])\n",
        )
        path = self.root / "tools" / "module_alias.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assertTrue(self.errors())

    def test_additional_dynamic_code_and_process_launchers_are_rejected(self) -> None:
        variants = (
            "import os\n"
            "os.spawnvp(os.P_WAIT, 'pip', ['pip', 'install', 'plugin'])\n",
            "import os\n"
            "os.posix_spawnp('pip', ['pip', 'install', 'plugin'], os.environ)\n",
            "import importlib.machinery\n"
            "loader = importlib.machinery.SourceFileLoader('plugin', '/tmp/plugin.py')\n"
            "loader.load_module()\n",
            "exec('import requests')\n",
            "import sys\n"
            "vars(sys.modules['builtins'])['__import__']('requests')\n",
        )
        path = self.root / "tools" / "additional_dynamic.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assertTrue(self.errors())

    def test_code_execution_and_spawn_aliases_are_rejected(self) -> None:
        variants = (
            "runner = exec\nrunner('import requests')\n",
            "runner = eval\nrunner('__import__(\\\"requests\\\")')\n",
            "from os import spawnvp as launch\n"
            "import os\nlaunch(os.P_WAIT, 'pip', ['pip', 'install', 'plugin'])\n",
            "import os\nlaunch = os.spawnvp\n"
            "launch(os.P_WAIT, 'pip', ['pip', 'install', 'plugin'])\n",
        )
        path = self.root / "tools" / "aliased_execution.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                errors = self.errors()
                self.assertTrue(
                    any(
                        fragment in error
                        for fragment in ("dynamic Python code execution", "package-manager command")
                        for error in errors
                    ),
                    errors,
                )

    def test_unresolved_process_commands_and_ordinary_wrappers_fail_closed(self) -> None:
        variants = (
            "import os\nimport subprocess\n"
            "subprocess.run(os.environ['INSTALL_COMMAND'], shell=True)\n",
            "import subprocess\ndef launch(command):\n"
            "    subprocess.run(command, shell=True)\nlaunch('echo offline')\n",
        )
        path = self.root / "tools" / "unresolved_process.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains("process command exceeds static analysis limits")

    def test_aliased_reflection_and_builtin_import_are_rejected(self) -> None:
        variants = (
            "import importlib\nreflect = getattr\n"
            "loader = reflect(importlib, 'import_module')\nloader('plugin')\n",
            "load = __import__\nload('plugin')\n",
        )
        path = self.root / "tools" / "reflected_alias.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                errors = self.errors()
                self.assertTrue(
                    any("dynamic package-loading" in error for error in errors),
                    errors,
                )

    def test_unsupported_process_indirection_is_rejected(self) -> None:
        variants = (
            "import subprocess\noptions = {'args': ['echo', 'safe']}\n"
            "subprocess.run(**options)\n",
            "import subprocess\n_, launch = (None, subprocess.run)\n"
            "launch(['echo', 'safe'])\n",
            "import subprocess\na = subprocess.run\n"
            "_, launch = (None, a)\nlaunch(['echo', 'safe'])\n",
            "import subprocess\n(f := subprocess.run)(['pip', 'install', 'plugin'])\n",
        )
        path = self.root / "tools" / "indirect_process.py"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assertTrue(self.errors())

    def test_safely_reassigned_launcher_alias_is_not_treated_as_process_execution(self) -> None:
        (self.root / "tools" / "safe_alias.py").write_text(
            "import subprocess\n"
            "launch = subprocess.run\n"
            "launch = print\n"
            "launch(['pip', 'install', 'plugin'])\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_static_safe_reflection_is_not_treated_as_dependency_loading(self) -> None:
        (self.root / "tools" / "reflection.py").write_text(
            "import importlib\n"
            "import subprocess\n"
            "IMPORT_UTIL = getattr(importlib, 'util')\n"
            "PIPE = getattr(subprocess, 'PIPE')\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

        (self.root / "tools" / "reflection.py").write_text(
            "import importlib\n"
            "import subprocess\n"
            "invalidate = object.__getattribute__(importlib, 'invalidate_caches')\n"
            "render = object.__getattribute__(subprocess, 'list2cmdline')\n"
            "typed_invalidate = type(importlib).__getattribute__(importlib, 'invalidate_caches')\n"
            "invalidate()\n"
            "typed_invalidate()\n"
            "print(render(['echo', 'offline']))\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_pep_723_inline_package_metadata_is_rejected(self) -> None:
        path = self.root / "tools" / "inline.py"
        path.write_text(
            "# /// script\n"
            "# dependencies = ['requests==2.32.5']\n"
            "# ///\n"
            "print('offline')\n",
            encoding="utf-8",
        )
        self.assert_error_contains("unapproved PEP 723 inline package metadata")
        path.write_text("TEXT = '# /// script'\n", encoding="utf-8")
        self.assertEqual(self.errors(), [])

    def test_extensionless_python_shebang_pep_723_block_is_rejected(self) -> None:
        path = self.root / "tools" / "inline-script"
        shebangs = (
            "#!/usr/bin/env python3",
            "#!/usr/bin/env -S uv run --script",
        )
        for shebang in shebangs:
            with self.subTest(shebang=shebang):
                path.write_text(
                    f"{shebang}\n"
                    "# /// script\n"
                    "# dependencies = ['requests==2.32.5']\n"
                    "# ///\n",
                    encoding="utf-8",
                )
                self.assert_error_contains("unapproved PEP 723 inline package metadata")

    def test_dynamic_javascript_package_loader_is_rejected(self) -> None:
        (self.root / "app" / "dynamic.mjs").write_text(
            "await pyodide.loadPackage('numpy');\n", encoding="utf-8"
        )
        self.assert_error_contains("dynamic Pyodide package loading")

    def test_computed_and_template_javascript_loaders_are_rejected(self) -> None:
        variants = (
            "pyodide['load' + 'Package']('numpy');\n",
            "const value = `${pyodide.loadPackage('numpy')}`;\n",
            "const value = `${import('plugin')}`;\n",
            "const value = `${importScripts('worker.js')}`;\n",
        )
        path = self.root / "app" / "computed-loader.js"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assertTrue(self.errors())

    def test_mixed_case_browser_suffixes_are_scanned(self) -> None:
        (self.root / "app" / "loader.JS").write_text(
            "await import('plugin');\n",
            encoding="utf-8",
        )
        self.assert_error_contains("dynamic JavaScript import")

    def test_remote_binding_analysis_has_a_work_budget(self) -> None:
        source = "".join(
            f'const remote{index} = "{dependency_boundary.PYODIDE_INDEX_URL}";\n'
            for index in range(dependency_boundary.MAX_JAVASCRIPT_REMOTE_BINDINGS + 1)
        )
        (self.root / "app" / "many-remotes.js").write_text(source, encoding="utf-8")
        self.assert_error_contains("remote-binding analysis exceeds static limits")

    def test_javascript_loader_names_in_comments_and_strings_are_ignored(self) -> None:
        (self.root / "app" / "dynamic.mjs").write_text(
            "// require('offline')\n"
            "const explanation = \"import('offline') and loadPackage('offline')\";\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_simply_constructed_javascript_remote_locations_are_rejected(self) -> None:
        index_url = dependency_boundary.PYODIDE_INDEX_URL
        variants = (
            f'const base = "{index_url}";\nconst alias = base\n'
            'script.src = `${alias}../../../npm/x.js`;\n',
            r'const target = "\u0068ttps://evil.example/runtime.js";' "\n",
            'script.src = "ht" + "tps://evil.example/runtime.js";\n',
            f'script.src = "{index_url}".concat("../../../npm/x.js");\n',
            f'script.src = new URL("../../../npm/x.js", "{index_url}");\n',
            f'let base; base = "{index_url}";\n'
            'script.src = (base) + "../../../npm/x.js";\n',
            f'const base = {"(" * 20}"{index_url}"{")" * 20};\n'
            'script.src = base?.concat("../../../npm/x.js");\n',
            f'const base = /* {"x" * 600} */ "{index_url}";\n'
            'script.src = new URL(resolvePath("x"), base);\n',
        )
        path = self.root / "app" / "loader.js"
        for source in variants:
            with self.subTest(source=source[:80]):
                path.write_text(source, encoding="utf-8")
                self.assertTrue(
                    any(
                        fragment in error
                        for error in self.errors()
                        for fragment in (
                            "remote executable",
                            "URL concatenation",
                        )
                    ),
                    self.errors(),
                )

    def test_javascript_regex_literals_cannot_mask_a_later_remote_url(self) -> None:
        (self.root / "app" / "loader.js").write_text(
            r'const pattern = /[\"]/; const loader = "https://evil.example/x.js";'
            "\n",
            encoding="utf-8",
        )
        self.assert_error_contains("unapproved remote executable origin")

    def test_escaped_javascript_identifiers_are_rejected_without_crashing(self) -> None:
        path = self.root / "app" / "loader.js"
        path.write_text(
            r'const b\u0061se = "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/";'
            "\n",
            encoding="utf-8",
        )
        self.assert_error_contains("escaped JavaScript identifier")
        path.write_text(r'const invalid = "\u{110000}";' "\n", encoding="utf-8")
        self.errors()

    def test_protocol_relative_ipv6_and_triple_slash_urls_are_rejected(self) -> None:
        path = self.root / "app" / "loader.js"
        for value in ("//[::1]/x.js", "///evil.example/x.js", "//user@evil.example/x.js"):
            with self.subTest(value=value):
                path.write_text(f'const loader = "{value}";\n', encoding="utf-8")
                self.assert_error_contains("protocol-relative remote executable URL")

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

    def test_approved_remote_base_cannot_be_concatenated(self) -> None:
        variants = (
            f'script.src = "{dependency_boundary.PYODIDE_INDEX_URL}"'
            ' + "../../../npm/pkg@latest/file.js";\n',
            f'const base = "{dependency_boundary.PYODIDE_INDEX_URL}";\n'
            'script.src = base + "../../../npm/pkg@latest/file.js";\n',
        )
        path = self.root / "app" / "loader.js"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains("remote executable URL concatenation")

    def test_html_entity_urls_and_bare_origin_concatenation_are_rejected(self) -> None:
        variants = (
            (
                f'<script>const base = "{dependency_boundary.PYODIDE_ORIGIN}"; '
                'script.src = base + "/npm/pkg@latest/file.js";</script>\n',
                "inline script or event handler",
            ),
            (
                '<script src="https&colon;//evil.example/runtime.js"></script>\n',
                "unapproved remote executable origin",
            ),
            (
                '<script src="&#47;&#47;evil.example/runtime.js"></script>\n',
                "protocol-relative remote executable URL",
            ),
        )
        path = self.root / "app" / "index.html"
        for source, expected in variants:
            with self.subTest(expected=expected):
                path.write_text(source, encoding="utf-8")
                self.assert_error_contains(expected)

    def test_html_url_normalisation_and_active_resource_kinds_are_strict(self) -> None:
        variants = (
            '<script src="https&NewLine;://evil.example/x.js"></script>\n',
            '<script src="https&Tab;://evil.example/x.js"></script>\n',
            '<script href="https://evil.example/x.js"></script>\n',
            '<svg><script xlink:href="https://evil.example/x.js"></script></svg>\n',
            f'<base href="{dependency_boundary.PYODIDE_INDEX_URL}">\n',
        )
        path = self.root / "app" / "index.html"
        for source in variants:
            with self.subTest(source=source):
                path.write_text(source, encoding="utf-8")
                self.assertTrue(self.errors())

    def test_html_anchor_and_image_preload_are_not_executable_locations(self) -> None:
        (self.root / "app" / "index.html").write_text(
            '<meta http-equiv="Content-Security-Policy" '
            'content="script-src \'self\'">\n'
            '<a href="https://example.com/docs">Documentation</a>\n'
            '<link rel="preload" as="image" href="https://example.com/image.png">\n',
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_csp_remote_source_forms_are_rejected(self) -> None:
        unsafe_sources = (
            "*",
            "https:",
            "http:",
            "evil.example",
            "*.evil.example",
            "https&NewLine;://evil.example",
        )
        path = self.root / "app" / "index.html"
        for unsafe_source in unsafe_sources:
            with self.subTest(unsafe_source=unsafe_source):
                path.write_text(
                    '<meta http-equiv="Content-Security-Policy" '
                    f'content="script-src \'self\' {unsafe_source}">\n',
                    encoding="utf-8",
                )
                self.assert_error_contains("unapproved CSP executable source")

    def test_protocol_relative_remote_executable_url_is_rejected(self) -> None:
        (self.root / "app" / "index.html").write_text(
            "<script src=//evil.example/runtime.js></script>\n", encoding="utf-8"
        )
        self.assert_error_contains("protocol-relative remote executable URL")

    def test_html_embedded_executable_locations_and_schemes_are_rejected(self) -> None:
        path = self.root / "app" / "index.html"
        csp = (
            '<meta http-equiv="Content-Security-Policy" '
            'content="script-src \'self\'">\n'
        )
        variants = (
            ('<iframe src="https://evil.example/frame.html"></iframe>', "embedded active document"),
            ('<object data="https://evil.example/object.html"></object>', "embedded active document"),
            ('<embed src="https://evil.example/plugin.html">', "embedded active document"),
            ('<script src="data:text/javascript,alert(1)"></script>', "unapproved executable URL scheme"),
            ('<iframe srcdoc="<script>import(\'plugin\')</script>"></iframe>', "inline frame document"),
            ('<body onload="script.src=\'https://evil.example/runtime.js\'">', "inline script or event handler"),
        )
        for markup, expected in variants:
            with self.subTest(markup=markup):
                path.write_text(csp + markup + "\n", encoding="utf-8")
                self.assert_error_contains(expected)

    def test_html_csp_local_confinement_and_navigation_are_fail_closed(self) -> None:
        path = self.root / "app" / "index.html"
        variants = (
            ('<meta http-equiv="Content-Security-Policy" content="img-src \'self\'">',
             "lacks script-src or default-src"),
            ('<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'
             '<script src="../tools/helper.js"></script>', "escapes app"),
            ('<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'
             '<meta http-equiv="refresh" content="0;url=https://evil.example">', "meta refresh"),
            ('<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'
             '<a href="javascript:alert(1)">open</a>', "navigation URL scheme"),
            ('<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'
             '<script>pyodide.loadPackage(\'numpy\')</script>', "inline script or event handler"),
        )
        for source, expected in variants:
            with self.subTest(expected=expected):
                path.write_text(source + "\n", encoding="utf-8")
                self.assert_error_contains(expected)

    def test_json_escaped_remote_url_is_rejected_after_decoding(self) -> None:
        (self.root / "app" / "extra.json").write_text(
            '{"loader":"https\\u003a//evil.example/x.js"}\n',
            encoding="utf-8",
        )
        self.assert_error_contains("unapproved remote executable origin")

    def test_html_requires_a_content_security_policy(self) -> None:
        (self.root / "app" / "index.html").write_text(
            "<!doctype html><title>Missing policy</title>\n",
            encoding="utf-8",
        )
        self.assert_error_contains("missing Content-Security-Policy")

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

    def test_workflow_obfuscated_package_installs_are_rejected(self) -> None:
        variants = (
            "      - run: >-\n"
            "          python -m pip\n"
            "          install requests\n",
            "      - run: |\n"
            "          python -m pip \\\n"
            "            install requests\n",
            "      - env:\n"
            "          TOOL: pip\n"
            "        run: \"$TOOL\" install requests\n",
            "      - env:\n"
            "          TOOL: pip\n"
            "        run: \"${{ env.TOOL }} install requests\"\n",
            "      - run: \"pip install requests\"\n",
            "      - run: echo ready | pip install requests\n",
        )
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        for addition in variants:
            with self.subTest(addition=addition):
                workflow.write_text(approved_workflow() + addition, encoding="utf-8")
                self.assert_error_contains("package-manager command is forbidden")

    def test_workflow_dynamic_heads_fail_closed_through_wrappers_and_payloads(self) -> None:
        variants = (
            "      - shell: bash\n        run: TOOL=p''ip; $TOOL install requests\n",
            "      - shell: bash\n        run: command $TOOL install requests\n",
            "      - shell: bash\n        run: exec $TOOL install requests\n",
            "      - shell: bash\n        run: env $TOOL install requests\n",
            "      - shell: bash\n        run: sudo $TOOL install requests\n",
            "      - shell: bash\n        run: bash -c \"$CMD\"\n",
            "      - shell: bash\n        run: python -c \"$CODE\"\n",
        )
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        for addition in variants:
            with self.subTest(addition=addition):
                workflow.write_text(approved_workflow() + addition, encoding="utf-8")
                self.assert_error_contains("unsupported dynamic workflow executable")

    def test_workflow_explicit_keys_tags_and_flow_env_are_rejected(self) -> None:
        additions = (
            "      - ? run\n        : pip install requests\n",
            "      - run: !!str pip install requests\n",
            "      - env: {TOOL: pip}\n        run: echo offline\n",
            "  unsafe:\n    ? permissions\n    : write-all\n    runs-on: ubuntu-24.04\n",
        )
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        for addition in additions:
            with self.subTest(addition=addition):
                workflow.write_text(approved_workflow() + addition, encoding="utf-8")
                self.assertTrue(self.errors())

    def test_workflow_security_sensitive_tagged_keys_are_rejected(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        variants = (
            approved_workflow()
            + "      - !!str run: pip install requests\n",
            approved_workflow()
            + "      - !<tag:yaml.org,2002:str> uses: evil/action@main\n",
            approved_workflow().replace(
                "  validate:\n    runs-on:",
                "  validate:\n    !!str permissions:\n"
                "      contents: write\n    runs-on:",
            ),
        )
        for source in variants:
            with self.subTest(source=source):
                workflow.write_text(source, encoding="utf-8")
                self.assert_error_contains(
                    "YAML tags on security-sensitive mapping keys"
                )

        workflow.write_text(
            approved_workflow().replace(
                "name: Offline boundary", "!!str name: Offline boundary"
            ),
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_workflow_ambiguous_referenced_environment_is_rejected(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        workflow.write_text(
            approved_workflow()
            + "      - env:\n"
            + "          TOOL: pip\n"
            + "          TOOL: echo\n"
            + "        run: $TOOL offline\n",
            encoding="utf-8",
        )
        self.assert_error_contains("ambiguous workflow environment variable")

    def test_workflow_flow_runs_comments_and_shells_fail_closed(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        variants = (
            approved_workflow() + "      - {run: pip install requests}\n",
            approved_workflow()
            + "      - shell: bash\n"
            + "        run: echo foo#bar; pip install requests\n",
            approved_workflow()
            + "      - shell: cmd\n"
            + "        run: |\n"
            + "          echo safe # scanner must not truncate & pip install requests\n",
        )
        for source in variants:
            with self.subTest(source=source.rsplit("\n", 3)[-3:]):
                workflow.write_text(source, encoding="utf-8")
                self.assertTrue(self.errors())

    def test_workflow_dynamic_heads_prefixes_and_expansion_are_rejected(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        commands = (
            "$TOOL install requests",
            "command pip install requests",
            "exec pip install requests",
            "$'pip' install requests",
        )
        for command in commands:
            with self.subTest(command=command):
                workflow.write_text(
                    approved_workflow()
                    + "      - shell: bash\n"
                    + f"        run: {command}\n",
                    encoding="utf-8",
                )
                self.assertTrue(self.errors())

        workflow.write_text(
            approved_workflow()
            + "      - env:\n"
            + "          X: $X$X$X$X\n"
            + "        shell: bash\n"
            + "        run: $X\n",
            encoding="utf-8",
        )
        self.assert_error_contains("workflow command exceeds static analysis limits")

    def test_numeric_yaml_anchor_is_rejected_but_shell_glob_is_not(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        workflow.write_text(
            approved_workflow() + "extra: &123 safe\n",
            encoding="utf-8",
        )
        self.assert_error_contains("YAML anchors and aliases")
        workflow.write_text(
            approved_workflow()
            + "      - shell: bash\n"
            + "        run: echo *files\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_workflow_quoted_shell_data_and_unused_tool_environment_pass(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        workflow.write_text(
            approved_workflow()
            + "      - env:\n"
            + "          TOOL: pip\n"
            + "        shell: bash\n"
            + "        run: echo 'safe; pip install is unavailable'\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_workflow_metadata_is_not_treated_as_an_executable_command(self) -> None:
        workflow = self.root / ".github" / "workflows" / "ci.yml"
        workflow.write_text(
            approved_workflow()
            + "      - name: Explain why pip install is forbidden\n"
            + "        shell: bash\n"
            + "        run: echo offline\n",
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

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
