"""Static boundaries and hermetic races complement the real Chromium gate."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))
import calibrate_profile
import check_dependency_boundary
import check_pyodide_provenance


class WorkerContractTests(unittest.TestCase):
    def test_neither_interface_can_execute_python_on_the_page(self):
        for name in ("codeprobe-ui.js", "project-ui.js"):
            source = (ROOT / "app" / name).read_text(encoding="utf-8")
            self.assertNotIn(".runPython(", source)
            self.assertIn("CodeProbeRuntime.createAnalysisSession", source)
            self.assertIn("cancelAnalysis", source)
            self.assertIn("generation !==", source)

    def test_worker_has_fixed_entry_points_and_clears_payload(self):
        source = (ROOT / "app" / "analysis-worker.js").read_text(encoding="utf-8")
        self.assertIn('runtime.globals.delete("payload_json")', source)
        self.assertIn("codeprobe_runtime.codeprobe_analyze_project(payload_json)", source)
        self.assertIn("codeprobe_runtime.codeprobe_analyze(payload_json)", source)
        self.assertNotIn("runPython(message", source)
        self.assertNotIn("error.message", source)

    def test_worker_record_matches_bytes_before_any_remote_execution(self):
        source = (ROOT / "app" / "pyodide-loader.js").read_text(encoding="utf-8")
        data = (ROOT / "app" / "analysis-worker.js").read_bytes()
        record = re.search(r"const PACKAGED_WORKER_RECORD = Object.freeze\(\{(.*?)\}\);", source, re.S).group(1)
        self.assertIn(hashlib.sha256(data).hexdigest(), record)
        self.assertIn(f"size_bytes: {len(data)}", record)
        self.assertIn("integrity: script.integrity", source)
        self.assertIn("worker.terminate()", source)

    def test_worker_entry_is_not_allowed_to_install_packages(self):
        source = 'self.importScripts("https://example.invalid/untrusted.js");'
        self.assertTrue(any(pattern.search(source) for pattern, _ in check_dependency_boundary.DYNAMIC_JAVASCRIPT_LOADERS))

    def test_cancel_controls_exist_on_both_pages(self):
        for name in ("index.html", "project.html"):
            source = (ROOT / "app" / name).read_text(encoding="utf-8")
            self.assertIn('id="cancelBtn" type="button" disabled', source)
            self.assertIn("worker-src 'self' blob:", source)

    def test_large_input_highlighting_is_bounded(self):
        source = (ROOT / "app" / "codeprobe-ui.js").read_text(encoding="utf-8")
        self.assertIn("if (code.length > 50000) return escapeHtml(code);", source)

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable on this runner")
    def test_hermetic_worker_protocol_races(self):
        completed = subprocess.run(
            [shutil.which("node"), str(ROOT / "tools" / "check_worker_protocol.js")],
            cwd=ROOT, capture_output=True, text=True, timeout=45, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("21 hermetic scenarios", completed.stdout)

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable on this runner")
    def test_bounded_decoding_drop_inventory_and_worker_provenance(self):
        # The shipped loader and entry execute with finite callback/interpreter
        # doubles. Authentic browser execution remains a separate CI gate.
        script = r'''
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const loader = fs.readFileSync("app/pyodide-loader.js", "utf8");
const context = vm.createContext({Uint8Array, ArrayBuffer, TextDecoder,
  TextEncoder, setTimeout, clearTimeout});
vm.runInContext(loader, context, {timeout:1000});
const api = context.CodeProbeRuntime;
let observations = 0;
const check = (name, operation) => { operation(); observations++; };
check("UTF-8 and newline provenance", () => {
  const result = api.decodeSourceBytes(new Uint8Array([120,13,10]));
  assert.equal(result.text, "x\n");
  assert.equal(result.intake_provenance.encoding, "utf-8");
  assert.equal(result.intake_provenance.normalisation, "newlines");
  assert.equal(result.intake_provenance.warnings.length, 0);
});
check("Latin-1 preserves its authentic warning", () => {
  const result = api.decodeSourceBytes(new Uint8Array([99,97,102,233]));
  assert.equal(result.text, "café");
  assert.equal(result.intake_provenance.encoding, "latin-1");
  assert.deepEqual(Array.from(result.intake_provenance.warnings),
    ["Decoded as latin-1; review the file encoding."]);
});
check("UTF-8 BOM provenance", () => {
  const result = api.decodeSourceBytes(new Uint8Array([239,187,191,120]));
  assert.equal(result.text, "x");
  assert.equal(result.intake_provenance.encoding, "utf-8-sig");
});
for (const position of [0,4095,4096,4999]) check("full candidate NUL " + position, () => {
  const bytes = new Uint8Array(5000).fill(120); bytes[position] = 0;
  assert.throws(() => api.decodeSourceBytes(bytes), error => error.intakeReason === "undecodable_text");
});
check("byte limit precedes NUL policy", () => {
  assert.throws(() => api.decodeSourceBytes(new Uint8Array(1000001)),
    error => error.intakeReason === "file_too_large");
});
const provenance = {encoding:"latin-1",normalisation:"newlines",warnings:["<em>review encoding</em>"]};
check("plain text survives without becoming authenticated", () => {
  const output = api.validateIntakeProvenance(provenance);
  assert.equal(output.warnings[0], "<em>review encoding</em>");
  assert.equal(output.source, undefined);
});
check("warning limit counts Unicode characters", () => {
  const output = api.validateIntakeProvenance({...provenance,warnings:["\u{1f600}".repeat(512)]});
  assert.equal(Array.from(output.warnings[0]).length,512);
});
for (const invalid of [null, [], {...provenance,source:"native-intake"},
  {...provenance,encoding:"trusted"}, {...provenance,normalisation:"anything"},
  {...provenance,warnings:Array(9).fill("x")}, {...provenance,warnings:["x".repeat(513)]},
  {...provenance,warnings:["\u001b[31m"]}, {...provenance,warnings:["\u0085"]},
  {...provenance,warnings:["\u{1f600}".repeat(513)]},
  {...provenance,warnings:["\ud800"]}, {...provenance,warnings:["\udfff"]}]) {
  check("invalid provenance", () => assert.throws(() => api.validateIntakeProvenance(invalid)));
}
async function run() {
  const files = [{name:"a.py"},{name:"b.py"}];
  const item = file => ({kind:"file",webkitGetAsEntry:() => file &&
    ({isFile:true,file:resolve => resolve(file)})});
  let result = await api.collectDroppedFiles({items:files.map(item),files});
  assert.equal(result.length, 2); assert.equal(result[0], files[0]); assert.equal(result[1], files[1]); observations++;
  result = await api.collectDroppedFiles({items:[item(null),item(null)],files});
  assert.equal(result.length, 2); assert.equal(result[0], files[0]); assert.equal(result[1], files[1]); observations++;
  for (const items of [[item(files[0]),item(null)],[item(null),item(files[1])]]) {
    await assert.rejects(api.collectDroppedFiles({items,files}), /incomplete/); observations++;
  }
  await assert.rejects(api.collectDroppedFiles({items:[item(null),item(null)],files:[files[0]]}), /incomplete/); observations++;
  await assert.rejects(api.collectDroppedFiles({items:[{kind:"file",webkitGetAsEntry:() =>
    ({isFile:true,file:resolve => {resolve(files[0]);resolve(files[1]);}})}]}), /repeated a callback/); observations++;

  const replies = [], supplied = [];
  const runtime = {FS:{writeFile() {}}, globals:{set(_key,value) {supplied.push(JSON.parse(value));},delete() {}},
    runPython(command) {return command === "import codeprobe_runtime" ? null : "{}";}};
  const worker = vm.createContext({Uint8Array,JSON,Number,Object,Array,
    self:{CodeProbeRuntime:{...api,loadVerifiedPyodide:async () => runtime,
      loadVerifiedEngine:async () => ({copyBytes:() => new Uint8Array([1]),fingerprint:{source:"fixture"}}),
      getBootstrapConsumption:() => ({})},postMessage:message => replies.push(message)}});
  vm.runInContext(fs.readFileSync("app/analysis-worker.js","utf8"),worker,{timeout:1000});
  await worker.self.onmessage({data:{id:1,type:"init",manual:null}});
  for (const [kind,payload] of [["file",{code:"x=1",intake_provenance:provenance}],
    ["project",{files:[{path:"a.py",content:"x=1",intake_provenance:provenance}]}]]) {
    await worker.self.onmessage({data:{id:replies.length+1,type:"analyse",kind,payloadJson:JSON.stringify(payload)}});
    assert.equal(replies.at(-1).error, undefined);
    const actual = supplied.at(-1);
    assert.deepEqual((actual.files ? actual.files[0] : actual).intake_provenance,provenance); observations++;
  }
  const before = supplied.length;
  await worker.self.onmessage({data:{id:99,type:"analyse",kind:"file",payloadJson:JSON.stringify({code:"x=1",
    intake_provenance:{...provenance,source:"native-intake"}})}});
  assert.equal(replies.at(-1).error,true); assert.equal(supplied.length,before); observations++;
  console.log("intake protocol observations: " + observations);
}
run().catch(error => {console.error(error);process.exitCode=1;});
'''
        completed = subprocess.run(
            [shutil.which("node"), "-"], input=script, cwd=ROOT,
            capture_output=True, text=True, timeout=45, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("intake protocol observations: 31", completed.stdout)

    def test_an_extra_worker_import_is_rejected_by_the_actual_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "app", root / "app")
            path = root / "app" / "pyodide-loader.js"
            with path.open("a", encoding="utf-8") as stream:
                stream.write('\nself.importScripts("unreviewed.js");\n')
            errors = check_dependency_boundary.check_javascript_package_loading(root)
            self.assertTrue(any("dynamic worker import" in error for error in errors), errors)

    def test_worker_size_cannot_pass_as_a_decimal_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "app", root / "app")
            shutil.copytree(ROOT / "src", root / "src")
            path = root / "app" / "pyodide-loader.js"
            source = path.read_text(encoding="utf-8")
            size = len((root / "app" / "analysis-worker.js").read_bytes())
            source = source.replace(f"size_bytes: {size},", f"size_bytes: {size}0,")
            path.write_text(source, encoding="utf-8")
            errors = check_pyodide_provenance.audit_pyodide_provenance(root)
            self.assertTrue(any("worker integrity record differs" in error for error in errors), errors)

    def test_real_browser_gate_covers_both_pages_without_a_worker_double(self):
        source = (ROOT / "tools" / "check_browser_functional.js").read_text(encoding="utf-8")
        self.assertIn("testWorkerResponsiveness(cdp, baseUrl, state, false)", source)
        self.assertIn("testWorkerResponsiveness(cdp, baseUrl, state, true)", source)
        self.assertIn("testTamperedWorkerBootstrap", source)
        self.assertIn("LEGAL_BUSY_SOURCE", source)
        self.assertNotIn("class Worker", source)

    def test_governance_metadata_does_not_invent_authorship_or_enforcement(self):
        citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
        owners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        self.assertEqual(json.loads(citation)["authors"], [{"family-names": "Clim", "given-names": "Antonio"}])
        self.assertIn("CodeProbe contributors", licence)
        self.assertNotIn("doi", json.loads(citation))
        self.assertTrue(all("orcid" not in author for author in json.loads(citation)["authors"]))
        self.assertIn("* @antonioclim", owners)
        self.assertIn("does not establish", owners)
        self.assertTrue((ROOT / "SECURITY.md").is_file())
        self.assertTrue((ROOT / "docs" / "21-runtime-lifecycle.md").is_file())


class OpaqueCalibrationIdentifierTests(unittest.TestCase):
    @staticmethod
    def observations():
        return [
            calibrate_profile.SampleResult(
                path=f"alice-{index}.py", label="human" if index % 2 == 0 else "ai",
                kind="file", language="python", score=.2 if index % 2 == 0 else .8,
                applicable=True, sloc=20, verdict_class="low", sample_id=f"private-name-{index}",
                split="fit" if index < 4 else "evaluation", group_id=f"group-person-{index // 2}-{index % 2}",
            ) for index in range(8)
        ]

    def test_tokens_are_fresh_and_contain_no_source_or_declared_identifiers(self):
        rows = self.observations()
        first = calibrate_profile.build_profile({}, rows, .1)
        second = calibrate_profile.build_profile({}, rows, .1)
        left = first["validation"]["sample_results"]
        right = second["validation"]["sample_results"]
        self.assertTrue({row["sample_id"] for row in left}.isdisjoint(row["sample_id"] for row in right))
        self.assertTrue({row["group_id"] for row in left}.isdisjoint(row["group_id"] for row in right))
        serialised = json.dumps(first)
        self.assertNotIn("alice", serialised)
        self.assertNotIn("private-name", serialised)
        self.assertNotIn("group-person", serialised)
        self.assertEqual(first["review_policy"], second["review_policy"])
        self.assertFalse(first["validation"]["identifier_policy"]["mapping_exported"])

    def test_estimation_and_partition_assignment_do_not_depend_on_export_tokens(self):
        rows = self.observations()
        first = calibrate_profile.build_profile({}, rows, .1)
        second = calibrate_profile.build_profile({}, rows, .1)
        for field in ("evaluation_design", "fit_at_selected_trigger", "evaluation_at_selected_trigger", "sensitivity"):
            self.assertEqual(first["validation"][field], second["validation"][field])
        for left, right in zip(first["validation"]["sample_results"], second["validation"]["sample_results"]):
            for field in ("split", "score", "label", "language", "sloc"):
                self.assertEqual(left[field], right[field])

    def test_group_equality_is_retained_within_one_export(self):
        rows = self.observations()
        rows[2].group_id = rows[0].group_id
        output = calibrate_profile._opaque_sample_results(rows)
        self.assertEqual(output[0]["group_id"], output[2]["group_id"])
        self.assertNotEqual(output[0]["sample_id"], output[2]["sample_id"])
        for row in output:
            self.assertEqual(row["path"], row["sample_id"])
            self.assertRegex(row["sample_id"], r"^sample-[0-9a-f]{32}$")
        self.assertEqual(rows[0].path, "alice-0.py")

    def test_explicit_split_leakage_is_still_rejected_before_tokenisation(self):
        rows = self.observations()
        rows[4].group_id = rows[0].group_id
        with self.assertRaisesRegex(ValueError, "one partition"):
            calibrate_profile.build_profile({}, rows, .1)


if __name__ == "__main__":
    unittest.main()
