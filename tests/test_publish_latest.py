"""Exercise release publishing with a fake gh executable; no network writes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "publish-latest.sh"

FAKE_GH = """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$GH_CALLS"
case "$1 $2" in
  'api repos/example/auditpatch/releases/latest')
    case "$SCENARIO" in
      missing|create_failure) echo 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;
      forbidden) echo 'gh: Forbidden (HTTP 403)' >&2; exit 1 ;;
      unavailable) echo 'gh: Unavailable (HTTP 503)' >&2; exit 1 ;;
      empty) echo null ;;
      *) echo existing-latest ;;
    esac
    ;;
  'release upload')
    if [[ "$SCENARIO" == upload_failure ]]; then exit 1; fi
    ;;
  'release create')
    if [[ "$SCENARIO" == create_failure ]]; then exit 1; fi
    ;;
  'release view') echo "https://github.com/example/auditpatch/releases/tag/$3" ;;
  *) echo "Unexpected gh invocation: $*" >&2; exit 2 ;;
esac
"""


class PublishLatestTest(unittest.TestCase):
    def run_publish(self, scenario, include_checksum=True):
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "Bash is required")
        with tempfile.TemporaryDirectory(prefix="auditpatch-ci-") as directory:
            work = Path(directory)
            bindir = work / "bin"
            bindir.mkdir()
            gh = bindir / "gh"
            gh.write_text(FAKE_GH, encoding="utf-8", newline="\n")
            gh.chmod(0o755)
            archive = work / "ZN-AuditPatch-release.zip"
            archive.write_bytes(b"test artifact")
            if include_checksum:
                Path(str(archive) + ".sha256").write_text("test checksum\n", encoding="utf-8")
            calls = work / "calls.txt"
            summary = work / "summary.txt"
            env = dict(os.environ)
            env.update({
                "PATH": str(bindir) + os.pathsep + env["PATH"],
                "SCENARIO": scenario,
                "GH_CALLS": calls.as_posix(),
                "GH_TOKEN": "fake-token-for-tests",
                "GITHUB_REPOSITORY": "example/auditpatch",
                "GITHUB_SHA": "1234567890abcdef1234567890abcdef12345678",
                "GITHUB_STEP_SUMMARY": summary.as_posix(),
            })
            result = subprocess.run(
                [bash, SCRIPT.as_posix(), archive.as_posix(), "v1.2.0"],
                env=env, capture_output=True, text=True, timeout=15,
            )
            commands = calls.read_text().splitlines() if calls.exists() else []
            notes = summary.read_text() if summary.exists() else ""
            return result, commands, notes

    def test_uploads_to_github_latest_not_the_version_tag(self):
        result, commands, notes = self.run_publish("existing")
        self.assertEqual(result.returncode, 0, result.stderr)
        uploads = [line for line in commands if line.startswith("release upload ")]
        self.assertEqual(len(uploads), 1)
        self.assertIn("release upload existing-latest ", uploads[0])
        self.assertIn("--clobber", uploads[0])
        self.assertIn(".zip.sha256", uploads[0])
        self.assertFalse(any(line.startswith("release create ") for line in commands))
        self.assertIn("existing-latest", notes)

    def test_bootstraps_first_stable_release_with_assets(self):
        result, commands, notes = self.run_publish("missing")
        self.assertEqual(result.returncode, 0, result.stderr)
        creates = [line for line in commands if line.startswith("release create ")]
        self.assertEqual(len(creates), 1)
        self.assertIn("release create v1.2.0 ", creates[0])
        self.assertIn("--latest", creates[0])
        self.assertIn("--target 1234567890abcdef1234567890abcdef12345678", creates[0])
        self.assertIn(".zip.sha256", creates[0])
        self.assertFalse(any(line.startswith("release upload ") for line in commands))
        self.assertIn("v1.2.0", notes)

    def test_lookup_errors_do_not_create_or_upload(self):
        for scenario in ("forbidden", "unavailable", "empty"):
            with self.subTest(scenario=scenario):
                result, commands, notes = self.run_publish(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(commands), 1)
                self.assertTrue(commands[0].startswith("api "))
                self.assertEqual(notes, "")

    def test_failed_mutations_are_not_reported_as_success(self):
        for scenario in ("upload_failure", "create_failure"):
            with self.subTest(scenario=scenario):
                result, commands, notes = self.run_publish(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(line.startswith("release view ") for line in commands))
                self.assertEqual(notes, "")

    def test_missing_assets_fail_before_contacting_github(self):
        result, commands, notes = self.run_publish("existing", include_checksum=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(commands, [])
        self.assertEqual(notes, "")


if __name__ == "__main__":
    unittest.main()
