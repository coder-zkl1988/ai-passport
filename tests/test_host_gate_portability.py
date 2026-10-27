#!/usr/bin/env python3
"""Host tests keeping the static gate portable to macOS and Linux hosts."""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "install-actionlint.sh"
VALIDATE = ROOT / "tools" / "validate.sh"
BASH = shutil.which("bash")
# Real tools the installer needs besides the faked ones. GNU tar runs gzip itself.
REAL_TOOLS = ("awk", "cat", "chmod", "gzip", "mkdir", "rm", "tar")

FAKE_UNAME = """\
case "$1" in
    -s) echo "${FAKE_UNAME_S:-Linux}" ;;
    -m) echo x86_64 ;;
esac
"""
FAKE_CURL = """\
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--output" ]]; then
        cat "${FAKE_ACTIONLINT_ARCHIVE}" > "$2"
        exit 0
    fi
    shift
done
exit 1
"""
# GNU coreutils also verifies "<digest>  <file>" lines with --check; its plain
# digest line matches the BSD tool's.
FAKE_GNU_SHA256SUM = """\
if [[ " $* " == *" --check "* ]]; then
    read -r digest _
    [[ "${digest}" == "${FAKE_DIGEST}" ]]
    exit
fi
echo "${FAKE_DIGEST}  ${1:--}"
"""
# The BSD sha256sum shipped with recent macOS rejects GNU's --check/--status.
FAKE_BSD_SHA256SUM = """\
for arg in "$@"; do
    case "${arg}" in
        --*) echo "usage: sha256sum [-bctwz] [files ...]" >&2; exit 1 ;;
    esac
done
echo "${FAKE_DIGEST}  ${1:--}"
"""
FAKE_SHASUM = """\
[[ "$1" == "-a" && "$2" == "256" ]] || exit 2
echo "${FAKE_DIGEST}  ${3:--}"
"""


def write_script(path: Path, body: str) -> None:
    path.write_text(f"#!{BASH}\n{body}", encoding="utf-8")
    path.chmod(0o755)


def linux_amd64_checksum() -> str:
    match = re.search(
        r'Linux/x86_64\)\s*platform="linux_amd64"\s*checksum="([0-9a-f]{64})"',
        INSTALLER.read_text(encoding="utf-8"),
    )
    if not match:
        raise AssertionError("linux_amd64 checksum not found in install-actionlint.sh")
    return match.group(1)


@unittest.skipUnless(BASH, "bash is required for the shell gate")
class InstallActionlintChecksumTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ai-passport-actionlint-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.destination = self.root / "actionlint"
        for name in REAL_TOOLS:
            real = shutil.which(name)
            if real:
                write_script(self.bin / name, f'exec "{real}" "$@"\n')
        write_script(self.bin / "uname", FAKE_UNAME)
        write_script(self.bin / "curl", FAKE_CURL)

        # Stand-in release archive; the faked hash tools decide whether it matches.
        self.archive = self.root / "release.tar.gz"
        payload = b"#!/bin/sh\necho fake actionlint\n"
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo("actionlint")
            member.size = len(payload)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(payload))

    def run_installer(self, digest: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": str(self.bin),
            "FAKE_ACTIONLINT_ARCHIVE": str(self.archive),
            "FAKE_DIGEST": digest,
        }
        return subprocess.run(
            [BASH, str(INSTALLER), str(self.destination)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_installed(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stderr)
        binary = self.destination / "actionlint"
        self.assertEqual(result.stdout.strip(), str(binary))
        self.assertTrue(os.access(binary, os.X_OK))

    def test_bsd_sha256sum_without_gnu_options_verifies_archive(self) -> None:
        write_script(self.bin / "sha256sum", FAKE_BSD_SHA256SUM)
        self.assert_installed(self.run_installer(linux_amd64_checksum()))

    def test_gnu_sha256sum_verifies_archive(self) -> None:
        write_script(self.bin / "sha256sum", FAKE_GNU_SHA256SUM)
        self.assert_installed(self.run_installer(linux_amd64_checksum()))

    def test_shasum_verifies_archive_when_sha256sum_is_missing(self) -> None:
        write_script(self.bin / "shasum", FAKE_SHASUM)
        self.assert_installed(self.run_installer(linux_amd64_checksum()))

    def test_checksum_mismatch_stops_before_extraction(self) -> None:
        write_script(self.bin / "sha256sum", FAKE_BSD_SHA256SUM)
        result = self.run_installer("0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse((self.destination / "actionlint").exists())

    def test_missing_sha256_tool_fails_closed(self) -> None:
        result = self.run_installer(linux_amd64_checksum())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No SHA-256 verification tool", result.stderr)
        self.assertFalse((self.destination / "actionlint").exists())


@unittest.skipUnless(BASH, "bash is required for the shell gate")
class ValidateDeadCodeLinkerFlagTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = VALIDATE.read_text(encoding="utf-8")

    def selected_flag(self, system_name: str) -> str:
        match = re.search(
            r'^\s*if \[\[ "\$\(uname -s\)" == "Darwin" \]\]; then\n.*?^\s*fi\n',
            self.source,
            re.MULTILINE | re.DOTALL,
        )
        if not match:
            raise AssertionError("dead-code linker flag selection not found in validate.sh")
        with tempfile.TemporaryDirectory(prefix="ai-passport-ldflag-tests-") as directory:
            write_script(Path(directory) / "uname", FAKE_UNAME)
            result = subprocess.run(
                [BASH, "-c", f'{match.group(0)}printf "%s" "${{dead_code_ldflag}}"'],
                env={"PATH": directory, "FAKE_UNAME_S": system_name},
                capture_output=True,
                text=True,
                check=True,
            )
        return result.stdout

    def test_apple_ld_gets_dead_strip(self) -> None:
        self.assertEqual(self.selected_flag("Darwin"), "-Wl,-dead_strip")

    def test_gnu_ld_keeps_gc_sections(self) -> None:
        self.assertEqual(self.selected_flag("Linux"), "-Wl,--gc-sections")

    def test_demo_runtime_link_uses_the_selected_flag(self) -> None:
        match = re.search(r"for demo in [^\n]*; do\n(.*?)\n\s*done", self.source, re.DOTALL)
        if not match:
            raise AssertionError("demo runtime test loop not found in validate.sh")
        loop = match.group(1)
        self.assertIn('"${dead_code_ldflag}"', loop)
        self.assertNotIn("--gc-sections", loop)
        self.assertNotIn("-dead_strip", loop)


if __name__ == "__main__":
    unittest.main()
