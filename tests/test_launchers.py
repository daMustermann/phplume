"""Regression coverage for launchers invoked from agent subprocesses."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import phplume


@unittest.skipUnless(sys.platform == "win32" and shutil.which("powershell.exe"), "Windows PowerShell launcher")
class PowerShellLauncherTests(unittest.TestCase):
    def invoke(self, payload):
        env = os.environ.copy()
        env["PHPLUME_TEST_PAYLOAD"] = str(payload)
        env["PHPLUME_TEST_LAUNCHER"] = str(Path(__file__).resolve().parents[1] / "run.ps1")
        command = """
$ErrorActionPreference = 'Stop'
function Invoke-WebRequest {
    param($Uri, $OutFile, $TimeoutSec, [switch]$UseBasicParsing, $ErrorAction)
    Copy-Item -LiteralPath $env:PHPLUME_TEST_PAYLOAD -Destination $OutFile
}
function Get-FileHash { throw 'Get-FileHash is unavailable in this agent shell' }
$launcher = [scriptblock]::Create([System.IO.File]::ReadAllText($env:PHPLUME_TEST_LAUNCHER))
& $launcher '--version'
exit $LASTEXITCODE
"""
        return subprocess.run(["powershell.exe", "-NoProfile", "-Command", command],
                              capture_output=True, text=True, timeout=30, env=env)

    def test_nested_agent_shell_does_not_require_get_file_hash(self):
        run = self.invoke(Path(__file__).resolve().parents[1] / "phplume.py")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"phplume {phplume.VERSION}", run.stdout)

    def test_corrupt_download_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "corrupt.py"
            payload.write_text('raise RuntimeError("CORRUPT_PAYLOAD_EXECUTED")', encoding="utf-8")
            run = self.invoke(payload)
        self.assertEqual(run.returncode, 3, run.stderr)
        self.assertIn("checksum mismatch", run.stderr)
        self.assertNotIn("CORRUPT_PAYLOAD_EXECUTED", run.stdout + run.stderr)
