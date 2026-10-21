# phplume launcher. Works in Windows PowerShell 5.1 and PowerShell 7+.
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ScanArgs)

$phplumeAsFile = $MyInvocation.MyCommand.CommandType -eq 'ExternalScript'
$phplumeUrl = 'https://raw.githubusercontent.com/daMustermann/phplume/v0.3.0/phplume.py'
$phplumeSha = '073f89765df2481634bb957401e3e6564977077cce3010c61e551785b6d9b972'
$phplumePython = $null
$phplumePrefix = @()
$phplumeDirectory = $null
$phplumeExit = 3
try {
    foreach ($phplumeCandidate in @('py', 'python3', 'python')) {
        if (Get-Command $phplumeCandidate -CommandType Application -ErrorAction SilentlyContinue) {
            $phplumeTestArgs = @()
            if ($phplumeCandidate -eq 'py') { $phplumeTestArgs = @('-3') }
            & $phplumeCandidate @phplumeTestArgs -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>$null
            if ($LASTEXITCODE -eq 0) {
                $phplumePython = $phplumeCandidate
                $phplumePrefix = $phplumeTestArgs
                break
            }
        }
    }
    if (-not $phplumePython) {
        throw 'Python 3.10 or newer is required. Install it from python.org (enable PATH), then run this command again.'
    }
    $phplumeDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('phplume-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $phplumeDirectory -ErrorAction Stop
    $phplumeFile = Join-Path $phplumeDirectory 'phplume.py'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $phplumeUrl -OutFile $phplumeFile -TimeoutSec 60 -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $phplumeFile -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -ne $phplumeSha) {
        throw 'Scanner checksum mismatch. Download stopped; please check the GitHub release.'
    }
    & $phplumePython @phplumePrefix $phplumeFile @ScanArgs
    $phplumeExit = $LASTEXITCODE
}
catch {
    [Console]::Error.WriteLine('phplume could not start: ' + $_.Exception.Message)
    $phplumeExit = 3
}
finally {
    if ($phplumeDirectory -and (Test-Path -LiteralPath $phplumeDirectory)) {
        # Only the known downloaded file and the empty, randomly named temp directory.
        $phplumeFile = Join-Path $phplumeDirectory 'phplume.py'
        if (Test-Path -LiteralPath $phplumeFile) { Remove-Item -LiteralPath $phplumeFile -Force }
        Remove-Item -LiteralPath $phplumeDirectory -Force
    }
}
$global:LASTEXITCODE = $phplumeExit
if ($phplumeAsFile) { exit $phplumeExit }
