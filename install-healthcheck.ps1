<#
.SYNOPSIS
    One-shot setup for the Rapid7 InsightVM Health Check (Windows / PowerShell).

.DESCRIPTION
    Idempotent installer (issue #27). Safe to re-run -- each step detects existing
    state and skips or reuses it. It:
      1. Verifies Python >= 3.11 is on PATH.
      2. Creates (or reuses) a .venv virtual environment.
      3. Installs/upgrades the tool into the venv (editable, from this repo).
      4. Bootstraps .env (prompts for the Security Console HTTP Basic
         username/password; secrets go ONLY to .env).
      5. Bootstraps config.yaml from docs/examples/config.yaml (prompts for the
         console base_url).
      6. Runs `python -m rapid7_healthcheck --check-connection` to validate
         connectivity before you commit to a full run.

    Secrets are written to .env and never echoed or hardcoded. Re-running never
    overwrites an existing .env or config.yaml without asking.

.EXAMPLE
    .\install-healthcheck.ps1

.EXAMPLE
    .\install-healthcheck.ps1 -SkipConnectionCheck
#>
[CmdletBinding()]
param(
    # Skip the final connectivity probe (e.g. offline setup).
    [switch]$SkipConnectionCheck
)

$ErrorActionPreference = 'Stop'
$RepoRoot = $PSScriptRoot
Set-Location $RepoRoot

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

# --- 1. Python version ------------------------------------------------------
Write-Step "Checking Python"
$pythonExe = $null
foreach ($cand in @('python', 'py -3', 'python3')) {
    try {
        $parts = $cand.Split(' ')
        $ver = & $parts[0] $parts[1..($parts.Length-1)] --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $ver -match 'Python (\d+)\.(\d+)') {
            $major = [int]$Matches[1]; $minor = [int]$Matches[2]
            if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 11)) {
                $pythonExe = $cand
                Write-Ok "found $ver via '$cand'"
                break
            } else {
                Write-Warn2 "$ver via '$cand' is too old (need >= 3.11)"
            }
        }
    } catch { }
}
if (-not $pythonExe) {
    Write-Error "No Python >= 3.11 found on PATH. Install it from https://www.python.org/downloads/ and re-run."
    exit 1
}

# --- 2. Virtual environment -------------------------------------------------
Write-Step "Setting up virtual environment (.venv)"
$venvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'
if (Test-Path $venvPython) {
    Write-Ok ".venv already exists -- reusing it"
} else {
    $parts = $pythonExe.Split(' ')
    & $parts[0] $parts[1..($parts.Length-1)] -m venv .venv
    if (-not (Test-Path $venvPython)) { Write-Error "venv creation failed"; exit 1 }
    Write-Ok "created .venv"
}

# --- 3. Install dependencies ------------------------------------------------
Write-Step "Installing the tool into .venv"
& $venvPython -m pip install --upgrade pip --quiet
# pip-system-certs makes pip and requests trust the OS certificate store, so the
# tool works behind TLS-inspecting corporate proxies (common around InsightVM
# consoles). Installed before the editable install so that step can also reach a
# proxy-intercepted PyPI.
& $venvPython -m pip install --upgrade pip-system-certs --quiet
if ($LASTEXITCODE -ne 0) { Write-Error "pip-system-certs install failed"; exit 1 }
& $venvPython -m pip install --editable . --quiet
if ($LASTEXITCODE -ne 0) { Write-Error "pip install failed"; exit 1 }
Write-Ok "installed rapid7_healthcheck and dependencies"

# --- 4. .env bootstrap ------------------------------------------------------
Write-Step "Configuring credentials (.env)"
$envPath = Join-Path $RepoRoot '.env'
if (Test-Path $envPath) {
    Write-Ok ".env already exists -- leaving it untouched"
} else {
    # Console v3 authenticates with HTTP Basic only (X-Api-Key is a v4 Insight
    # Platform mechanism the Console rejects). Prompt for username + password.
    $basicUser = Read-Host "Enter your Security Console username"
    $basicPwSecure = Read-Host "Enter your Security Console password (input hidden)" -AsSecureString
    $basicPw = [System.Net.NetworkCredential]::new('', $basicPwSecure).Password
    if ([string]::IsNullOrWhiteSpace($basicUser) -or [string]::IsNullOrWhiteSpace($basicPw)) {
        Write-Warn2 "Username or password blank -- writing a template .env you must edit before running."
        Copy-Item (Join-Path $RepoRoot '.env.example') $envPath
    } else {
        # Write only the credential lines; copy the rest of the template comments.
        $template = Get-Content (Join-Path $RepoRoot '.env.example')
        $template = $template -replace '^R7_BASIC_USER=.*$', "R7_BASIC_USER=$basicUser"
        $template = $template -replace '^R7_BASIC_PASSWORD=.*$', "R7_BASIC_PASSWORD=$basicPw"
        Set-Content -Path $envPath -Value $template -Encoding UTF8
        Write-Ok "wrote .env (credentials stored locally; not echoed)"
    }
}

# --- 5. config.yaml bootstrap ----------------------------------------------
Write-Step "Configuring the tool (config.yaml)"
$configPath  = Join-Path $RepoRoot 'config.yaml'
$examplePath = Join-Path $RepoRoot 'docs\examples\config.yaml'
if (Test-Path $configPath) {
    Write-Ok "config.yaml already exists -- leaving it untouched"
} else {
    Copy-Item $examplePath $configPath
    $baseUrl = Read-Host "Enter your Security Console base URL (blank = keep example default)"
    if (-not [string]::IsNullOrWhiteSpace($baseUrl)) {
        $cfg = Get-Content $configPath
        $cfg = $cfg -replace '(?m)^(\s*base_url:\s*).*$', "`${1}$baseUrl"
        Set-Content -Path $configPath -Value $cfg -Encoding UTF8
        Write-Ok "wrote config.yaml with base_url = $baseUrl"
    } else {
        Write-Ok "wrote config.yaml from the example template (edit base_url before running)"
    }
}

# --- 6. Connectivity check --------------------------------------------------
if ($SkipConnectionCheck) {
    Write-Step "Skipping connectivity check (-SkipConnectionCheck)"
} else {
    Write-Step "Validating connectivity (--check-connection)"
    & $venvPython -m rapid7_healthcheck --config $configPath --check-connection
    $checkExit = $LASTEXITCODE
    if ($checkExit -eq 0) {
        Write-Ok "connection OK"
    } else {
        Write-Warn2 "connectivity check failed (exit $checkExit). Edit .env / config.yaml and re-run, or use -SkipConnectionCheck."
        exit $checkExit
    }
}

Write-Step "Setup complete"
Write-Host "    Run a full health check with:" -ForegroundColor Green
Write-Host "      .\.venv\Scripts\python.exe -m rapid7_healthcheck --config config.yaml" -ForegroundColor Green
