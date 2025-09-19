<#
.SYNOPSIS
    Detects vulnerable dependencies, malicious file signatures, and other
    Indicators of Compromise (IoC) within a project.

.DESCRIPTION
    This PowerShell script is a version of the original Bash script, for Windows PowerShell.
    It analyzes a project for various security threats, including:
    - Compromised versions of npm packages.
    - Use of malicious npm namespaces.
    - File signatures (hashes) that match known malware.
    - Suspicious 'postinstall' scripts in package.json files.
    - Code patterns that indicate secret exfiltration.

    ==================================================================================
    == NOTE ON EXECUTION IN WINDOWS CMD ==
    ==================================================================================
    1. To correctly view special characters (like accents):
       - Before running the script, type this command in the same CMD window:
         chcp 65001
    2. Save this script file with the encoding "UTF-8 with BOM".
       - In VS Code, you can do this from the bottom bar.
       - In Notepad, select "UTF-8 with BOM" in the "Save As" dialog.
    ==================================================================================

.PARAMETER Path
    The path to the root folder of the project to be scanned.
    If not specified, the current directory is used.

.EXAMPLE
    .\scan-project-fixed.ps1 -Path C:\Users\user\projects\my-app

.EXAMPLE
    .\scan-project-fixed.ps1
#>
[CmdletBinding()]
param (
    [string]$Path = "."
)

# Stops the script if an error occurs. Equivalent to 'set -e'
$ErrorActionPreference = "Stop"

# Force UTF-8 for the main session
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$OutputEncoding = [System.Text.Encoding]::UTF8

# === Constants ===
$VERSION_LIST_URL = "https://raw.githubusercontent.com/sng-jroji/hulud-party/refs/heads/main/compromised-libs.txt"
$MALICIOUS_HASH = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
[string[]]$COMPROMISED_NAMESPACES = @(
    "@crowdstrike", "@art-ws", "@ngx", "@ctrl", "@nativescript-community",
    "@ahmedhfarag", "@operato", "@teselagen", "@things-factory", "@hestjs",
    "@nstudio", "@basic-ui-components-stc", "@nexe", "@thangved", "@tnf-dev",
    "@ui-ux-gang", "@yoobic"
)

# Exclusions for file searches.
[string[]]$GCI_EXCLUDES = @(
    "*.md",
    "*.d.ts"
)
[string[]]$GCI_EXCLUDE_DIRS = @(
    "node_modules",
    ".git"
)

# === Global Variables ===
$TEMP_DIR = ""

# === Functions ===

# --- Logging and Utilities ---
function Write-ErrorAndExit
{
    param([string]$Message)
    Write-Host "ERROR: $( $Message )" -ForegroundColor Red
    exit 1
}

function Write-High
{
    param([string]$Message)
    Write-Host "$( $Message )"  -ForegroundColor Red
}

function Write-Warn
{
    param([string]$Message)
    Write-Host "WARN: $( $Message )"  -ForegroundColor Yellow
}

function Write-Info
{
    param([string]$Message)
    Write-Host "INFO: $( $Message )"  -ForegroundColor Green
}

function Write-Header
{
    param([string]$Message)
    Write-Host "`n--- $( $Message ) ---" -ForegroundColor Blue
}

function Check-Dependencies {
    Write-Info "Verifying required tools (Git)..."
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-ErrorAndExit "'git' is not installed or not found in the PATH."
    }
}

function Download-List {
    param([string]$Url)
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
        return $response.Content -split ' ' | Where-Object { $_ }
    }
    catch {
        Write-ErrorAndExit "Could not download the list from $Url"
    }
}

# Gets a list of files to scan, applying exclusions
function Get-FilesToScan {
    param([string]$BasePath)
    $excludePatterns = $GCI_EXCLUDE_DIRS | ForEach-Object { [regex]::Escape($_) }
    $regexExclude = "($($excludePatterns -join '|'))"

    return Get-ChildItem -Path $BasePath -Recurse -File -Exclude $GCI_EXCLUDES | Where-Object {
        $_.FullName -notmatch $regexExclude
    }
}


# --- Analysis Modules ---

function Run-DependencyAnalysis {
    param([string]$project_path, [string]$findings_dir)
    Write-Header "Module 1: Dependency and Namespace Analysis"

    $version_findings_file = Join-Path $findings_dir "version_findings.txt"
    $namespace_findings_file = Join-Path $findings_dir "namespace_findings.txt"
    New-Item -Path $version_findings_file -ItemType File -Force | Out-Null
    New-Item -Path $namespace_findings_file -ItemType File -Force | Out-Null

    $pkg_file = Join-Path $project_path "package.json"
    if (-not (Test-Path $pkg_file)) {
        Write-Warn "package.json not found. Skipping dependency analysis."
        return
    }

    Write-Info "Scanning package.json..."
    try {
        $pkgJson = Get-Content $pkg_file -Raw | ConvertFrom-Json
        $allDependencies = @{}
        if ($pkgJson.PSObject.Properties['dependencies']) {
            $pkgJson.dependencies.PSObject.Properties | ForEach-Object { $allDependencies[$_.Name] = $_.Value }
        }
        if ($pkgJson.PSObject.Properties['devDependencies']) {
            $pkgJson.devDependencies.PSObject.Properties | ForEach-Object { $allDependencies[$_.Name] = $_.Value }
        }

        $local_packages_full = $allDependencies.GetEnumerator() | ForEach-Object {
            "$($_.Name)@$($_.Value)".Replace('^', '').Replace('~', '')
        } | Sort-Object -Unique

        Write-Info "Checking for vulnerable versions..."
        $remote_list = Download-List $VERSION_LIST_URL | ForEach-Object { $_.Replace(':', '@') } | Where-Object { $_ -notmatch ' integrity' }

        $vulnerableVersions = Compare-Object -ReferenceObject $remote_list -DifferenceObject $local_packages_full -IncludeEqual -ExcludeDifferent -PassThru
        if ($vulnerableVersions) {
            $vulnerableVersions | Out-File -FilePath $version_findings_file -Append -Encoding utf8
        }

        Write-Info "Checking for compromised namespaces..."
        foreach ($ns in $COMPROMISED_NAMESPACES) {
            $found = $allDependencies.Keys | Where-Object { $_.StartsWith("$ns/") }
            if ($found) {
                "Warning: Contains packages from the compromised namespace: $ns (Found in package.json)" | Out-File -FilePath $namespace_findings_file -Append -Encoding utf8
            }
        }
    }
    catch {
        Write-ErrorAndExit "Failed to process $pkg_file. Is it a valid JSON?"
    }
    Write-Info "Dependency analysis completed."
}

function Scan-ForMaliciousFiles {
    param([string]$project_path, [string]$findings_file)
    Write-Header "Module 2: Malware Signature Scan"
    Write-Info "Scanning file hashes for known malware..."
    New-Item -Path $findings_file -ItemType File -Force | Out-Null

    $files = Get-ChildItem -Path $project_path -Recurse -File -Include "*.js", "*.ts", "*.json" | Where-Object {
        $_.FullName -notmatch '(\.git|node_modules)' -and $_.Name -notlike "*.d.ts"
    }

    foreach ($file in $files) {
        $file_hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
        if ($file_hash -eq $MALICIOUS_HASH) {
            $relativePath = $file.FullName.Substring($project_path.Length + 1)
            $relativePath | Out-File -FilePath $findings_file -Append -Encoding utf8
        }
    }
    Write-Info "File signature scan completed."
}

function Scan-ForHooks {
    param([string]$project_path, [string]$findings_file)
    Write-Header "Module 3: 'postinstall' Hook Scan"
    Write-Info "Scanning for hooks in package.json..."
    New-Item -Path $findings_file -ItemType File -Force | Out-Null

    $jsonFiles = Get-ChildItem -Path $project_path -Recurse -File -Filter "*.json" | Where-Object { $_.FullName -notmatch '(\.git)' }
    foreach ($file in $jsonFiles) {
        try {
            $content = Get-Content $file.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($null -ne $content.scripts.postinstall) {
                "- File: $($file.FullName.Substring($project_path.Length + 1))" | Out-File -FilePath $findings_file -Append -Encoding utf8
            }
        }
        catch {
            # Ignore invalid JSON files
        }
    }
    Write-Info "Hook scan completed."
}

function Scan-Workflows {
    param([string]$project_path, [string]$findings_file)
    Write-Header "Module 4: CI/CD Workflow Scan"
    Write-Info "Scanning CI/CD workflow files..."
    New-Item -Path $findings_file -ItemType File -Force | Out-Null

    $workflows_dir = Join-Path $project_path ".github\workflows"
    if (-not (Test-Path $workflows_dir -PathType Container)) {
        Write-Info ".github/workflows directory not found, skipping."
        return
    }
    Get-ChildItem -Path $workflows_dir -Recurse -File -Filter "*.yml" | ForEach-Object {
        "- $($_.FullName.Substring($project_path.Length + 1))" | Out-File -FilePath $findings_file -Append -Encoding utf8
    }
    Write-Info "Workflow scan completed."
}

function Scan-ForCorrelatedExfiltration {
    param([string]$project_path, [string]$findings_file)
    Write-Header "Module 5: Correlated Exfiltration Scan"
    Write-Info "Scanning for correlated exfiltration with secret scanning..."
    New-Item -Path $findings_file -ItemType File -Force | Out-Null

    [string[]]$env_patterns = @('process\.env', 'os\.environ', 'getenv', 'AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN')
    [string[]]$exfil_patterns = @('webhook\.site', 'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7', 'exfiltrat')

    $env_regex = $env_patterns -join '|'
    $exfil_regex = $exfil_patterns -join '|'

    $filesToScan = Get-FilesToScan -BasePath $project_path

    foreach ($file in $filesToScan) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (($content -match $env_regex) -and ($content -match $exfil_regex)) {
             $file.FullName.Substring($project_path.Length + 1) | Out-File -FilePath $findings_file -Append -Encoding utf8
        }
    }
    Write-Info "Correlated exfiltration scan completed."
}

function Scan-ForPatterns {
    param([string]$project_path, [string]$findings_file, [string[]]$patterns, [string]$infoMessage, [string]$findingPrefix)
    Write-Header $infoMessage
    New-Item -Path $findings_file -ItemType File -Force | Out-Null

    if ($patterns.Count -eq 0) { return }
    $regex = $patterns -join '|'
    $filesToScan = Get-FilesToScan -BasePath $project_path

    if ($null -ne $filesToScan) {
        Select-String -Path $filesToScan.FullName -Pattern $regex -List -ErrorAction SilentlyContinue | ForEach-Object {
            "$findingPrefix $($_.Path.Substring($project_path.Length + 1))" | Out-File -FilePath $findings_file -Append -Encoding utf8
        }
    }

    Write-Info "Pattern scan completed."
}

function Analyze-GitState {
    param([string]$project_path, [string]$findings_file)
    Write-Header "Module 6: Git State Analysis"
    Write-Info "Analyzing git branches..."
    New-Item -Path $findings_file -ItemType File -Force | Out-Null

    if (-not (Test-Path (Join-Path $project_path ".git"))) {
        Write-Warn "Not a git repository, skipping."
        return
    }

    try {
        "All local and remote branches:" | Out-File -FilePath $findings_file -Append -Encoding utf8
        $branches = git -C $project_path branch -a
        $branches | ForEach-Object { "  $_" } | Out-File -FilePath $findings_file -Append -Encoding utf8
    } catch {
        Write-Warn "Could not execute 'git branch -a'. Make sure git is configured correctly."
    }
    Write-Info "Git state analysis completed."
}

# --- Report ---
function Generate-Report {
    param([string]$findings_dir)
    Write-Header "Scan Report"
    $total_issues = 0; $high_risk = 0; $medium_risk = 0

    # Read all results
    $file_hash = Get-Content (Join-Path $findings_dir "file_hash_findings.txt") -ErrorAction SilentlyContinue
    $malicious_activity = Get-Content (Join-Path $findings_dir "malicious_activity_findings.txt") -ErrorAction SilentlyContinue
    $workflows = Get-Content (Join-Path $findings_dir "workflow_findings.txt") -ErrorAction SilentlyContinue
    $versions = Get-Content (Join-Path $findings_dir "version_findings.txt") -ErrorAction SilentlyContinue | Sort-Object -Unique
    $namespaces = Get-Content (Join-Path $findings_dir "namespace_findings.txt") -ErrorAction SilentlyContinue
    $suspicious_patterns = Get-Content (Join-Path $findings_dir "suspicious_pattern_findings.txt") -ErrorAction SilentlyContinue
    $secret_scanning_patterns = Get-Content (Join-Path $findings_dir "secret_scanning_patterns.txt") -ErrorAction SilentlyContinue
    $hooks = Get-Content (Join-Path $findings_dir "hook_findings.txt") -ErrorAction SilentlyContinue
    $git_state = Get-Content (Join-Path $findings_dir "git_findings.txt") -ErrorAction SilentlyContinue
    $correlated_exfil = Get-Content (Join-Path $findings_dir "correlated_exfiltration_findings.txt") -ErrorAction SilentlyContinue

    # De-duplication logic
    if ($correlated_exfil) {
        $highRiskFiles = $correlated_exfil | ForEach-Object { [System.IO.Path]::GetFileName($_) }
        $suspicious_patterns = $suspicious_patterns | Where-Object { $fileName = $_.Split(' ')[-1]; $highRiskFiles -notcontains $fileName }
        $secret_scanning_patterns = $secret_scanning_patterns | Where-Object { $fileName = $_.Split(' ')[-1]; $highRiskFiles -notcontains $fileName }
        $malicious_activity = $malicious_activity | Where-Object { $fileName = $_.Split(' ')[-1]; $highRiskFiles -notcontains $fileName }
    }

    $high_risk = 0
    if ($null -ne $file_hash) { $high_risk += $file_hash.Count }
    if ($null -ne $correlated_exfil) { $high_risk += $correlated_exfil.Count }
    if ($null -ne $workflows) { $high_risk += $workflows.Count }
    if ($null -ne $versions) { $high_risk += $versions.Count }
    if ($null -ne $malicious_activity) { $high_risk += $malicious_activity.Count }

    $medium_risk = 0
    if ($null -ne $namespaces) { $medium_risk += $namespaces.Count }
    if ($null -ne $suspicious_patterns) { $medium_risk += $suspicious_patterns.Count }
    if ($null -ne $secret_scanning_patterns) { $medium_risk += $secret_scanning_patterns.Count }
    if ($null -ne $hooks) { $medium_risk += $hooks.Count }

    $total_issues = $high_risk + $medium_risk

    # If there are no issues, show success message and exit
    if ($total_issues -eq 0) {
        Write-Info "`n-----------------------------------------------------"
        Write-Info "[+] No actionable project integrity issues were found."
        Write-Info "-----------------------------------------------------`n"
        if ($git_state) {
            Write-Info "[INFO] Git State Analysis:"
            $git_state | Out-Host
        }
        return 0 # Exit code to indicate success
    }

    # If there are issues, generate the detailed report
    Write-Info "`n=============================================="
    Write-Info "         SHAI-HULUD DETECTION REPORT"
    Write-Info "=============================================="

    if ($file_hash) {
        Write-High "`n[!] CRITICAL RISK: Known Malware Signature Detected"
        Write-High "    - File with matching signature: $($file_hash)"
        Write-High "    NOTE: This is a definitive indicator of compromise. Immediate investigation is required."
    }
    if ($correlated_exfil) {
        Write-High "`n[!] HIGH RISK: Environment Scan with Exfiltration Detected"
        $correlated_exfil | ForEach-Object { Write-High "    - File: $_" }
        Write-High "    NOTE: These files access secrets AND contain data exfiltration patterns."
    }
    if ($workflows) {
        Write-High "`n[!] HIGH RISK: Malicious Workflow Files Detected"
        $workflows | ForEach-Object { Write-High $_ }
    }
    if ($versions) {
        Write-High "`n[!] HIGH RISK: Compromised Package Versions Detected"
        $versions | ForEach-Object { Write-High "    - Package: $_" }
        Write-High "    NOTE: These specific package versions are known to be compromised."
    }
    if ($malicious_activity) {
        Write-High "`n[!] HIGH RISK: Trufflehog Activity/Secret Scanning Detected"
        $malicious_activity | ForEach-Object { Write-High $_ }
        Write-High "    NOTE: These patterns indicate probable malicious credential harvesting."
    }
    if ($namespaces) {
        Write-Warn "`n[!] MEDIUM RISK: Packages from Compromised Namespaces"
        $namespaces | ForEach-Object { Write-Warn "    - $_" }
        Write-Warn "    NOTE: Carefully review the packages from these organizations."
    }
    if ($suspicious_patterns) {
        Write-Warn "`n[!] MEDIUM RISK: Suspicious Content Patterns"
        $suspicious_patterns | ForEach-Object { Write-Warn $_ }
        Write-Warn "    NOTE: Manual review is required to determine if they are malicious."
    }
    if ($secret_scanning_patterns) {
        Write-Warn "`n[!] MEDIUM RISK: Potentially Suspicious Secret Scanning Patterns"
        $secret_scanning_patterns | ForEach-Object { Write-Warn $_ }
        Write-Warn "    NOTE: These may be legitimate security tools or framework code. Manual review is recommended."
    }
    if ($hooks) {
        Write-Warn "`n[!] MEDIUM RISK: Potentially Malicious package.json Hooks"
        $hooks | ForEach-Object { Write-Warn $_ }
        Write-Warn "    NOTE: 'postinstall' scripts can run arbitrary commands and require review."
    }

    Write-Info "`n=============================================="
    Write-Info "SUMMARY:"
    Write-Info "    High/Critical Risk Issues: $high_risk"
    Write-Info "    Medium Risk Issues: $medium_risk"
    Write-Info "    Total Actionable Issues: $total_issues"
    Write-Info "=============================================="
    return 2 # Exit code to indicate that issues were found
}

# --- Main Orchestrator ---
function Main {
    Check-Dependencies
    $project_path = Resolve-Path -Path $Path
    if (-not (Test-Path $project_path -PathType Container)) {
        Write-ErrorAndExit "Project directory not found at: $project_path"
    }

    Write-Info "Scanning project at: $project_path"

    $TEMP_DIR = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $TEMP_DIR | Out-Null

    # =================================================================================
    # == START OF INITIALIZATION BLOCK ==
    # Defines an initialization script with ALL functions and variables
    # that the jobs will need in their session to avoid scope and encoding issues.
    # =================================================================================
    $InitializationScript = {
        # --- Essential Job Configuration ---
        # Force UTF-8 so that special characters work correctly.
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

        # --- Constants Required by Jobs ---
        $VERSION_LIST_URL = "https://raw.githubusercontent.com/sng-jroji/hulud-party/refs/heads/main/compromised-libs.txt"
        $MALICIOUS_HASH = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
        [string[]]$COMPROMISED_NAMESPACES = @(
            "@crowdstrike", "@art-ws", "@ngx", "@ctrl", "@nativescript-community",
            "@ahmedhfarag", "@operato", "@teselagen", "@things-factory", "@hestjs",
            "@nstudio", "@basic-ui-components-stc", "@nexe", "@thangved", "@tnf-dev",
            "@ui-ux-gang", "@yoobic"
        )
        [string[]]$GCI_EXCLUDES = @("*.md", "*.d.ts")
        [string[]]$GCI_EXCLUDE_DIRS = @("node_modules", ".git")

        # --- Utility Functions Required by Jobs ---
        # (Copied here so each job has them in its own scope)
        function Write-ErrorAndExit
        {
            param([string]$Message)
            Write-Host "ERROR: $( $Message )" -ForegroundColor Red
            exit 1
        }

        function Write-High
        {
            param([string]$Message)
            Write-Host "$( $Message )"  -ForegroundColor Red
        }

        function Write-Warn
        {
            param([string]$Message)
            Write-Host "WARN: $( $Message )"  -ForegroundColor Yellow
        }

        function Write-Info
        {
            param([string]$Message)
            Write-Host "INFO: $( $Message )"  -ForegroundColor Green
        }

        function Write-Header
        {
            param([string]$Message)
            Write-Host "`n--- $( $Message ) ---" -ForegroundColor Blue
        }

        function Get-FilesToScan {
            param([string]$BasePath)
            $excludePatterns = $GCI_EXCLUDE_DIRS | ForEach-Object { [regex]::Escape($_) }
            $regexExclude = "($($excludePatterns -join '|'))"
            return Get-ChildItem -Path $BasePath -Recurse -File -Exclude $GCI_EXCLUDES | Where-Object { $_.FullName -notmatch $regexExclude }
        }

        # --- Analysis Functions Required by Jobs ---
        function Run-DependencyAnalysis {
            param([string]$project_path, [string]$findings_dir)
            Write-Header "Module 1: Dependency and Namespace Analysis"
            $version_findings_file = Join-Path $findings_dir "version_findings.txt"
            $namespace_findings_file = Join-Path $findings_dir "namespace_findings.txt"
            New-Item -Path $version_findings_file -ItemType File -Force | Out-Null
            New-Item -Path $namespace_findings_file -ItemType File -Force | Out-Null
            $pkg_file = Join-Path $project_path "package.json"
            if (-not (Test-Path $pkg_file)) { Write-Warn "package.json not found. Skipping dependency analysis."; return }
            Write-Info "Scanning package.json..."
            try {
                $pkgJson = Get-Content $pkg_file -Raw | ConvertFrom-Json
                $allDependencies = @{}; if ($pkgJson.PSObject.Properties['dependencies']) { $pkgJson.dependencies.PSObject.Properties | ForEach-Object { $allDependencies[$_.Name] = $_.Value } }; if ($pkgJson.PSObject.Properties['devDependencies']) { $pkgJson.devDependencies.PSObject.Properties | ForEach-Object { $allDependencies[$_.Name] = $_.Value } }
                $local_packages_full = $allDependencies.GetEnumerator() | ForEach-Object { "$($_.Name)@$($_.Value)".Replace('^', '').Replace('~', '') } | Sort-Object -Unique
                Write-Info "Checking for vulnerable versions..."
                $remote_list = Download-List $VERSION_LIST_URL | ForEach-Object { $_.Replace(':', '@') } | Where-Object { $_ -notmatch ' integrity' }
                $vulnerableVersions = Compare-Object -ReferenceObject $remote_list -DifferenceObject $local_packages_full -IncludeEqual -ExcludeDifferent -PassThru
                if ($vulnerableVersions) { $vulnerableVersions | Out-File -FilePath $version_findings_file -Append -Encoding utf8 }
                Write-Info "Checking for compromised namespaces..."
                foreach ($ns in $COMPROMISED_NAMESPACES) { $found = $allDependencies.Keys | Where-Object { $_.StartsWith("$ns/") }; if ($found) { "Warning: Contains packages from the compromised namespace: $ns (Found in package.json)" | Out-File -FilePath $namespace_findings_file -Append -Encoding utf8 } }
            } catch { Write-ErrorAndExit "Failed to process $pkg_file. Is it a valid JSON?" }
            Write-Info "Dependency analysis completed."
        }
        function Scan-ForMaliciousFiles {
            param([string]$project_path, [string]$findings_file)
            Write-Header "Module 2: Malware Signature Scan"
            Write-Info "Scanning file hashes for known malware..."
            New-Item -Path $findings_file -ItemType File -Force | Out-Null
            $files = Get-ChildItem -Path $project_path -Recurse -File -Include "*.js", "*.ts", "*.json" | Where-Object { $_.FullName -notmatch '(\.git|node_modules)' -and $_.Name -notlike "*.d.ts" }
            foreach ($file in $files) { $file_hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower(); if ($file_hash -eq $MALICIOUS_HASH) { $file.FullName.Substring($project_path.Length + 1) | Out-File -FilePath $findings_file -Append -Encoding utf8 } }
            Write-Info "File signature scan completed."
        }
        function Scan-ForHooks {
            param([string]$project_path, [string]$findings_file)
            Write-Header "Module 3: 'postinstall' Hook Scan"
            Write-Info "Scanning for hooks in package.json..."
            New-Item -Path $findings_file -ItemType File -Force | Out-Null
            $jsonFiles = Get-ChildItem -Path $project_path -Recurse -File -Filter "*.json" | Where-Object { $_.FullName -notmatch '(\.git)' }
            foreach ($file in $jsonFiles) { try { $content = Get-Content $file.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue; if ($null -ne $content.scripts.postinstall) { "- File: $($file.FullName.Substring($project_path.Length + 1))" | Out-File -FilePath $findings_file -Append -Encoding utf8 } } catch { } }
            Write-Info "Hook scan completed."
        }
        function Scan-Workflows {
            param([string]$project_path, [string]$findings_file)
            Write-Header "Module 4: CI/CD Workflow Scan"
            Write-Info "Scanning CI/CD workflow files..."
            New-Item -Path $findings_file -ItemType File -Force | Out-Null
            $workflows_dir = Join-Path $project_path ".github\workflows"
            if (-not (Test-Path $workflows_dir -PathType Container)) { Write-Info ".github/workflows directory not found, skipping."; return }
            Get-ChildItem -Path $workflows_dir -Recurse -File -Filter "*.yml" | ForEach-Object { "- $($_.FullName.Substring($project_path.Length + 1))" | Out-File -FilePath $findings_file -Append -Encoding utf8 }
            Write-Info "Workflow scan completed."
        }
        function Scan-ForCorrelatedExfiltration {
            param([string]$project_path, [string]$findings_file)
            Write-Header "Module 5: Correlated Exfiltration Scan"
            Write-Info "Scanning for correlated exfiltration with secret scanning..."
            New-Item -Path $findings_file -ItemType File -Force | Out-Null
            [string[]]$env_patterns = @('process\.env', 'os\.environ', 'getenv', 'AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN')
            [string[]]$exfil_patterns = @('webhook\.site', 'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7', 'exfiltrat')
            $env_regex = $env_patterns -join '|'; $exfil_regex = $exfil_patterns -join '|'
            $filesToScan = Get-FilesToScan -BasePath $project_path
            foreach ($file in $filesToScan) { $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue; if (($content -match $env_regex) -and ($content -match $exfil_regex)) { $file.FullName.Substring($project_path.Length + 1) | Out-File -FilePath $findings_file -Append -Encoding utf8 } }
            Write-Info "Correlated exfiltration scan completed."
        }
        function Scan-ForPatterns {
            param([string]$project_path, [string]$findings_file, [string[]]$patterns, [string]$infoMessage, [string]$findingPrefix)
            Write-Info $infoMessage
            New-Item -Path $findings_file -ItemType File -Force | Out-Null
            if ($patterns.Count -eq 0) { return }
            $regex = $patterns -join '|'
            $filesToScan = Get-FilesToScan -BasePath $project_path
            if ($null -ne $filesToScan) { Select-String -Path $filesToScan.FullName -Pattern $regex -List -ErrorAction SilentlyContinue | ForEach-Object { "$findingPrefix $($_.Path.Substring($project_path.Length + 1))" | Out-File -FilePath $findings_file -Append -Encoding utf8 } }
            Write-Info "Pattern scan completed."
        }
        function Analyze-GitState {
            param([string]$project_path, [string]$findings_file)
            Write-Header "Module 6: Git State Analysis"
            Write-Info "Analyzing git branches..."
            New-Item -Path $findings_file -ItemType File -Force | Out-Null
            if (-not (Test-Path (Join-Path $project_path ".git"))) { Write-Warn "Not a git repository, skipping."; return }
            try { "All local and remote branches:" | Out-File -FilePath $findings_file -Append -Encoding utf8; $branches = git -C $project_path branch -a; $branches | ForEach-Object { "  $_" } | Out-File -FilePath $findings_file -Append -Encoding utf8 } catch { Write-Warn "Could not execute 'git branch -a'. Make sure git is configured correctly." }
            Write-Info "Git state analysis completed."
        }
    }
    # =================================================================================
    # == END OF INITIALIZATION SECTION ==
    # =================================================================================

    $final_exit_code = 0
    try {
        # Start analysis in parallel jobs
        $jobs = @()

        # CORRECTION: The desired function is invoked inside a clean ScriptBlock.
        # Arguments are passed with -ArgumentList.
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Run-DependencyAnalysis $args[0] $args[1] } -ArgumentList $project_path, $TEMP_DIR
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Scan-ForMaliciousFiles $args[0] $args[1] } -ArgumentList $project_path, (Join-Path $TEMP_DIR "file_hash_findings.txt")
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Scan-ForHooks $args[0] $args[1] } -ArgumentList $project_path, (Join-Path $TEMP_DIR "hook_findings.txt")
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Scan-Workflows $args[0] $args[1] } -ArgumentList $project_path, (Join-Path $TEMP_DIR "workflow_findings.txt")
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Scan-ForCorrelatedExfiltration $args[0] $args[1] } -ArgumentList $project_path, (Join-Path $TEMP_DIR "correlated_exfiltration_findings.txt")
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Analyze-GitState $args[0] $args[1] } -ArgumentList $project_path, (Join-Path $TEMP_DIR "git_findings.txt")
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Scan-ForPatterns $args[0] $args[1] $args[2] $args[3] $args[4] } -ArgumentList $project_path, (Join-Path $TEMP_DIR "malicious_activity_findings.txt"), @('trufflehog', 'credential.*exfiltration'), "Module 7: Malicious Activity Scan", "    - Activity found in: "
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Scan-ForPatterns $args[0] $args[1] $args[2] $args[3] $args[4] } -ArgumentList $project_path, (Join-Path $TEMP_DIR "suspicious_pattern_findings.txt"), @('webhook\.site', 'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7', 'malicious webhook endpoint'), "Module 8: Suspicious Pattern Scan", "    - Pattern found in: "
        $jobs += Start-Job -InitializationScript $InitializationScript -ScriptBlock { Scan-ForPatterns $args[0] $args[1] $args[2] $args[3] $args[4] } -ArgumentList $project_path, (Join-Path $TEMP_DIR "secret_scanning_patterns.txt"), @('credential scanning patterns', 'suspicious environment variable access', 'AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN', 'process\.env', 'os\.environ', 'getenv'), "Module 9: Secret Pattern Scan", "    - Pattern found in: "

        # Wait for all jobs to finish and receive their output (including errors)
        $jobs | Wait-Job | Receive-Job

        $final_exit_code = Generate-Report -findings_dir $TEMP_DIR
    }
    finally {
        # Clean up temporary directory
        if (Test-Path $TEMP_DIR) {
            Remove-Item -Path $TEMP_DIR -Recurse -Force
        }
        # Clean up finished jobs
        Get-Job | Remove-Job
    }

    Write-Info "Scan completed."
    exit $final_exit_code
}

# Execute the script
Main
