# Project Integrity Scanner

A script to scan Node.js projects for known vulnerabilities and suspicious patterns related to the Shai-Hulud supply-chain attack.

## What it does

This scanner performs a multi-vector check on a project to find:
*   **Compromised Dependencies:** Compares `package.json` against a list of known malicious package versions.
*   **Malicious Files:** Checks for files with a known malware signature (SHA256 hash).
*   **Correlated Exfiltration:** Flags files that both access environment variables (`process.env`) and contain data exfiltration URLs (`webhook.site`).
*   **Suspicious Code:** Looks for `postinstall` hooks, hardcoded secret-scanning tools (`trufflehog`), and other suspicious patterns.
*   **Risky Namespaces:** Warns if the project uses packages from known-compromised npm organizations (e.g., `@ctrl`).

**Important:** The content scan intentionally ignores documentation (`.md`), and TypeScript definitions (`.d.ts`) to reduce false positives.

## Prerequisites

The script requires a POSIX environment (Linux, macOS, or Windows with WSL2) and the following tools:

*   `git`
*   `curl`
*   `jq`
*   `shasum`

## How to use

Execute the following curl INSIDE the project you want to analyze:

```bash
    curl -s https://raw.githubusercontent.com/sng-jroji/hulud-party/refs/heads/main/scan-project.sh | bash /dev/stdin
```

Or locally:

1.  Make the script executable:
    ```bash
    chmod +x scan-project.sh
    ```
    
2. Run it against a specific project path:
    ```bash
    ./scan-project.sh /path/to/project
    ```

## Exit codes & example output

The script uses exit codes for automation:
*   **0:** Scan complete, no issues found.
*   **1:** Script error (e.g., a dependency is missing).
*   **2:** Scan complete, actionable issues were found.

```
==============================================
      SHAI-HULUD DETECTION REPORT
==============================================

🚨 HIGH RISK: Compromised Package Versions Detected
   - Package: @ctrl/tinycolor@4.1.0
   NOTE: These specific package versions are known to be compromised.

🚨 HIGH RISK: Environment Scanning with Exfiltration Detected
   - File: src/services/telemetry-service.js
   NOTE: These files access secrets AND contain data exfiltration patterns.

⚠️ MEDIUM RISK: Packages from Compromised Namespaces
   - Warning: Contains packages from compromised namespace: @ctrl (Found in package.json)
   NOTE: Review packages from these organizations carefully.

==============================================
🔍 SUMMARY:
   High/Critical Risk Issues: 2
   Medium Risk Issues: 1
   Total Actionable Issues: 3
==============================================
```