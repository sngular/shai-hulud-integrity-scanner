# Project Integrity Scanner

A script to scan Node.js projects for known vulnerabilities and suspicious patterns related to the Shai-Hulud
supply-chain attack.

## What it does

This scanner performs a multi-vector check on a project to find:

* **Compromised Dependencies:** Compares `package.json` against a list of known malicious package versions.
* **Malicious Files:** Checks for files with a known malware signature (SHA256 hash).
* **Correlated Exfiltration:** Flags files that both access environment variables (`process.env`) and contain data
  exfiltration URLs (`webhook.site`).
* **Suspicious Code:** Looks for `postinstall` hooks, hardcoded secret-scanning tools (`trufflehog`), and other
  suspicious patterns.
* **Risky Namespaces:** Warns if the project uses packages from known-compromised npm organizations (e.g., `@ctrl`).

**Important:** The content scan intentionally ignores documentation (`.md`), and TypeScript definitions (`.d.ts`) to
reduce false positives.

## Prerequisites

The script requires a POSIX environment (Linux, macOS, or Windows with WSL2) and the following tools:

* `git`
* `curl`
* `jq`
* `shasum`

## How to use

### Running on Linux/macOS/WSL

Execute the following curl INSIDE the project you want to analyze:

```bash
    curl -s https://raw.githubusercontent.com/sng-jroji/hulud-party/refs/heads/main/scan-project.sh | bash /dev/stdin
```

Or locally:

1. Make the script executable:
   ```bash
   chmod +x scan-project.sh
   ```

2. Run it against a specific project path:
    ```bash
    ./scan-project.sh /path/to/project
    ```

Of course. This is a critical piece of documentation that sets clear expectations for the tool's capabilities. It needs
to be direct and unambiguous.

Here is a concise warning section that you can add to the internal `README.md`.

---

### Running on Windows with PowerShell

If you are on Windows and prefer to use the PowerShell version of the scanner (`scan-project.ps1`), follow these steps:

1. **Download the script** into your project directory (or anywhere on your machine):

    ```powershell
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sng-jroji/hulud-party/refs/heads/main/scan-project.ps1" -OutFile "scan-project.ps1"
    ```

2. **Open PowerShell** (preferably PowerShell 7 / Windows Terminal for full UTF-8 and color support).

3. **Allow script execution** if needed (only once per system):

    ```powershell
    Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
    ```

4. **Run the scanner inside your project folder**:

    ```powershell
    .\scan-project.ps1
    ```

   Or run it against a specific project path:

    ```powershell
    .\scan-project.ps1 -Path "C:\path\to\project"
    ```

5. **Exit codes:**

    * **0:** Scan complete, no issues found.
    * **1:** Script error (e.g., a required dependency is missing).
    * **2:** Scan complete, actionable issues were found.

**Tip:** For best results on Windows, run the script in **PowerShell 7+** inside **Windows Terminal**.  
This ensures UTF-8 characters and colored output render correctly.

## ⚠️ Important note on scanning accuracy

**This scanner provides the most accurate results when a lockfile is present.**

The script automatically detects and prioritizes the most reliable dependency file available in the following order:

1. **`pnpm-lock.yaml` (Highest Accuracy):** If found, and if `pnpm` is installed, the scanner will analyze the complete
   dependency tree, including all **transitive dependencies**.
2. **`yarn.lock` (High Accuracy):** If found, and if `yarn` is installed, the scanner will analyze the complete
   dependency tree, including all **transitive dependencies**.
3. **`package-lock.json` (High Accuracy):** If found, the scanner will parse the lockfile to analyze the complete
   dependency tree, including all **transitive dependencies**.
4. **`package.json` (Fallback - Low Accuracy):** If no lockfile is found, the scanner will fall back to reading
   `package.json`. In this mode, it can **only** detect vulnerabilities in your *direct* dependencies and will be blind
   to any threats hidden in the transitive ones.

#### Best Practice

For a complete and reliable security audit, always run the scanner **after** installing your dependencies (e.g.,
`npm install`, `yarn install`, or `pnpm install`), as this guarantees a lockfile is present.

## Exit codes & example output

The script uses exit codes for automation:

* **0:** Scan complete, no issues found.
* **1:** Script error (e.g., a dependency is missing).
* **2:** Scan complete, actionable issues were found.

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
