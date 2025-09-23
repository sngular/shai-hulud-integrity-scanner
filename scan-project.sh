#!/bin/bash

# Detects vulnerable dependencies, malicious file signatures, and other
# behavioral indicators of compromise within a project.
#
# Usage: ./scan-project.sh [path/to/project/root]

set -euo pipefail

# === Constants ===
readonly VERSION_LIST_URL="https://raw.githubusercontent.com/sngular/shai-hulud-integrity-scanner/refs/heads/main/compromised-libs.txt"
readonly MALICIOUS_HASHES=(
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6"
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3"
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e"
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db"
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c"
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"
    "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b"
    "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee"
)
COMPROMISED_NAMESPACES=(
    "@crowdstrike"
    "@art-ws"
    "@ngx"
    "@ctrl"
    "@nativescript-community"
    "@ahmedhfarag"
    "@operato"
    "@teselagen"
    "@things-factory"
    "@hestjs"
    "@nstudio"
    "@basic-ui-components-stc"
    "@nexe"
    "@thangved"
    "@tnf-dev"
    "@ui-ux-gang"
    "@yoobic"
)

readonly GREP_EXCLUDES=(
    --exclude-dir=".git"
    --exclude-dir="node_modules"
    --exclude="*.md"
    --exclude="*.d.ts"
)

# Color constants.
if [[ -t 1 && "$(tput colors 2>/dev/null)" -ge 8 ]]; then
    C_RED=$(tput setaf 1); C_GREEN=$(tput setaf 2); C_YELLOW=$(tput setaf 3)
    C_BLUE=$(tput setaf 4); C_BOLD=$(tput bold); C_RESET=$(tput sgr0)
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi
readonly C_RED C_GREEN C_YELLOW C_BLUE C_BOLD C_RESET

# === Global Variables ===
TEMP_DIR=""

# --- Logging & Utilities ---
error() { echo -e "${C_RED}${C_BOLD}ERROR:${C_RESET} $1" >&2; exit 1; }
warn() { echo -e "${C_YELLOW}${C_BOLD}WARN:${C_RESET} $1" >&2; }
info() { echo -e "${C_GREEN}INFO:${C_RESET} $1" >&2; }
header() { echo -e "\n${C_BLUE}${C_BOLD}--- $1 ---${C_RESET}"; }

check_dependencies() { info "Verifying required tools (jq, curl, git, shasum)..."; for cmd in jq curl git shasum; do command -v "$cmd" &>/dev/null || error "'$cmd' is not installed."; done; }
download_list() { curl -sSL "$1" | tr ' ' '\n' | grep -v '^$' || error "Failed to download list from $1"; }

# --- Dependency Parsers ---

parse_pnpm_lock() {
    local project_path="$1"
    info "Found pnpm-lock.yaml. Analyzing full dependency tree with PNPM..."
    cd "$project_path" && pnpm list --json --prod --dev 2>/dev/null | \
        jq -r '.[] | .dependencies // {} | to_entries[] | "\(.key)@\(.value.version)"' | \
        sort -u || { warn "The 'pnpm list' command failed. Please run 'pnpm install'."; return 1; }
}

parse_npm_lock() {
    local npm_lock_file="$1"
    info "Found package-lock.json. Analyzing full dependency tree..."

    if jq -e '.packages' "$npm_lock_file" >/dev/null 2>&1; then
        # Modern (v7+) package-lock.json format
        jq -r '
            .packages | to_entries[]
            | select(.key != "" and .value.version)
            | "\(.key | ltrimstr("node_modules/"))@\(.value.version)"
        ' "$npm_lock_file" | sort -u || { warn "Failed to parse modern package-lock.json."; return 1; }
    else
        # Legacy (v6) package-lock.json format
        jq -r '
            def walk_deps(obj):
                if obj then
                    to_entries[]
                    | select(.value.version)
                    | "\(.key)@\(.value.version)", ( .value.dependencies? | walk_deps )
                else empty end;
            .dependencies? | walk_deps
        ' "$npm_lock_file" | sort -u || { warn "Failed to parse legacy package-lock.json."; return 1; }
    fi
}

parse_yarn_lock() {
    local project_path="$1"
    local pkg_file="${project_path}/package.json"

    info "Found yarn.lock. Detecting Yarn version..."

    local is_modern_yarn=false
    if jq -e '.packageManager' "$pkg_file" >/dev/null 2>&1; then
        if jq -r '.packageManager' "$pkg_file" | grep -q '^yarn@[2-9]\.'; then
            is_modern_yarn=true
        fi
    elif yarn --version | grep -q '^[2-9]\.'; then
        is_modern_yarn=true
    fi

    if [[ "$is_modern_yarn" == true ]]; then
        info "Modern Yarn (v2+) detected. Using 'yarn info'..."
        (cd "$project_path" && yarn info --json 2>/dev/null | \
            jq -r '.value' | sed 's/@npm:/@/' | sort -u) || \
            { warn "The 'yarn info' command failed. Please run 'yarn install'."; return 1; }
    else
        info "Classic Yarn (v1) detected. Using 'yarn list'..."
        (cd "$project_path" && yarn list --json --no-progress 2>/dev/null | \
            jq -r '.. | .name? | select(. != null)' | \
            sort -u) || \
            { warn "The 'yarn list' command failed. The project may have no dependencies installed."; return 1; }
    fi
}

parse_package_json() {
    local pkg_file="$1"
    warn "No lockfile found. Falling back to package.json (will miss transitive dependencies)."
    info "Scanning package.json..."
    jq -r '(.dependencies // {}) + (.devDependencies // {}) | to_entries[] | "\(.key)@\(.value)"' "$pkg_file" | \
    sed 's/[\^~]//g' | sort -u || { error "Failed to parse package.json."; return 1; }
}

# --- Main dependency analysis dispatcher ---

run_dependency_analysis() {
    local project_path="$1"; local findings_dir="$2"
    header "Module 1: Dependency & Namespace Analysis"

    local version_findings_file="${findings_dir}/version_findings.txt"; touch "$version_findings_file"
    local namespace_findings_file="${findings_dir}/namespace_findings.txt"; touch "$namespace_findings_file"

    local pnpm_lock_file="${project_path}/pnpm-lock.yaml"
    local yarn_lock_file="${project_path}/yarn.lock"
    local npm_lock_file="${project_path}/package-lock.json"
    local pkg_file="${project_path}/package.json"
    local local_packages_full=""

    if [[ ! -f "$pkg_file" ]]; then
        warn "No package.json found. Skipping all dependency analysis."; return
    fi

    if [[ -f "$pnpm_lock_file" ]] && command -v pnpm &>/dev/null; then
        local_packages_full=$(parse_pnpm_lock "$project_path")
    elif [[ -f "$yarn_lock_file" ]] && command -v yarn &>/dev/null; then
        local_packages_full=$(parse_yarn_lock "$project_path")
    elif [[ -f "$npm_lock_file" ]]; then
        local_packages_full=$(parse_npm_lock "$npm_lock_file")
    else
        local_packages_full=$(parse_package_json "$pkg_file")
    fi

    if [[ -z "$local_packages_full" ]]; then
        warn "Could not determine local packages. Skipping version check."
    else
        info "Checking for vulnerable versions..."
        local remote_list_file="${findings_dir}/remote_list.txt"
        download_list "$VERSION_LIST_URL" | sed 's/:/@/' | grep -v ' integrity' > "$remote_list_file"
        grep -F -x -f "$remote_list_file" <(echo "$local_packages_full") >> "$version_findings_file" || true
    fi

    info "Checking for compromised namespaces..."
    for ns in "${COMPROMISED_NAMESPACES[@]}"; do
        if grep -q "\"${ns}/" "$pkg_file" 2>/dev/null; then
            echo "Warning: Contains packages from compromised namespace: ${ns} (Found in package.json)" >> "$namespace_findings_file"
        fi
    done
    info "Dependency analysis complete."
}

# --- Analysis Modules ---

run_project_analysis() {
    local project_path="$1"; local findings_dir="$2"
    header "Module 2: Project Structure & Content Analysis"
    scan_for_malicious_files "$project_path" "${findings_dir}/file_hash_findings.txt" &
    local hash_pid=$!
    scan_for_hooks "$project_path" "${findings_dir}/hook_findings.txt" &
    local hooks_pid=$!
    scan_workflows "$project_path" "${findings_dir}/workflow_findings.txt" &
    local workflows_pid=$!
    scan_for_correlated_exfiltration "$project_path" "${findings_dir}/correlated_exfiltration_findings.txt" &
    local exfil_pid=$!
    scan_for_malicious_activity "$project_path" "${findings_dir}/malicious_activity_findings.txt" &
    local activity_pid=$!
    scan_for_suspicious_patterns "$project_path" "${findings_dir}/suspicious_pattern_findings.txt" &
    local patterns_pid=$!
    scan_for_secret_scanning_patterns "$project_path" "${findings_dir}/secret_scanning_patterns.txt" &
    local secrets_pid=$!
    analyze_git_state "$project_path" "${findings_dir}/git_findings.txt" &
    local git_pid=$!

    wait $hash_pid $hooks_pid $workflows_pid $exfil_pid $activity_pid $patterns_pid $secrets_pid $git_pid
}

scan_for_malicious_files() {
    local project_path="$1"; local findings_file="$2"
    info "Scanning file hashes for known malware..."
    touch "$findings_file"
    find "$project_path" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" \) \
        -not -path '*/node_modules/*' -not -path '*/.git/*' -not -name '*.d.ts' -print0 | \
    while IFS= read -r -d '' file; do
        if [[ -f "$file" && -r "$file" ]]; then
            local file_hash
            file_hash=$(shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1)
            if printf "%s\n" "${MALICIOUS_HASHES[@]}" | grep -q -x "$file_hash"; then
                echo "${file#"$project_path/"}" >> "$findings_file"
            fi
        fi
    done
    info "File signature scan complete."
}

scan_for_hooks() {
    local project_path="$1"; local findings_file="$2"
    info "Scanning for package.json hooks..."
    touch "$findings_file"

    find "$project_path" -type f -name "*.json" -not -path "*.git/*" -print0 | \
    xargs -0 jq -r 'if (.name and .version and .scripts.postinstall) then input_filename else empty end' 2>/dev/null | \
    sed "s|^${project_path}/|- File: |" >> "$findings_file" || true

    info "Hook scan complete."
}

scan_workflows() {
    local project_path="$1"; local findings_file="$2"
    info "Scanning CI/CD workflow files..."
    touch "$findings_file"
    local workflows_dir="${project_path}/.github/workflows"
    if [[ ! -d "$workflows_dir" ]]; then info "No .github/workflows directory found, skipping."; return; fi
    find "$workflows_dir" -type f -name "*.yml" -print0 | while IFS= read -r -d $'\0' file; do
        echo "- ${file#"$project_path/"}" >> "$findings_file"
    done
    info "Workflow scan complete."
}

scan_for_correlated_exfiltration() {
    local project_path="$1"; local findings_file="$2"
    info "Scanning for correlated secret scanning and exfiltration..."
    touch "$findings_file"

    local env_patterns=('process\.env' 'os\.environ' 'getenv' 'AWS_ACCESS_KEY' 'GITHUB_TOKEN' 'NPM_TOKEN')
    local exfil_patterns=('webhook\.site' 'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7' 'exfiltrat')

    local env_grep_pattern; env_grep_pattern=$(printf "%s\n" "${env_patterns[@]}")
    local exfil_grep_pattern; exfil_grep_pattern=$(printf "%s\n" "${exfil_patterns[@]}")

    grep -lE "$(echo "$env_grep_pattern" | tr '\n' '|' | sed 's/|$//')" -r "$project_path" "${GREP_EXCLUDES[@]}" 2>/dev/null | \
    xargs -I{} grep -lE "$(echo "$exfil_grep_pattern" | tr '\n' '|' | sed 's/|$//')" "{}" 2>/dev/null | \
    sed "s|^${project_path}/||" >> "$findings_file" || true

    info "Correlated exfiltration scan complete."
}

scan_for_malicious_activity() {
    local project_path="$1"; local findings_file="$2"
    info "Scanning for high-risk malicious activity..."
    touch "$findings_file"
    local patterns=('trufflehog' 'credential.*exfiltration')
    local grep_pattern; grep_pattern=$(printf "|%s" "${patterns[@]}"); grep_pattern=${grep_pattern:1}
    grep -Eirl "$grep_pattern" "$project_path" "${GREP_EXCLUDES[@]}" | sed "s|^${project_path}/|   - Activity found in: |" >> "$findings_file" || true
    info "Malicious activity scan complete."
}

scan_for_suspicious_patterns() {
    local project_path="$1"; local findings_file="$2"
    info "Scanning for suspicious content patterns..."
    touch "$findings_file"
    local patterns=('webhook\.site' 'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7' 'malicious webhook endpoint')
    local grep_pattern; grep_pattern=$(printf "|%s" "${patterns[@]}"); grep_pattern=${grep_pattern:1}
    grep -Eirl "$grep_pattern" "$project_path" "${GREP_EXCLUDES[@]}" | sed "s|^${project_path}/|   - Pattern found in: |" >> "$findings_file" || true
    info "Suspicious pattern scan complete."
}

scan_for_secret_scanning_patterns() {
    local project_path="$1"; local findings_file="$2"
    info "Scanning for secret scanning patterns..."
    touch "$findings_file"
    local patterns=('credential scanning patterns' 'suspicious environment variable access' 'AWS_ACCESS_KEY' 'GITHUB_TOKEN' 'NPM_TOKEN' 'process\.env' 'os\.environ' 'getenv')
    local grep_pattern; grep_pattern=$(printf "|%s" "${patterns[@]}"); grep_pattern=${grep_pattern:1}
    grep -Eirl "$grep_pattern" "$project_path" "${GREP_EXCLUDES[@]}" | sed "s|^${project_path}/|   - Pattern found in: |" >> "$findings_file" || true
    info "Secret scanning pattern scan complete."
}

analyze_git_state() {
    local project_path="$1"; local findings_file="$2"
    info "Analyzing git branches..."
    touch "$findings_file"
    if ! git -C "$project_path" rev-parse --is-inside-work-tree >/dev/null 2>/dev/null; then warn "Not a git repository, skipping."; return; fi
    { echo "All local and remote branches:"; git -C "$project_path" branch -a | sed 's/^/  /'; } >> "$findings_file"
    info "Git state analysis complete."
}

# --- Reporting ---
generate_report() {
    local findings_dir="$1"; header "Scan Report"
    local total_issues=0; local high_risk=0; local medium_risk=0; local report=""

    local file_hash malicious_activity workflows versions namespaces
    local suspicious_patterns secret_scanning_patterns hooks git_state correlated_exfil

    file_hash=$(sed '/^\s*$/d' "${findings_dir}/file_hash_findings.txt")
    malicious_activity=$(sed '/^\s*$/d' "${findings_dir}/malicious_activity_findings.txt")
    workflows=$(sed '/^\s*$/d' "${findings_dir}/workflow_findings.txt")
    versions=$(sort -u "${findings_dir}/version_findings.txt" | sed '/^\s*$/d')
    namespaces=$(sed '/^\s*$/d' "${findings_dir}/namespace_findings.txt")
    suspicious_patterns=$(sed '/^\s*$/d' "${findings_dir}/suspicious_pattern_findings.txt")
    secret_scanning_patterns=$(sed '/^\s*$/d' "${findings_dir}/secret_scanning_patterns.txt")
    hooks=$(sed '/^\s*$/d' "${findings_dir}/hook_findings.txt")
    git_state=$(sed '/^\s*$/d' "${findings_dir}/git_findings.txt")
    correlated_exfil=$(sed '/^\s*$/d' "${findings_dir}/correlated_exfiltration_findings.txt")

    # De-duplication logic: Remove medium-risk findings for files already flagged as high-risk
    if [[ -n "$correlated_exfil" ]]; then
        suspicious_patterns=$(echo "$suspicious_patterns" | grep -vFf <(echo "$correlated_exfil" | sed 's/:.*//') 2>/dev/null) || true
        secret_scanning_patterns=$(echo "$secret_scanning_patterns" | grep -vFf <(echo "$correlated_exfil" | sed 's/:.*//') 2>/dev/null) || true
        malicious_activity=$(echo "$malicious_activity" | grep -vFf <(echo "$correlated_exfil" | sed 's/:.*//') 2>/dev/null) || true
    fi

    if [[ -n "$file_hash" ]]; then
        report+="${C_RED}🚨 CRITICAL RISK: Known Malware Signature Detected${C_RESET}\n   - File with matching signature: ${file_hash}\n   NOTE: This is a definitive indicator of compromise. Immediate investigation is required.\n\n"
        high_risk=$((high_risk + 1))
    fi
    if [[ -n "$correlated_exfil" ]]; then
        report+="${C_RED}🚨 HIGH RISK: Environment Scanning with Exfiltration Detected${C_RESET}\n$(echo "$correlated_exfil" | sed 's/^/   - File: /')\n   NOTE: These files access secrets AND contain data exfiltration patterns.\n\n"
        high_risk=$((high_risk + $(echo "$correlated_exfil" | wc -l | tr -d ' ')))
    fi
    if [[ -n "$workflows" ]]; then
        report+="${C_RED}🚨 HIGH RISK: Malicious Workflow Files Detected${C_RESET}\n${workflows}\n\n"
        high_risk=$((high_risk + $(echo "$workflows" | wc -l | tr -d ' ')))
    fi
     if [[ -n "$versions" ]]; then
        report+="${C_RED}🚨 HIGH RISK: Compromised Package Versions Detected${C_RESET}\n$(echo "$versions" | sed 's/^/   - Package: /')\n   NOTE: These specific package versions are known to be compromised.\n\n"
        high_risk=$((high_risk + $(echo "$versions" | wc -l | tr -d ' ')))
    fi
    if [[ -n "$malicious_activity" ]]; then
        report+="${C_RED}🚨 HIGH RISK: Trufflehog/Secret Scanning Activity Detected${C_RESET}\n${malicious_activity}\n   NOTE: These patterns indicate likely malicious credential harvesting.\n\n"
        high_risk=$((high_risk + $(echo "$malicious_activity" | wc -l | tr -d ' ')))
    fi
    if [[ -n "$namespaces" ]]; then
        report+="${C_YELLOW}⚠️ MEDIUM RISK: Packages from Compromised Namespaces${C_RESET}\n$(echo "$namespaces" | sed 's/^/   - /')\n   NOTE: Review packages from these organizations carefully.\n\n"
        medium_risk=$((medium_risk + $(echo "$namespaces" | wc -l | tr -d ' ')))
    fi
    if [[ -n "$suspicious_patterns" ]]; then
        report+="${C_YELLOW}⚠️ MEDIUM RISK: Suspicious Content Patterns${C_RESET}\n${suspicious_patterns}\n   NOTE: Manual review required to determine if these are malicious.\n\n"
        medium_risk=$((medium_risk + $(echo "$suspicious_patterns" | wc -l | tr -d ' ')))
    fi
    if [[ -n "$secret_scanning_patterns" ]]; then
        report+="${C_YELLOW}⚠️ MEDIUM RISK: Potentially Suspicious Secret Scanning Patterns${C_RESET}\n${secret_scanning_patterns}\n   NOTE: These may be legitimate security tools or framework code. Manual review recommended.\n\n"
        medium_risk=$((medium_risk + $(echo "$secret_scanning_patterns" | wc -l | tr -d ' ')))
    fi
    if [[ -n "$hooks" ]]; then
        report+="${C_YELLOW}⚠️ MEDIUM RISK: Potentially Malicious package.json Hooks${C_RESET}\n${hooks}\n   NOTE: 'postinstall' scripts can execute arbitrary commands and require review.\n\n"
        medium_risk=$((medium_risk + $(echo "$hooks" | wc -l | tr -d ' ')))
    fi

    total_issues=$((high_risk + medium_risk))
    if [[ "$total_issues" -gt 0 ]]; then
        echo -e "\n=============================================="
        echo -e "      SHAI-HULUD DETECTION REPORT"
        echo -e "=============================================="
        echo -e "\n$report"
        echo -e "=============================================="
        echo -e "🔍 SUMMARY:"
        echo -e "   High/Critical Risk Issues: $high_risk"
        echo -e "   Medium Risk Issues: $medium_risk"
        echo -e "   Total Actionable Issues: $total_issues"
        echo -e "=============================================="
        return 2
    else
        echo -e "\n-----------------------------------------------------"
        info "${C_GREEN}✅ No actionable project integrity issues found.${C_RESET}"
        echo -e "-----------------------------------------------------\n"
        if [[ -n "$git_state" ]]; then echo -e "${C_BLUE}[INFO] Git State Analysis:${C_RESET}\n${git_state}"; fi
        return 0
    fi
}

# --- Main Orchestrator ---
main() {
    check_dependencies
    local project_path="${1:-.}"; project_path=$(realpath "$project_path")
    [[ -d "$project_path" ]] || error "Project directory not found at: $project_path"
    info "Scanning project at: $project_path"
    TEMP_DIR=$(mktemp -d); trap 'rm -rf -- "$TEMP_DIR"' EXIT
    run_dependency_analysis "$project_path" "$TEMP_DIR" & local dep_pid=$!
    run_project_analysis "$project_path" "$TEMP_DIR" & local proj_pid=$!
    wait $dep_pid; wait $proj_pid
    local final_exit_code=0; generate_report "$TEMP_DIR" || final_exit_code=$?
    info "Scan complete."; exit $final_exit_code
}

main "$@"