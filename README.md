# DevSecKit

DevSecKit is a terminal-first DevSecOps scanner orchestrator for running SAST, SCA, Secrets, IaC, DAST, and IAST workflows from one CLI command.

## Demo

- GitHub Pages demo: `https://imharshitaa.github.io/DevSecKit/demo/`
- Demo source: https://imharshitaa.github.io/DevSecKit/demo/

## Command

Use `devsec` (wrapper for `devseckit.py`):

```bash
./devsec
```

You can still run directly:

```bash
./devseckit.py
```

## Scan Categories

- `sast`: Semgrep
- `sca`: Dependency-Check + Trivy
- `secrets`: Gitleaks + TruffleHog
- `iac`: Checkov
- `dast`: OWASP ZAP baseline
- `iast`: Runtime header/cookie checks

## Input Flow (After Cloning)

1. Choose target mode:
   - `Scan local source directory`
   - `Scan remote directory (provide the git URL)`
2. Choose scan type(s): `sast`, `sca`, `secrets`, `iac`, `dast`, `iast`, or `all`
3. If `dast`/`iast` selected, provide running target URL.
4. Review terminal report + JSON report in `reports/combined_report.json`.

## Setup

### 1) Clone and enter project

```bash
git clone https://github.com/imharshitaa/DevSecKit.git
cd DevSecKit
chmod +x devsec devseckit.py scanners/**/**/*.sh
```

### 2) Install tools (only what you need)

- Semgrep: `pipx install semgrep`
- Trivy: `brew install trivy`
- Dependency-Check: install from [OWASP Dependency-Check](https://jeremylong.github.io/DependencyCheck/)
- Gitleaks: install from [gitleaks releases](https://github.com/gitleaks/gitleaks)
- TruffleHog: `brew install trufflehog`
- Checkov: `pipx install checkov`
- DAST: Docker Desktop
- IAST-lite: Python 3

### 3) Run

```bash
./devsec
```

## Sample Git Targets

- `https://github.com/juice-shop/juice-shop`
- `https://github.com/WebGoat/WebGoat`
- `https://github.com/digininja/DVWA`
- `https://github.com/OWASP/NodeGoat`

## Technical Working Structure

```text
DevSecKit/
├── devsec                        # primary launcher command
├── devseckit.py                  # orchestrator + parser + report formatter
├── demo/
│   └── index.html                # terminal-style GitHub Pages demo
├── scanners/
│   ├── sast/semgrep.sh
│   ├── sca/dependencycheck.sh
│   ├── sca/trivy.sh
│   ├── secrets/gitleaks.sh
│   ├── secrets/trufflehog.sh
│   ├── iac/checkov.sh
│   ├── dast/zap.sh
│   └── iast/iast.sh
├── reports/                      # generated scanner outputs + combined report
└── targets/                      # cloned remote repositories for scanning
```

## Blueprint

1. Target acquisition layer
   - local path scan or remote git clone into `targets/`
2. Category orchestration layer
   - grouped categories run one or more tool scripts (e.g., `sca` runs both DC + Trivy)
3. Execution & resilience layer
   - preflight checks, per-tool execution, continue-on-failure behavior
4. Parsing & normalization layer
   - converts tool-native JSON output into unified security findings format
5. Reporting layer
   - terminal report with severity + location + remediation
   - machine-readable `reports/combined_report.json`

## Notes

- If one scanner fails, others continue.
- Reports are generated under `reports/`.
- For DAST/IAST, target app must be running and reachable.
- If Docker socket permissions fail, run scanners with local binaries or fix Docker access.
