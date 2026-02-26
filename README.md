# DevSecKit

DevSecKit is a terminal-based DevSecOps scanner orchestrator.

It can:
- ask whether you want to scan a local source folder or a remote repository
- clone repository code automatically (when repo mode is selected)
- run security scan workflows individually or all at once
- print readable, colorized findings with severity and location
- generate a combined machine-readable report at `reports/combined_report.json`

## Supported scan workflows

- `sast`: Semgrep (static code analysis)
- `sca`: OWASP Dependency-Check (dependency vulnerabilities)
- `sca_trivy`: Trivy FS vuln scan (dependency vulnerabilities)
- `secrets`: Gitleaks (secret detection)
- `secrets_trufflehog`: TruffleHog (secret detection)
- `iac`: Checkov (IaC misconfiguration)
- `dast`: OWASP ZAP Baseline (web runtime scan)
- `iast`: IAST-lite runtime checks (security headers)

## Project structure

```text
DevSecKit/
├── devseckit.py
├── scanners/
│   ├── sast/semgrep.sh
│   ├── sca/dependencycheck.sh
│   ├── sca/trivy.sh
│   ├── secrets/gitleaks.sh
│   ├── secrets/trufflehog.sh
│   ├── iac/checkov.sh
│   ├── dast/zap.sh
│   └── iast/iast.sh
├── reports/
└── targets/
```

## Usage

Run the terminal tool:

```bash
./devseckit.py
```

Interactive flow:
1. Choose target mode: local source or repository clone.
2. Provide path or git URL.
3. Choose scan types (`all` or selected types).
4. Provide URL if DAST/IAST is selected.
5. View formatted results and open combined report JSON.

## Tool prerequisites

Install only the tools you plan to run:

- Semgrep: `pipx install semgrep`
- Dependency-Check: [OWASP Dependency-Check](https://jeremylong.github.io/DependencyCheck/)
- Trivy: `brew install trivy`
- Gitleaks: [gitleaks releases](https://github.com/gitleaks/gitleaks)
- TruffleHog: `brew install trufflehog`
- Checkov: `pipx install checkov`
- DAST: Docker (for OWASP ZAP container)
- IAST-lite: Python 3 + curl

## Notes

- If one scan fails (missing tool, runtime issue), DevSecKit continues with other scans.
- Scan outputs are written to `reports/`.
- Repositories scanned in clone mode are stored in `targets/`.
