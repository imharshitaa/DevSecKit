# DevSecKit

DevSecKit is a modular DevSecOps security scanning toolkit that integrates multiple security analysis techniques—SAST, SCA, Secrets Scanning, and DAST—into a single, CLI-driven framework with GitHub Actions CI/CD integration.

---

## Objectives

Security analysis categories:
- SAST (Static Application Security Testing)
- SCA (Software Composition Analysis)
- Secrets Scanning
- DAST (Dynamic Application Security Testing)

---

## Tools

| Security Category | Tool                   | Target          | Scanner Script                      |
| ----------------- | ---------------------- | --------------- | ----------------------------------- |
| **SAST**          | Semgrep                | Source code     | `scanners/sast/semgrep_scan.sh`     |
| **SCA**           | OWASP Dependency-Check | Dependencies    | `scanners/sca/dependency_check.sh`  |
| **Secrets**       | Gitleaks               | Repo files      | `scanners/secrets/gitleaks_scan.sh` |
| **DAST**          | OWASP ZAP              | Running web app | `scanners/dast/zap_scan.sh`         |


---
```
DevSecKit/
│
├── scanners/                       # Security scan logic (CI-executed)
│   ├── sast/
│   │   └── semgrep_scan.sh
│   │
│   ├── sca/
│   │   └── dependency_check.sh
│   │
│   ├── secrets/
│   │   └── gitleaks_scan.sh
│   │
│   ├── dast/
│   │   └── zap_scan.sh
│
├── reports/                        # Scan results (CI artifacts)
│   └── .gitkeep
│
├── configs/                        # Tool configs (optional)
│
├── .github/
│   └── workflows/
│       └── devseckit.yml           # MAIN workflow (single entry)
│
└── README.md

```

---

Installation (Local):












