# DevSecKit

**DevSecKit** is a lightweight toolkit that helps developers and security researchers integrate **SAST (Static Application Security Testing)** and **SCA (Software Composition Analysis)** directly into their workflow.

It automates code and dependency scanning to detect vulnerabilities early in the development process — both manually and through CI/CD pipelines.

---

## Objective

Make security testing simple and developer-friendly by enabling:
-  Code scanning for insecure coding patterns (SAST)
-  Dependency vulnerability checks (SCA)
-  Quick setup and easy automation

---

## Tools Used

| Tool | Type | Purpose |
|------|------|----------|
| **Semgrep** | SAST | Scans source code for security flaws across multiple languages |
| **Bandit** | SAST | Finds common security issues in Python code |
| **Safety** | SCA | Checks dependencies from `requirements.txt` for known CVEs |
| **pip-audit** | SCA | Audits installed Python packages for vulnerabilities |

---

## Features

- Supports both **manual** and **automated** scanning  
- Generates clear and readable vulnerability reports  
- Works on any Python or multi-language project  
- Easy integration with **GitHub Actions** or **GitLab CI**

---

SAST Scan: Finds insecure functions, secrets, and unsafe logic.

SCA Scan: Lists outdated or vulnerable dependencies (CVEs).

