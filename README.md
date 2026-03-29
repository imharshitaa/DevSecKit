# DevSecKit

DevSecKit is a terminal-first DevSecOps toolkit with two layers:

1. Existing scanner CLI (`run devseckit`) for practical repo scanning.
2. New extensible security platform (`devsec_platform`) with plugin SDK, orchestrator, risk engine, AI insights, and remediation workflow.

## Quick Start

- GitHub Pages demo: `https://imharshitaa.github.io/DevSecKit/demo/`

After cloning:

```bash
chmod +x run devseckit
```

For `fish` (current terminal session):

```fish
set -gx PATH (pwd) $PATH
```

For `zsh`/`bash` (current terminal session):

```bash
export PATH="$PWD:$PATH"
```

Run scanner CLI:

```bash
run devseckit
```

Output:

- Terminal report
- One JSON report file: `reports/scan_report.json`

Run platform API:

```bash
python3 -m devsec_platform.api
```

Demo page:

- [https://imharshitaa.github.io/DevSecKit/demo/](https://imharshitaa.github.io/DevSecKit/demo/)

## Platform Capabilities

- Plugin SDK with normalized schemas for `sast`, `sca`, `secrets`, `iac`, `cspm`, `easm`, `dast`, `iast`
- Rule-based + AI-assisted orchestration by events: `pr`, `deploy`, `runtime`
- Real scanner-backed plugin adapters (Semgrep, Trivy, Gitleaks, TruffleHog, Checkov, ZAP, IAST-lite)
- Parallel scan execution with per-plugin hard timeouts and isolated temporary report directories
- Risk correlation engine with unified risk object:
  - exploitability score
  - exposure score
  - business impact score
  - composite score
- AI module for context-aware vulnerability analysis and fix suggestions
- Auto-remediation planner with GitHub PR preview/creation hooks
- Guardrails: RBAC, audit logs, remediation validation

## Folder Structure

```text
DevSecKit/
├── run                                    # preferred scanner launcher command
├── devseckit                              # scanner launcher wrapper
├── devsec                                 # legacy scanner launcher wrapper
├── devseckit.py                           # terminal scanner orchestrator
├── demo/
│   └── index.html                         # terminal demo UI
├── devsec_platform/
│   ├── api.py                             # REST API server
│   ├── orchestrator.py                    # rule + AI plugin routing and execution
│   ├── risk_engine.py                     # finding correlation and scoring
│   ├── ai_module.py                       # risk analysis and plugin suggestion
│   ├── remediation.py                     # remediation plans and GitHub PR hooks
│   ├── guardrails.py                      # RBAC and validation
│   ├── audit.py                           # audit logging
│   ├── schemas.py                         # internal dataclasses and model helpers
│   └── plugins/
│       ├── base.py                        # plugin interface
│       ├── builtin.py                     # built-in plugin implementations
│       └── registry.py                    # plugin registry
├── sdk/
│   └── schemas/
│       ├── scan-request.schema.json
│       ├── finding.schema.json
│       └── unified-risk.schema.json
├── docs/
│   ├── ARCHITECTURE.md
│   └── API.md
├── examples/
│   └── node-plugin/
│       ├── trivy-sca-plugin.js
│       ├── server.js
│       └── README.md
├── scanners/                              # tool wrappers for existing CLI
└── .github/workflows/devsec-platform-ci.yml
```

## REST API Samples

List available plugins:

```bash
curl -sS http://127.0.0.1:8787/api/v1/plugins
```

Run event-aware scan:

```bash
curl -sS -X POST http://127.0.0.1:8787/api/v1/scans \
  -H "Authorization: Bearer $DEVSEC_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "event_type":"deploy",
    "target":{"repo_url":"https://github.com/OWASP/NodeGoat","environment":"prod","runtime_url":"http://localhost:3000"},
    "context":{"business_service":"payments","internet_exposed":true,"data_classification":"confidential","known_exploits":true,"changed_files":["infra/main.tf","pnpm-lock.yaml"]},
    "roles":["security_engineer"],
    "actor":"demo-user"
  }'
```

API security defaults:

- `DEVSEC_API_TOKEN` is required for all `/api/*` endpoints.
- Request must include explicit `actor` and `roles` (no privileged role defaults).

## Existing CLI Flow (`run devseckit`)

Command:

```bash
run devseckit
```

1. Choose scan target:
   - Scan local source directory
   - Scan remote directory (provide git URL)
2. Choose scan categories: `sast`, `sca`, `secrets`, `iac`, `dast`, `iast`, or `all`
3. If dynamic scans selected, provide target URL.
4. Review terminal report and one final JSON file: `reports/scan_report.json`.

Note:
- SCA in platform mode currently uses Trivy only.
- `dependencycheck.sh` is intentionally excluded until the script issue is fixed.

## Platform Terminal Report

Use terminal output directly (no API call needed):

```bash
devseckit platform --event pr --repo https://github.com/WebGoat/WebGoat
```

Options:

- `--event pr|deploy|runtime`
- `--plugins sast,sca,secrets,iac,cspm,easm,dast,iast` (optional override)
- `--internet-exposed`
- `--known-exploits`
- `--business-service <name>`
- `--data-classification internal|confidential|restricted`
- `--json` for full structured output

## Plugin SDK Contract

### Input

- Use [scan-request.schema.json](/Users/harshitaaa/Projects/DevSecKit/sdk/schemas/scan-request.schema.json)

### Output

- Emit findings following [finding.schema.json](/Users/harshitaaa/Projects/DevSecKit/sdk/schemas/finding.schema.json)

### Risk Object

- Unified risk follows [unified-risk.schema.json](/Users/harshitaaa/Projects/DevSecKit/sdk/schemas/unified-risk.schema.json)

## CI/CD Integration

Sample GitHub Actions workflow:

- [.github/workflows/devsec-platform-ci.yml](/Users/harshitaaa/Projects/DevSecKit/.github/workflows/devsec-platform-ci.yml)

It starts the API, executes a sample orchestrated scan, validates response shape, and uploads artifacts.

## Technical Blueprint

1. Event arrives (`pr`, `deploy`, `runtime`)
2. Orchestrator selects plugins with rule-based + AI augmentation
3. Plugins produce normalized findings
4. Risk engine correlates and scores into unified risks
5. AI module generates context-aware remediation guidance
6. Guardrails validate remediation and enforce RBAC
7. Optional GitHub PR creation for auto-remediation
8. Audit trail stored in `reports/audit/devsec_platform_audit_YYYYMMDD.log`

## Demo Notes

- Demo UI remains terminal-style and shows realistic streaming multi-module logs.
- Demo command is `devseckit` (demo-only simulation).
- Sample target git options are included directly in the terminal prompt flow.
