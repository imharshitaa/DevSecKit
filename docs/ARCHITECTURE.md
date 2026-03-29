# DevSecKit Platform Architecture

## 1) Plugin SDK

DevSecKit uses a standard plugin contract for SAST, SCA, Secrets, IaC, CSPM, EASM, DAST, IAST.

- Input schema: `sdk/schemas/scan-request.schema.json`
- Output schema: `sdk/schemas/finding.schema.json`
- Unified risk schema: `sdk/schemas/unified-risk.schema.json`

Plugin contract (Python):

- Implement `SecurityPlugin` in [devsec_platform/plugins/base.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/plugins/base.py).
- Register plugin in [devsec_platform/plugins/registry.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/plugins/registry.py).

Node plugin examples:

- [examples/node-plugin/trivy-sca-plugin.js](/Users/harshitaaa/Projects/DevSecKit/examples/node-plugin/trivy-sca-plugin.js)
- [examples/node-plugin/server.js](/Users/harshitaaa/Projects/DevSecKit/examples/node-plugin/server.js)

## 2) Orchestrator (Rule-based + AI-assisted)

Main orchestrator: [devsec_platform/orchestrator.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/orchestrator.py)

Execution logic:

1. Rule-based defaults by event:
   - `pr`: `sast, sca, secrets, iac`
   - `deploy`: adds `cspm, easm`
   - `runtime`: `iast, dast, cspm, easm, secrets`
2. AI-assisted plugin suggestion from context (`changed_files`, `internet_exposed`, etc).
3. Resolve target path (local directory or shallow git clone).
4. Execute plugins in parallel with hard subprocess timeouts and isolated temporary output directories.
5. Parse tool-native reports and validate findings against SDK schema rules.

## 3) Risk Engine

Risk correlation: [devsec_platform/risk_engine.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/risk_engine.py)

Unified risk object scoring:

- Exploitability score (0-10)
- Exposure score (0-10)
- Business impact score (0-10)
- Composite score (weighted)

Context-aware modifiers include:

- `internet_exposed`
- `data_classification`
- `known_exploits`
- `business_service`

## 4) AI Module

AI insights module: [devsec_platform/ai_module.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/ai_module.py)

Produces structured JSON:

- Summary
- Probable root cause
- Fix suggestions
- Confidence

## 5) Auto-remediation

Remediation planning: [devsec_platform/remediation.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/remediation.py)

Capabilities:

- Generate remediation plans for high/critical/medium risks.
- Build GitHub PR intent and optional `gh pr create` execution.
- Support dry-run preview for safe integration.

## 6) Guardrails

Guardrail modules:

- RBAC: [devsec_platform/guardrails.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/guardrails.py)
- Audit logging: [devsec_platform/audit.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/audit.py)
- Plan validation before remediation apply.
- API token authentication is required for `/api/*` endpoints.
- Auto-remediation apply is blocked unless plan is explicitly marked safe and passes strict path/type checks.

RBAC permissions:

- `scan:run`
- `risk:read`
- `remediate:propose`
- `remediate:apply`

Audit log file:

- `reports/audit/devsec_platform_audit_YYYYMMDD.log`

## 7) Blueprint

```text
Event (PR/Deploy/Runtime)
  -> Orchestrator (rule + AI selection)
  -> Plugin execution (SAST/SCA/Secrets/IaC/CSPM/EASM/DAST/IAST)
  -> Normalized Findings
  -> Risk Correlation Engine
  -> AI Insight Engine
  -> Remediation Planner
  -> Guardrail Validation + RBAC
  -> Optional GitHub PR flow
  -> REST response + audit trail
```
