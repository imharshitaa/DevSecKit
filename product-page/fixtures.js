/*
 * Static sample data for the DevSecKit GitHub Pages demo.
 * Everything here is a fixed fixture, not a live scan result. Severity scores
 * and formulas mirror the real implementation in devsec_platform/risk_engine.py
 * so the numbers shown are representative, not invented.
 */

const DEVSECKIT_VERSION_INFO = [
  "DevSecKit CLI v1.0.0 (scanner layer)",
  "DevSecKit Platform v1.0.0 (devsec_platform)",
  "Python: stdlib-only, no third-party runtime dependencies",
  "Scanner adapters: semgrep, trivy, gitleaks, trufflehog, checkov, zap, iast-lite",
];

const PLUGIN_LIST_FIXTURE = [
  { type: "sast", tool: "semgrep", status: "implemented" },
  { type: "sca", tool: "trivy", status: "implemented" },
  { type: "secrets", tool: "gitleaks + trufflehog", status: "implemented" },
  { type: "iac", tool: "checkov", status: "implemented" },
  { type: "dast", tool: "owasp-zap", status: "implemented" },
  { type: "iast", tool: "iast-lite", status: "implemented" },
  { type: "cspm", tool: "cloud-cspm", status: "placeholder" },
  { type: "easm", tool: "attack-surface-monitor", status: "placeholder" },
];

// Illustrative sample scan output for the `devseckit scan` terminal command.
// Labeled as a fixture — this text is not produced by executing a real scan.
const SAMPLE_SCAN_TERMINAL_LINES = [
  "Target: sample-target (illustrative fixture, not a live scan)",
  "Selected scans: sast, sca, secrets, iac",
  "",
  "[sast]    semgrep       3 findings   (1 HIGH, 2 MEDIUM)",
  "[sca]     trivy         2 findings   (1 CRITICAL, 1 HIGH)",
  "[secrets] gitleaks      1 finding    (1 CRITICAL)",
  "[secrets] trufflehog    0 findings",
  "[iac]     checkov       2 findings   (2 MEDIUM)",
  "",
  "=== Findings Summary ===",
  "CRITICAL: 2",
  "HIGH: 2",
  "MEDIUM: 4",
  "",
  "Report written: reports/scan_report.json",
];

// Mirrors print_final_report() output shape from devsec_platform/cli.py for
// `devseckit platform --event pr`.
const SAMPLE_PLATFORM_REPORT = {
  target: "https://github.com/OWASP/NodeGoat (sample fixture)",
  event_type: "pr",
  plugins_executed: ["sast", "sca", "secrets", "iac"],
  total_findings: 6,
  total_risks: 3,
  risks: [
    {
      risk_id: "RISK-7F3A91C2D4",
      severity: "CRITICAL",
      title: "Hardcoded database credentials",
      composite_score: 8.73,
      exploitability_score: 9.0,
      exposure_score: 8.0,
      business_impact_score: 8.9,
      business_service: "payments",
      internet_exposed: true,
      primary_location: "config/database.js:14 (secrets via gitleaks)",
      why_risky: "Hardcoded database credentials is prioritized as CRITICAL (score=8.73).",
      root_cause: "Credential handling violation in repository or configuration",
      remediation_guidance: "Apply fix in the next release window and rotate affected credentials/tokens if applicable.",
      auto_remediation: { action_type: "github_pr", safe_to_auto_apply: false, files: ["config/database.js"] },
    },
    {
      risk_id: "RISK-2B88E015AA",
      severity: "HIGH",
      title: "SQL injection via unsanitized query parameter",
      composite_score: 7.41,
      exploitability_score: 8.2,
      exposure_score: 7.0,
      business_impact_score: 6.9,
      business_service: "payments",
      internet_exposed: true,
      primary_location: "routes/users.js:52 (sast via semgrep)",
      why_risky: "SQL injection via unsanitized query parameter is prioritized as HIGH (score=7.41).",
      root_cause: "Untrusted input reaches execution/data layer without proper validation",
      remediation_guidance: "Apply fix in the next release window and rotate affected credentials/tokens if applicable.",
      auto_remediation: { action_type: "github_pr", safe_to_auto_apply: false, files: ["routes/users.js"] },
    },
    {
      risk_id: "RISK-9C01F4E73B",
      severity: "MEDIUM",
      title: "Outdated dependency with known CVE",
      composite_score: 5.62,
      exploitability_score: 6.3,
      exposure_score: 6.0,
      business_impact_score: 4.8,
      business_service: "payments",
      internet_exposed: true,
      primary_location: "package-lock.json (sca via trivy)",
      why_risky: "Outdated dependency with known CVE is prioritized as MEDIUM (score=5.62).",
      root_cause: "Insecure configuration",
      remediation_guidance: "Patch the vulnerable code/config and add regression tests.",
      auto_remediation: { action_type: "github_pr", safe_to_auto_apply: true, files: ["package-lock.json"] },
    },
  ],
};

const SAMPLE_REPORT_JSON = {
  generated_at: "2026-01-14T09:32:07.000000Z",
  target: "sample-target (illustrative fixture)",
  selected_scans: ["sast", "sca", "secrets", "iac"],
  summary: {
    total_findings: 6,
    severity: { CRITICAL: 2, HIGH: 2, MEDIUM: 2 },
    scan_type: { sast: 2, sca: 1, secrets: 1, iac: 2 },
  },
  execution: [
    { scan: "sast", tool: "semgrep", status: "ok" },
    { scan: "sca", tool: "trivy", status: "ok" },
    { scan: "secrets", tool: "gitleaks", status: "ok" },
    { scan: "iac", tool: "checkov", status: "ok" },
  ],
};

// Fixture for the sample scan results explorer (section 4). Explicitly
// illustrative — not the output of a real scan against a real repository.
const FINDINGS_EXPLORER_FIXTURE = [
  {
    id: "F-001",
    severity: "CRITICAL",
    category: "secrets",
    tool: "gitleaks",
    status: "open",
    title: "Hardcoded database credentials",
    file: "config/database.js",
    line: 14,
    evidence: "const DB_PASSWORD = \"sup3rSecret!\"",
    remediation: "Move credentials to a secret manager or environment variables; rotate the exposed value.",
  },
  {
    id: "F-002",
    severity: "CRITICAL",
    category: "sca",
    tool: "trivy",
    status: "open",
    title: "Known-vulnerable version of lodash (CVE-2021-23337)",
    file: "package-lock.json",
    line: null,
    evidence: "lodash 4.17.15 (fixed: 4.17.21)",
    remediation: "Upgrade to fixed version and verify transitive dependency path.",
  },
  {
    id: "F-003",
    severity: "HIGH",
    category: "sast",
    tool: "semgrep",
    status: "open",
    title: "SQL injection via unsanitized query parameter",
    file: "routes/users.js",
    line: 52,
    evidence: "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
    remediation: "Use parameterized queries and validate untrusted input.",
  },
  {
    id: "F-004",
    severity: "HIGH",
    category: "sca",
    tool: "trivy",
    status: "acknowledged",
    title: "Known-vulnerable version of express (CVE-2022-24999)",
    file: "package-lock.json",
    line: null,
    evidence: "express 4.17.1 (fixed: 4.17.3)",
    remediation: "Upgrade to fixed version and verify transitive dependency path.",
  },
  {
    id: "F-005",
    severity: "MEDIUM",
    category: "iac",
    tool: "checkov",
    status: "open",
    title: "Dockerfile runs as root user",
    file: "Dockerfile",
    line: 3,
    evidence: "CKV_DOCKER_3: ensure a USER instruction is set",
    remediation: "Add a non-root USER instruction before the container entrypoint.",
  },
  {
    id: "F-006",
    severity: "MEDIUM",
    category: "iac",
    tool: "checkov",
    status: "resolved",
    title: "S3 bucket does not enforce encryption at rest",
    file: "infra/main.tf",
    line: 21,
    evidence: "CKV_AWS_19: ensure bucket has encryption enabled",
    remediation: "Set server_side_encryption_configuration on the bucket resource.",
  },
];

// API playground samples (section 10). These are static examples — the
// playground never auto-fires requests against a live server.
const API_PLAYGROUND_SAMPLES = {
  listPlugins: {
    method: "GET",
    path: "/api/v1/plugins",
    curl:
      'curl -sS http://127.0.0.1:8787/api/v1/plugins \\\n  -H "Authorization: Bearer $DEVSEC_API_TOKEN"',
    responseBody: {
      plugins: ["cspm", "dast", "easm", "iac", "iast", "sast", "sca", "secrets"],
    },
  },
  createScan: {
    method: "POST",
    path: "/api/v1/scans",
    requestBody: {
      event_type: "deploy",
      target: {
        repo_url: "https://github.com/OWASP/NodeGoat",
        branch: "main",
        environment: "prod",
        runtime_url: "http://localhost:3000",
      },
      context: {
        business_service: "payments",
        internet_exposed: true,
        data_classification: "confidential",
        known_exploits: true,
        changed_files: ["infra/main.tf", "package-lock.json"],
      },
      roles: ["security_engineer"],
      actor: "demo-user",
    },
    responseBody: {
      request_id: "b6f3a2d1-9e4c-4a7b-8f21-3c9d8e2a1f00",
      event_type: "deploy",
      executed_plugins: [
        { plugin: "sast", tool: "semgrep", status: "success" },
        { plugin: "sca", tool: "trivy", status: "success" },
      ],
      unified_risks: "[ ...see risk engine section... ]",
      ai_insights: "[ ...see AI module summary... ]",
      remediation_plans: "[ ...see remediation workflow section... ]",
    },
  },
  remediationPreview: {
    method: "POST",
    path: "/api/v1/remediations/preview",
    requestBody: {
      repo: "owner/repo",
      plan: { risk_id: "RISK-9C01F4E73B" },
      roles: ["security_engineer"],
    },
    responseBody: {
      created: false,
      branch: "codex/remediate-risk-9c01f4e73b",
      pr_url: "https://github.com/owner/repo/pull/new/codex/remediate-risk-9c01f4e73b",
      title: "fix(security): remediate RISK-9C01F4E73B",
    },
  },
};
