#!/usr/bin/env node

/**
 * Minimal Node plugin example for DevSecKit plugin SDK.
 * Input schema matches sdk/schemas/scan-request.schema.json.
 * Output findings match sdk/schemas/finding.schema.json.
 */

function run(input) {
  const repo = input?.target?.repo_url || "local://repo";
  return [
    {
      plugin_type: "sca",
      tool: "trivy",
      rule_id: "CVE-2024-24786",
      title: "golang.org/x/net vulnerable package",
      severity: "HIGH",
      confidence: "HIGH",
      file_path: "go.sum",
      line: 210,
      evidence: "golang.org/x/net v0.23.0",
      remediation: "Upgrade golang.org/x/net to a patched version and rerun SCA scan.",
      references: ["CVE-2024-24786"],
      tags: {
        source_repo: repo,
        package: "golang.org/x/net"
      }
    }
  ];
}

function main() {
  let raw = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => (raw += chunk));
  process.stdin.on("end", () => {
    const input = raw.trim() ? JSON.parse(raw) : {};
    const findings = run(input);
    process.stdout.write(JSON.stringify({ findings }, null, 2));
  });
}

if (require.main === module) {
  main();
}

module.exports = { run };
