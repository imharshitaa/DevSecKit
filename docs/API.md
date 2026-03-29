# DevSecKit Platform REST API

API server file: [devsec_platform/api.py](/Users/harshitaaa/Projects/DevSecKit/devsec_platform/api.py)

Start API:

```bash
export DEVSEC_API_TOKEN='change-me'
python3 -m devsec_platform.api
```

Default URL: `http://127.0.0.1:8787`

## Endpoints

### `GET /health`

Returns health status.

### `GET /api/v1/plugins`

Lists registered plugins.
Requires auth header:

```bash
curl -sS http://127.0.0.1:8787/api/v1/plugins \
  -H "Authorization: Bearer $DEVSEC_API_TOKEN"
```

### `POST /api/v1/scans`

Runs orchestrated scan flow and returns:

- plugin executions
- unified risks
- ai insights
- remediation plans

Required request fields:

- `actor` (non-empty string)
- `roles` (non-empty list)
- `target.repo_url`

Example request:

```bash
curl -sS -X POST http://127.0.0.1:8787/api/v1/scans \
  -H "Authorization: Bearer $DEVSEC_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "event_type":"deploy",
    "target":{
      "repo_url":"https://github.com/OWASP/NodeGoat",
      "branch":"main",
      "environment":"prod",
      "runtime_url":"http://localhost:3000"
    },
    "context":{
      "business_service":"payments",
      "internet_exposed":true,
      "data_classification":"confidential",
      "known_exploits":true,
      "changed_files":["infra/main.tf","package-lock.json"]
    },
    "roles":["security_engineer"],
    "actor":"demo-user"
  }'
```

### `POST /api/v1/remediations/preview`

Returns GitHub PR preview data for remediation plan.

## OpenAPI-style schema references

- [scan-request.schema.json](/Users/harshitaaa/Projects/DevSecKit/sdk/schemas/scan-request.schema.json)
- [finding.schema.json](/Users/harshitaaa/Projects/DevSecKit/sdk/schemas/finding.schema.json)
- [unified-risk.schema.json](/Users/harshitaaa/Projects/DevSecKit/sdk/schemas/unified-risk.schema.json)
