# Node Plugin Example

Run plugin as stdin/stdout SDK:

```bash
cat <<'JSON' | node examples/node-plugin/trivy-sca-plugin.js
{
  "event_type": "pr",
  "target": {"repo_url": "https://github.com/OWASP/NodeGoat"}
}
JSON
```

Run plugin as REST service:

```bash
node examples/node-plugin/server.js
curl -sS -X POST http://127.0.0.1:9091/run \
  -H 'content-type: application/json' \
  -d '{"event_type":"pr","target":{"repo_url":"https://github.com/OWASP/NodeGoat"}}'
```
