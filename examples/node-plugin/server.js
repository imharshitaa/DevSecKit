#!/usr/bin/env node

const http = require("http");
const { run } = require("./trivy-sca-plugin");

const server = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/run") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        const payload = body ? JSON.parse(body) : {};
        const findings = run(payload);
        const response = JSON.stringify({ findings }, null, 2);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(response);
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: String(err) }));
      }
    });
    return;
  }

  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(9091, "127.0.0.1", () => {
  console.log("Node plugin example listening on http://127.0.0.1:9091");
});
