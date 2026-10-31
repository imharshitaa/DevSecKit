/*
 * DevSecKit demo interactivity. Pure client-side simulation — no network
 * requests are ever fired. All data comes from fixtures.js.
 */

(function () {
  "use strict";

  /* ---------------------------------------------------------------- *
   * Terminal
   * ---------------------------------------------------------------- */

  var terminalLog = document.getElementById("terminal-log");
  var terminalForm = document.getElementById("terminal-form");
  var terminalInput = document.getElementById("terminal-input");
  var history = [];
  var historyIndex = -1;

  function appendLine(text, className) {
    var div = document.createElement("div");
    div.className = "line" + (className ? " " + className : "");
    div.textContent = text;
    terminalLog.appendChild(div);
  }

  function appendLines(lines, className) {
    lines.forEach(function (line) {
      appendLine(line, className);
    });
  }

  function renderRiskLine(risk) {
    return (
      "  [" + risk.severity + "] " + risk.title +
      " (score=" + risk.composite_score.toFixed(2) + ", " + risk.primary_location + ")"
    );
  }

  function runCommand(raw) {
    var cmd = raw.trim();
    if (!cmd) return;

    appendLine("$ " + cmd, "line-cmd");

    if (cmd === "clear") {
      terminalLog.innerHTML = "";
      return;
    }

    if (cmd === "help") {
      appendLines([
        "Available commands:",
        "  help                              show this message",
        "  devseckit --version               print version info",
        "  devseckit scan                    run a sample scan (fixture output)",
        "  devseckit platform --event pr     run a sample platform event (fixture output)",
        "  plugins list                      list plugin types and status",
        "  risk summary                      show sample correlated risks",
        "  report show                       print the sample report JSON",
        "  clear                             clear the terminal",
      ]);
      return;
    }

    if (cmd === "devseckit --version") {
      appendLines(DEVSECKIT_VERSION_INFO);
      return;
    }

    if (cmd === "devseckit scan") {
      appendLines(SAMPLE_SCAN_TERMINAL_LINES);
      return;
    }

    if (cmd === "devseckit platform --event pr") {
      var report = SAMPLE_PLATFORM_REPORT;
      appendLine("Target: " + report.target);
      appendLine("Event: " + report.event_type);
      appendLine("Plugins executed: " + report.plugins_executed.join(", "));
      appendLine("");
      appendLine("=== Unified Risks (" + report.total_risks + ") ===");
      report.risks.forEach(function (risk) {
        appendLine(renderRiskLine(risk));
      });
      appendLine("");
      appendLine("(fixture output — not a live scan)");
      return;
    }

    if (cmd === "plugins list") {
      PLUGIN_LIST_FIXTURE.forEach(function (plugin) {
        appendLine("  " + plugin.type.padEnd(8) + plugin.tool.padEnd(28) + plugin.status);
      });
      return;
    }

    if (cmd === "risk summary") {
      SAMPLE_PLATFORM_REPORT.risks.forEach(function (risk) {
        appendLine(renderRiskLine(risk));
      });
      return;
    }

    if (cmd === "report show") {
      appendLine(JSON.stringify(SAMPLE_REPORT_JSON, null, 2));
      return;
    }

    appendLine(cmd + ": command not found. Type \"help\" for a list of commands.", "line-error");
  }

  if (terminalForm) {
    appendLines([
      "DevSecKit simulated terminal — type \"help\" to get started.",
      "",
    ]);

    terminalForm.addEventListener("submit", function (event) {
      event.preventDefault();
      var value = terminalInput.value;
      if (value.trim()) {
        history.push(value);
        historyIndex = history.length;
      }
      runCommand(value);
      terminalInput.value = "";
      terminalLog.scrollTop = terminalLog.scrollHeight;
    });

    terminalInput.addEventListener("keydown", function (event) {
      if (event.key === "ArrowUp") {
        event.preventDefault();
        if (historyIndex > 0) {
          historyIndex -= 1;
          terminalInput.value = history[historyIndex] || "";
        }
      } else if (event.key === "ArrowDown") {
        event.preventDefault();
        if (historyIndex < history.length - 1) {
          historyIndex += 1;
          terminalInput.value = history[historyIndex] || "";
        } else {
          historyIndex = history.length;
          terminalInput.value = "";
        }
      }
    });

    document.querySelectorAll(".chip[data-cmd]").forEach(function (chip) {
      chip.addEventListener("click", function () {
        terminalInput.value = chip.getAttribute("data-cmd");
        terminalInput.focus();
      });
    });
  }

  /* ---------------------------------------------------------------- *
   * Sample findings explorer
   * ---------------------------------------------------------------- */

  var findingsList = document.getElementById("findings-list");
  var filterSeverity = document.getElementById("filter-severity");
  var filterCategory = document.getElementById("filter-category");
  var filterStatus = document.getElementById("filter-status");

  function renderFindings() {
    if (!findingsList) return;
    var sev = filterSeverity.value;
    var cat = filterCategory.value;
    var status = filterStatus.value;

    var filtered = FINDINGS_EXPLORER_FIXTURE.filter(function (f) {
      return (
        (!sev || f.severity === sev) &&
        (!cat || f.category === cat) &&
        (!status || f.status === status)
      );
    });

    findingsList.innerHTML = "";

    if (!filtered.length) {
      var empty = document.createElement("li");
      empty.className = "empty-state";
      empty.textContent = "No sample findings match the selected filters.";
      findingsList.appendChild(empty);
      return;
    }

    filtered.forEach(function (finding) {
      var item = document.createElement("li");
      item.className = "finding-item";

      var head = document.createElement("button");
      head.type = "button";
      head.className = "finding-head";
      head.setAttribute("aria-expanded", "false");

      var badge = document.createElement("span");
      badge.className = "sev-badge " + finding.severity;
      badge.textContent = finding.severity;

      var title = document.createElement("span");
      title.className = "finding-title";
      title.textContent = finding.title;

      var meta = document.createElement("span");
      meta.className = "finding-meta";
      meta.textContent = finding.id + " · " + finding.category + " · " + finding.tool;

      var status = document.createElement("span");
      status.className = "finding-status";
      status.textContent = finding.status;

      head.appendChild(badge);
      head.appendChild(title);
      head.appendChild(meta);
      head.appendChild(status);

      var details = document.createElement("dl");
      details.className = "finding-details";

      var locDt = document.createElement("dt");
      locDt.textContent = "Location";
      var locDd = document.createElement("dd");
      locDd.textContent = finding.file + (finding.line ? ":" + finding.line : "");

      var evDt = document.createElement("dt");
      evDt.textContent = "Evidence";
      var evDd = document.createElement("dd");
      var evCode = document.createElement("code");
      evCode.textContent = finding.evidence;
      evDd.appendChild(evCode);

      var remDt = document.createElement("dt");
      remDt.textContent = "Suggested remediation";
      var remDd = document.createElement("dd");
      remDd.textContent = finding.remediation;

      details.appendChild(locDt);
      details.appendChild(locDd);
      details.appendChild(evDt);
      details.appendChild(evDd);
      details.appendChild(remDt);
      details.appendChild(remDd);

      head.addEventListener("click", function () {
        var isOpen = details.classList.toggle("is-open");
        head.setAttribute("aria-expanded", String(isOpen));
      });

      item.appendChild(head);
      item.appendChild(details);
      findingsList.appendChild(item);
    });
  }

  [filterSeverity, filterCategory, filterStatus].forEach(function (select) {
    if (select) select.addEventListener("change", renderFindings);
  });
  renderFindings();

  /* ---------------------------------------------------------------- *
   * Plugin ecosystem grid
   * ---------------------------------------------------------------- */

  var pluginGrid = document.getElementById("plugin-grid");
  if (pluginGrid) {
    PLUGIN_LIST_FIXTURE.forEach(function (plugin) {
      var card = document.createElement("div");
      card.className = "plugin-card";

      var h4 = document.createElement("h4");
      h4.textContent = plugin.type;

      var p = document.createElement("p");
      p.textContent = plugin.tool;

      var statusSpan = document.createElement("span");
      statusSpan.className = "plugin-status " + plugin.status;
      statusSpan.textContent = plugin.status === "implemented" ? "Implemented" : "Placeholder";

      card.appendChild(h4);
      card.appendChild(p);
      card.appendChild(statusSpan);
      pluginGrid.appendChild(card);
    });
  }

  /* ---------------------------------------------------------------- *
   * Risk engine worked example
   * ---------------------------------------------------------------- */

  var riskExample = document.getElementById("risk-example");
  if (riskExample) {
    var risk = SAMPLE_PLATFORM_REPORT.risks[0];
    var dl = document.createElement("dl");

    var rows = [
      ["Risk", risk.title],
      ["Exploitability", risk.exploitability_score.toFixed(2)],
      ["Exposure", risk.exposure_score.toFixed(2)],
      ["Business impact", risk.business_impact_score.toFixed(2)],
      [
        "Composite",
        risk.exploitability_score.toFixed(2) + " × 0.4 + " +
          risk.exposure_score.toFixed(2) + " × 0.25 + " +
          risk.business_impact_score.toFixed(2) + " × 0.35 = " +
          risk.composite_score.toFixed(2),
      ],
      ["Severity", risk.severity],
    ];

    rows.forEach(function (pair) {
      var dt = document.createElement("dt");
      dt.textContent = pair[0];
      var dd = document.createElement("dd");
      dd.textContent = pair[1];
      dl.appendChild(dt);
      dl.appendChild(dd);
    });

    riskExample.appendChild(dl);
  }

  /* ---------------------------------------------------------------- *
   * API playground
   * ---------------------------------------------------------------- */

  var apiTabs = document.querySelectorAll(".api-tab[data-sample]");
  var apiCurl = document.getElementById("api-curl");
  var apiRequestBody = document.getElementById("api-request-body");
  var apiResponse = document.getElementById("api-response");

  function renderApiSample(key) {
    var sample = API_PLAYGROUND_SAMPLES[key];
    if (!sample) return;
    apiCurl.textContent = sample.curl || (sample.method + " " + sample.path);
    apiRequestBody.value = sample.requestBody ? JSON.stringify(sample.requestBody, null, 2) : "(no request body)";
    apiRequestBody.readOnly = !sample.requestBody;
    apiResponse.textContent = JSON.stringify(sample.responseBody, null, 2);
  }

  apiTabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      apiTabs.forEach(function (t) {
        t.classList.remove("is-active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("is-active");
      tab.setAttribute("aria-selected", "true");
      renderApiSample(tab.getAttribute("data-sample"));
    });
  });

  if (apiCurl) {
    renderApiSample("listPlugins");
  }

  /* ---------------------------------------------------------------- *
   * Copy-to-clipboard for all [data-copy] blocks
   * ---------------------------------------------------------------- */

  document.querySelectorAll("[data-copy]").forEach(function (block) {
    var button = block.querySelector(".copy-btn");
    if (!button) return;
    button.addEventListener("click", function () {
      var source = block.querySelector("pre") || block.querySelector("textarea");
      if (!source) return;
      var text = source.tagName === "TEXTAREA" ? source.value : source.textContent;

      var done = function () {
        var original = button.textContent;
        button.textContent = "Copied";
        button.classList.add("copied");
        setTimeout(function () {
          button.textContent = original;
          button.classList.remove("copied");
        }, 1500);
      };

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        var textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        try {
          document.execCommand("copy");
        } catch (err) {
          /* clipboard unavailable — silently ignore, button still provides visual feedback */
        }
        document.body.removeChild(textarea);
        done();
      }
    });
  });
})();
