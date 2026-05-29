"use strict";
// Zero-dependency tests for the SARIF Explorer's pure helpers.
// Run with: node --test "web/**/*.test.js"   (Node 21+; no package.json / node_modules)

const test = require("node:test");
const assert = require("node:assert/strict");

const { numOrNull, parseSarif, severityLabel, severityRank, matchesFilter } = require("./viewer.js");

test("numOrNull coerces finite numbers + numeric strings, rejects the rest", () => {
  assert.equal(numOrNull(0.42), 0.42);
  assert.equal(numOrNull(0), 0);
  assert.equal(numOrNull("0.42"), 0.42); // numeric string coerced
  assert.equal(numOrNull("high"), null);
  assert.equal(numOrNull(""), null);
  assert.equal(numOrNull(NaN), null);
  assert.equal(numOrNull(Infinity), null);
  assert.equal(numOrNull(null), null);
  assert.equal(numOrNull(undefined), null);
});

test("severityLabel title-cases known buckets, falls back to Info", () => {
  assert.equal(severityLabel("critical"), "Critical");
  assert.equal(severityLabel("HIGH"), "High");
  assert.equal(severityLabel("medium"), "Medium");
  assert.equal(severityLabel("low"), "Low");
  assert.equal(severityLabel("bogus"), "Info");
  assert.equal(severityLabel(null), "Info");
});

test("severityRank orders the buckets; unknown => 0", () => {
  assert.ok(severityRank("critical") > severityRank("high"));
  assert.ok(severityRank("high") > severityRank("medium"));
  assert.ok(severityRank("medium") > severityRank("low"));
  assert.ok(severityRank("low") > severityRank("info"));
  assert.equal(severityRank("info"), 0);
  assert.equal(severityRank("bogus"), 0);
});

test("parseSarif returns [] (never throws) on non-SARIF / hostile input", () => {
  assert.deepEqual(parseSarif(null), []);
  assert.deepEqual(parseSarif({}), []);
  assert.deepEqual(parseSarif({ runs: [null] }), []);
  assert.deepEqual(parseSarif(42), []);
});

test("parseSarif reads Cepheus canonical keys (result props + rule props)", () => {
  const blob = {
    runs: [
      {
        tool: {
          driver: {
            rules: [
              {
                id: "cap_sys_admin_mount",
                name: "Mount host filesystem via CAP_SYS_ADMIN",
                helpUri: "https://example.com/x",
                properties: {
                  remediation: "Drop CAP_SYS_ADMIN (runtime flag: --cap-drop=SYS_ADMIN)",
                  "cis-kubernetes-benchmark": ["5.2.1", "5.2.6"],
                  "nist-800-190": ["4.2.4"],
                  "pci-dss": ["2.2.5"],
                },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "cap_sys_admin_mount",
            level: "error",
            message: { text: "chain detected" },
            properties: {
              severity: "critical",
              "composite-score": 0.92,
              "reliability-score": 0.8,
              "stealth-score": 0.3,
              "confidence-score": 0.95,
              "chain-id": "c1",
              "chain-length": 2,
              impact: "Read/write access to the entire host filesystem.",
              "affected-components": ["Container: web-7f9", "Linux capabilities"],
              techniques: ["cap_sys_admin_mount", "cap_dac_override"],
            },
          },
        ],
      },
    ],
  };
  const f = parseSarif(blob);
  assert.equal(f.length, 1);
  const x = f[0];
  assert.equal(x.severity, "critical");
  assert.equal(x.score, 0.92);
  assert.equal(x.reliability, 0.8);
  assert.equal(x.stealth, 0.3);
  assert.equal(x.confidence, 0.95);
  assert.equal(x.chainId, "c1");
  assert.equal(x.chainLength, 2);
  assert.equal(x.impact, "Read/write access to the entire host filesystem.");
  assert.deepEqual(x.affectedComponents, ["Container: web-7f9", "Linux capabilities"]);
  assert.equal(x.recommendation, "Drop CAP_SYS_ADMIN (runtime flag: --cap-drop=SYS_ADMIN)");
  assert.equal(x.title, "Mount host filesystem via CAP_SYS_ADMIN");
  assert.equal(x.reference, "https://example.com/x");
  assert.deepEqual(
    x.techniques.map((t) => t.id),
    ["cap_sys_admin_mount", "cap_dac_override"]
  );
  // compliance comes from the rule, in framework display order
  assert.deepEqual(
    x.compliance.map((c) => c.framework),
    ["CIS Kubernetes Benchmark", "NIST SP 800-190", "PCI DSS"]
  );
  assert.deepEqual(x.compliance[0].ids, ["5.2.1", "5.2.6"]);
});

test("parseSarif falls back to camelCase/short keys + SARIF level", () => {
  const blob = {
    runs: [
      {
        tool: { driver: { rules: [] } },
        results: [
          {
            ruleId: "x",
            level: "warning",
            properties: { score: 0.5, chainId: "z", affectedComponents: ["C"], recommendation: "do x", reliability: 0.6 },
          },
        ],
      },
    ],
  };
  const x = parseSarif(blob)[0];
  assert.equal(x.severity, "medium"); // derived from level=warning (no props.severity)
  assert.equal(x.score, 0.5);
  assert.equal(x.chainId, "z");
  assert.deepEqual(x.affectedComponents, ["C"]);
  assert.equal(x.recommendation, "do x");
  assert.equal(x.reliability, 0.6);
});

test("parseSarif coerces wrong-typed numeric props to null (no toFixed crash)", () => {
  const blob = {
    runs: [
      {
        tool: { driver: { rules: [] } },
        results: [{ ruleId: "x", level: "note", properties: { "composite-score": "high", "reliability-score": {} } }],
      },
    ],
  };
  const x = parseSarif(blob)[0];
  assert.equal(x.score, null);
  assert.equal(x.reliability, null);
  assert.equal(x.severity, "low"); // level=note
});

test("matchesFilter: severity buckets ('all' / '' = all)", () => {
  const base = {
    severity: "critical", ruleId: "a", title: "", impact: "", message: "", chainId: "",
    recommendation: "", techniques: [], affectedComponents: [], compliance: [],
  };
  const crit = base;
  const med = Object.assign({}, base, { severity: "medium", ruleId: "b" });
  assert.equal(matchesFilter(crit, "", "critical"), true);
  assert.equal(matchesFilter(med, "", "critical"), false);
  assert.equal(matchesFilter(med, "", "medium"), true);
  assert.equal(matchesFilter(crit, "", ""), true); // empty = all
  assert.equal(matchesFilter(crit, "", "all"), true); // 'all' = all
});

test("matchesFilter: multi-token AND search across all fields", () => {
  const f = {
    severity: "high", ruleId: "docker_socket_mount", title: "Docker socket",
    impact: "Full daemon control", message: "escape chain", chainId: "chain-7",
    recommendation: "remove the socket mount",
    techniques: [{ id: "docker_socket_mount", label: "Docker socket mount" }],
    affectedComponents: ["Container: api", "Host mounts / filesystem"],
    compliance: [{ framework: "CIS Kubernetes Benchmark", ids: ["5.1.5"] }],
  };
  assert.equal(matchesFilter(f, "socket", ""), true);
  assert.equal(matchesFilter(f, "daemon control", ""), true); // AND across tokens
  assert.equal(matchesFilter(f, "host mounts", ""), true); // affected component
  assert.equal(matchesFilter(f, "5.1.5", ""), true); // compliance id
  assert.equal(matchesFilter(f, "socket nonexistent", ""), false);
  assert.equal(matchesFilter(null, "x", ""), false);
});
