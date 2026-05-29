/* ============================================================================
   CEPHEUS · SARIF Explorer — viewer.js
   Vanilla JS. No framework, no bundler, no network.

   SECURITY MODEL
   --------------
   The report is untrusted third-party input. Every value that originates from
   the report is inserted into the DOM via textContent / createTextNode /
   createElement — never innerHTML. The SVG chain graph is built with
   createElementNS. The reference link is the only attribute sink: it is only
   rendered as a clickable <a> when its URL scheme is http(s); otherwise it is
   shown as inert text.

   The pure helpers (numOrNull, parseSarif, severityLabel, severityRank,
   matchesFilter) are side-effect free and unit-tested separately.
   ============================================================================ */

/* ----------------------------------------------------------------------------
   PURE HELPERS  (no DOM, stable signatures)
   ---------------------------------------------------------------------------- */

/** Coerce a value to a finite number, or null. */
function numOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  var n = Number(v);
  return Number.isFinite(n) ? n : null;
}

var SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/** Map a SARIF `level` to a Cepheus severity bucket. */
function levelToSeverity(level) {
  switch (String(level || '').toLowerCase()) {
    case 'error': return 'high';
    case 'warning': return 'medium';
    case 'note': return 'low';
    case 'none': return 'info';
    default: return 'info';
  }
}

/** Normalise an arbitrary severity string to a known bucket. */
function normSeverity(sev) {
  var s = String(sev || '').toLowerCase().trim();
  return SEVERITY_ORDER.indexOf(s) >= 0 ? s : 'info';
}

/** Display label for a severity key. */
function severityLabel(sev) {
  var s = normSeverity(sev);
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Sort rank for a severity — higher is more severe. */
function severityRank(sev) {
  var i = SEVERITY_ORDER.indexOf(normSeverity(sev));
  // critical(0) -> 4 ... info(4) -> 0
  return i < 0 ? 0 : (SEVERITY_ORDER.length - 1 - i);
}

// First non-null of two property reads — lets parseSarif accept Cepheus's
// canonical SARIF keys (kebab-case, `-score` suffixed sub-scores) while still
// tolerating the short/camelCase forms a hand-written or third-party SARIF
// might use.
function _firstDefined(a, b) {
  return a !== undefined && a !== null ? a : b;
}

// Cepheus emits the compliance crosswalk on the SARIF *rule* as separate
// arrays. Map each known key to its human framework name, in display order.
var _COMPLIANCE_KEYS = [
  ['cis-kubernetes-benchmark', 'CIS Kubernetes Benchmark'],
  ['nist-800-190', 'NIST SP 800-190'],
  ['pci-dss', 'PCI DSS']
];

/**
 * Parse a SARIF 2.1.0 document (object OR JSON string) into a flat array of
 * normalised finding objects. Defensive against malformed / hostile input:
 * never throws on shape problems, just skips what it can't read.
 *
 * Reads Cepheus's canonical result/rule property keys:
 *   result.properties: severity, composite-score, chain-id, chain-length,
 *     reliability-score, stealth-score, confidence-score, impact,
 *     affected-components, techniques
 *   rule.properties:   remediation, impact, cis-kubernetes-benchmark,
 *     nist-800-190, pci-dss   (+ rule.helpUri)
 * Falls back to short/camelCase forms (score, chainId, recommendation,
 * compliance, …) for generic third-party SARIF and the embedded demo sample.
 */
function parseSarif(input) {
  var doc = input;
  if (typeof input === 'string') {
    doc = JSON.parse(input); // may throw on invalid JSON — caller handles
  }
  if (!doc || typeof doc !== 'object') return [];

  var runs = Array.isArray(doc.runs) ? doc.runs : [];
  var findings = [];
  var seq = 0;

  for (var r = 0; r < runs.length; r++) {
    var run = runs[r] || {};
    var driver = (run.tool && run.tool.driver) || {};
    var rules = Array.isArray(driver.rules) ? driver.rules : [];

    // rule lookup by id -> rule descriptor
    var ruleMap = {};
    for (var k = 0; k < rules.length; k++) {
      var rdef = rules[k] || {};
      if (rdef.id != null) ruleMap[String(rdef.id)] = rdef;
    }

    var results = Array.isArray(run.results) ? run.results : [];
    for (var j = 0; j < results.length; j++) {
      var res = results[j] || {};
      var props = (res.properties && typeof res.properties === 'object') ? res.properties : {};
      var ruleId = res.ruleId != null ? String(res.ruleId) : '';
      var rule = ruleMap[ruleId] || {};
      var rprops = (rule.properties && typeof rule.properties === 'object') ? rule.properties : {};

      var severity = props.severity != null
        ? normSeverity(props.severity)
        : levelToSeverity(res.level);

      // techniques: accept strings or {id,label} objects
      var rawTech = Array.isArray(props.techniques) ? props.techniques : [];
      var techniques = [];
      for (var t = 0; t < rawTech.length; t++) {
        var tk = rawTech[t];
        if (tk == null) continue;
        if (typeof tk === 'string') {
          techniques.push({ id: tk, label: tk });
        } else if (typeof tk === 'object') {
          var id = tk.id != null ? String(tk.id) : (tk.label != null ? String(tk.label) : '');
          var label = tk.label != null ? String(tk.label) : id;
          techniques.push({ id: id, label: label });
        }
      }

      // affected components — Cepheus key `affected-components`.
      var rawComps = Array.isArray(props['affected-components']) ? props['affected-components']
        : (Array.isArray(props.affectedComponents) ? props.affectedComponents : []);
      var components = [];
      for (var c = 0; c < rawComps.length; c++) {
        if (rawComps[c] != null) components.push(String(rawComps[c]));
      }

      // compliance crosswalk — Cepheus emits it on the rule as separate
      // arrays; fall back to a result-level `compliance` object map for
      // generic SARIF.
      var compliance = [];
      for (var ci = 0; ci < _COMPLIANCE_KEYS.length; ci++) {
        var arr = rprops[_COMPLIANCE_KEYS[ci][0]];
        if (Array.isArray(arr) && arr.length) {
          compliance.push({
            framework: _COMPLIANCE_KEYS[ci][1],
            ids: arr.map(function (x) { return String(x); })
          });
        }
      }
      var rawComp = (props.compliance && typeof props.compliance === 'object') ? props.compliance : {};
      for (var fw in rawComp) {
        if (!Object.prototype.hasOwnProperty.call(rawComp, fw)) continue;
        var ids = Array.isArray(rawComp[fw]) ? rawComp[fw].map(function (x) { return String(x); }) : [];
        compliance.push({ framework: String(fw), ids: ids });
      }

      var message = '';
      if (res.message && typeof res.message === 'object' && res.message.text != null) {
        message = String(res.message.text);
      } else if (typeof res.message === 'string') {
        message = res.message;
      }

      // reference: result-level override, else the rule's helpUri.
      var reference = props.reference != null ? String(props.reference)
        : (rule.helpUri != null ? String(rule.helpUri) : '');

      // recommendation: Cepheus emits it on the rule as `remediation`.
      var recommendation = rprops.remediation != null ? String(rprops.remediation)
        : (props.recommendation != null ? String(props.recommendation) : '');

      // impact: result-level, else the rule's curated impact.
      var impact = props.impact != null ? String(props.impact)
        : (rprops.impact != null ? String(rprops.impact) : '');

      var chainLen = numOrNull(_firstDefined(props['chain-length'], props.chainLength));
      if (chainLen === null) chainLen = techniques.length;

      findings.push({
        uid: 'f' + (seq++),
        ruleId: ruleId,
        title: rule.name != null ? String(rule.name) : ruleId,
        severity: severity,
        score: numOrNull(_firstDefined(props['composite-score'], props.score)),
        chainId: _firstDefined(props['chain-id'], props.chainId) != null
          ? String(_firstDefined(props['chain-id'], props.chainId)) : '',
        chainLength: chainLen,
        techniques: techniques,
        impact: impact,
        affectedComponents: components,
        recommendation: recommendation,
        message: message,
        reliability: numOrNull(_firstDefined(props['reliability-score'], props.reliability)),
        stealth: numOrNull(_firstDefined(props['stealth-score'], props.stealth)),
        confidence: numOrNull(_firstDefined(props['confidence-score'], props.confidence)),
        compliance: compliance,
        reference: reference
      });
    }
  }
  return findings;
}

/**
 * Does a finding match the free-text query + severity filter?
 * @param finding normalised finding
 * @param query   free text (case-insensitive substring)
 * @param sevFilter 'all' | '' | severity key
 */
function matchesFilter(finding, query, sevFilter) {
  if (!finding) return false;
  var sev = sevFilter && sevFilter !== 'all' ? normSeverity(sevFilter) : null;
  if (sev && normSeverity(finding.severity) !== sev) return false;

  var q = String(query || '').toLowerCase().trim();
  if (!q) return true;

  var hay = [
    finding.ruleId, finding.title, finding.impact, finding.message,
    finding.chainId, finding.recommendation
  ];
  for (var i = 0; i < finding.techniques.length; i++) {
    hay.push(finding.techniques[i].id, finding.techniques[i].label);
  }
  for (var c = 0; c < finding.affectedComponents.length; c++) {
    hay.push(finding.affectedComponents[c]);
  }
  for (var k = 0; k < finding.compliance.length; k++) {
    hay.push(finding.compliance[k].framework);
    hay.push(finding.compliance[k].ids.join(' '));
  }
  var joined = hay.join('').toLowerCase();
  // support multi-token AND search
  var tokens = q.split(/\s+/);
  for (var tok = 0; tok < tokens.length; tok++) {
    if (joined.indexOf(tokens[tok]) < 0) return false;
  }
  return true;
}

/* Expose pure helpers for unit tests (both module + global). */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { numOrNull: numOrNull, parseSarif: parseSarif, severityLabel: severityLabel, severityRank: severityRank, matchesFilter: matchesFilter };
}
