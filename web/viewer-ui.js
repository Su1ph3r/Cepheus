/* ============================================================================
   CEPHEUS · SARIF Explorer — viewer-ui.js
   DOM rendering + event wiring. Depends on the pure helpers in viewer.js
   (numOrNull, parseSarif, severityLabel, severityRank, matchesFilter,
   normSeverity, levelToSeverity), defined as globals there.
   All report-derived content is inserted via textContent / createElement;
   the SVG chain is built with createElementNS. Never innerHTML.
   ============================================================================ */
/* ----------------------------------------------------------------------------
   DOM RENDERING  (browser only)
   ---------------------------------------------------------------------------- */
(function () {
  if (typeof document === 'undefined') return;

  var SVGNS = 'http://www.w3.org/2000/svg';

  /* tiny safe element builder. children: strings become text nodes. */
  function mk(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      for (var key in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, key)) continue;
        var val = attrs[key];
        if (val == null) continue;
        if (key === 'class') node.className = val;
        else if (key === 'text') node.textContent = val;
        else node.setAttribute(key, val);
      }
    }
    if (children != null) {
      var list = Array.isArray(children) ? children : [children];
      for (var i = 0; i < list.length; i++) {
        var ch = list[i];
        if (ch == null) continue;
        node.appendChild(typeof ch === 'string' || typeof ch === 'number'
          ? document.createTextNode(String(ch)) : ch);
      }
    }
    return node;
  }

  function svgEl(tag, attrs) {
    var node = document.createElementNS(SVGNS, tag);
    if (attrs) {
      for (var key in attrs) {
        if (Object.prototype.hasOwnProperty.call(attrs, key) && attrs[key] != null) {
          node.setAttribute(key, attrs[key]);
        }
      }
    }
    return node;
  }

  /* Format a 0..1 score as fixed 2dp string, or em-dash. */
  function fmtScore(n) { return n === null ? '—' : n.toFixed(2); }
  function pct(n) { return n === null ? 0 : Math.max(0, Math.min(1, n)) * 100; }

  /* Is this a safe http(s) URL we may render as a link? */
  function safeHttpUrl(raw) {
    if (!raw) return null;
    try {
      var u = new URL(raw, window.location.href);
      if (u.protocol === 'http:' || u.protocol === 'https:') return u.href;
    } catch (e) { /* not a URL */ }
    return null;
  }

  /* ---- DOM references ---- */
  var refs = {
    html: document.documentElement,
    fileInput: document.getElementById('file-input'),
    openBtn: document.getElementById('open-button'),
    openBtn2: document.getElementById('open-button-2'),
    loadSample: document.getElementById('load-sample'),
    dropZone: document.getElementById('drop-zone'),
    loaderView: document.getElementById('loader-view'),
    dataView: document.getElementById('data-view'),
    parseError: document.getElementById('parse-error'),
    fileMeta: document.getElementById('file-meta'),
    fileName: document.getElementById('file-name'),
    fileCount: document.getElementById('file-count'),
    countCrit: document.getElementById('count-crit'),
    countHigh: document.getElementById('count-high'),
    countMed: document.getElementById('count-med'),
    countLow: document.getElementById('count-low'),
    filter: document.getElementById('filter'),
    severityFilter: document.getElementById('severity-filter'),
    tbody: document.getElementById('results-tbody'),
    emptyState: document.getElementById('empty-state'),
    detail: document.getElementById('detail'),
    detailEmpty: document.getElementById('detail-empty'),
    themeToggle: document.getElementById('theme-toggle'),
    iconMoon: document.getElementById('icon-moon'),
    iconSun: document.getElementById('icon-sun'),
    stats: Array.prototype.slice.call(document.querySelectorAll('.stat'))
  };

  /* ---- state ---- */
  var state = { findings: [], filename: '', query: '', sevFilter: 'all', selectedUid: null };

  /* ============================ THEME ============================ */
  function applyTheme(theme) {
    refs.html.setAttribute('data-theme', theme);
    var dark = theme === 'dark';
    refs.iconMoon.hidden = !dark;
    refs.iconSun.hidden = dark;
    try { localStorage.setItem('cepheus-theme', theme); } catch (e) {}
  }
  (function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem('cepheus-theme'); } catch (e) {}
    applyTheme(saved === 'light' || saved === 'dark' ? saved : 'dark');
  })();
  refs.themeToggle.addEventListener('click', function () {
    applyTheme(refs.html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  });

  /* ============================ LOAD ============================ */
  function showLoader(msg) {
    state.findings = [];
    state.selectedUid = null;
    refs.dataView.hidden = true;
    refs.loaderView.hidden = false;
    refs.fileMeta.hidden = true;
    if (msg) { refs.parseError.textContent = msg; refs.parseError.hidden = false; }
    else { refs.parseError.hidden = true; }
  }

  function loadText(text, filename) {
    var doc;
    try {
      doc = JSON.parse(text);
    } catch (e) {
      showLoader('Could not parse file: invalid JSON.');
      return;
    }
    var findings;
    try {
      findings = parseSarif(doc);
    } catch (e) {
      showLoader('Could not read SARIF structure.');
      return;
    }
    if (!findings.length) {
      showLoader('No results found in this SARIF report.');
      return;
    }
    state.findings = findings;
    state.filename = filename || 'report.sarif';
    state.selectedUid = null;
    state.query = '';
    state.sevFilter = 'all';
    if (refs.filter) refs.filter.value = '';
    if (refs.severityFilter) refs.severityFilter.value = 'all';
    refs.parseError.hidden = true;
    refs.loaderView.hidden = true;
    refs.dataView.hidden = false;
    renderHeaderMeta();
    renderCounts();
    state.animateRows = true;
    renderTable();
    // auto-select most severe finding
    var sorted = sortedFindings(state.findings);
    if (sorted.length) selectFinding(sorted[0].uid);
  }

  function readFile(file) {
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () { loadText(String(reader.result), file.name); };
    reader.onerror = function () { showLoader('Could not read the file.'); };
    reader.readAsText(file);
  }

  /* ============================ FILTER / SORT ============================ */
  function sortedFindings(list) {
    return list.slice().sort(function (a, b) {
      var d = severityRank(b.severity) - severityRank(a.severity);
      if (d !== 0) return d;
      var sa = a.score === null ? -1 : a.score;
      var sb = b.score === null ? -1 : b.score;
      if (sb !== sa) return sb - sa;
      return a.ruleId.localeCompare(b.ruleId);
    });
  }

  function visibleFindings() {
    var out = [];
    for (var i = 0; i < state.findings.length; i++) {
      if (matchesFilter(state.findings[i], state.query, state.sevFilter)) out.push(state.findings[i]);
    }
    return sortedFindings(out);
  }

  /* ============================ RENDER: header + counts ============================ */
  function renderHeaderMeta() {
    refs.fileMeta.hidden = false;
    refs.fileName.textContent = state.filename;
    var n = state.findings.length;
    refs.fileCount.textContent = n + (n === 1 ? ' finding' : ' findings');
  }

  function renderCounts() {
    var c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (var i = 0; i < state.findings.length; i++) {
      var s = normSeverity(state.findings[i].severity);
      if (c[s] !== undefined) c[s]++;
    }
    refs.countCrit.textContent = c.critical;
    refs.countHigh.textContent = c.high;
    refs.countMed.textContent = c.medium;
    refs.countLow.textContent = c.low;
  }

  function syncStatActive() {
    for (var i = 0; i < refs.stats.length; i++) {
      var sev = refs.stats[i].getAttribute('data-sev');
      refs.stats[i].classList.toggle('is-active', state.sevFilter === sev);
    }
  }

  /* ============================ RENDER: table ============================ */
  function severityPill(sev) {
    var key = normSeverity(sev);
    var pill = mk('span', { class: 'sev sev-' + key });
    pill.appendChild(mk('span', { class: 'dot' }));
    pill.appendChild(document.createTextNode(severityLabel(key)));
    return pill;
  }

  function miniChain(techniques) {
    var wrap = mk('div', { class: 'cell-chain' });
    var max = 4;
    for (var i = 0; i < techniques.length && i < max; i++) {
      if (i > 0) wrap.appendChild(mk('span', { class: 'arrow' }, '→'));
      wrap.appendChild(mk('span', { class: 'chip' }, techniques[i].label || techniques[i].id));
    }
    if (techniques.length > max) {
      wrap.appendChild(mk('span', { class: 'arrow' }, '→'));
      wrap.appendChild(mk('span', { class: 'more' }, '+' + (techniques.length - max)));
    }
    return wrap;
  }

  function renderTable() {
    var list = visibleFindings();
    refs.tbody.textContent = '';
    syncStatActive();

    if (!list.length) {
      refs.emptyState.hidden = false;
      return;
    }
    refs.emptyState.hidden = true;

    var frag = document.createDocumentFragment();
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      var tr = mk('tr');
      tr.setAttribute('data-uid', f.uid);
      tr.setAttribute('tabindex', '0');
      if (state.animateRows) tr.style.animationDelay = Math.min(i * 30, 340) + 'ms';
      else tr.style.animation = 'none';
      tr.setAttribute('role', 'button');
      if (f.uid === state.selectedUid) tr.className = 'is-selected';

      // severity cell
      tr.appendChild(mk('td', { class: 'c-sev' }, severityPill(f.severity)));

      // rule + chain cell
      var ruleCell = mk('td', { class: 'c-rule' });
      ruleCell.appendChild(mk('div', { class: 'cell-rule-id mono' }, f.ruleId));
      ruleCell.appendChild(mk('div', { class: 'cell-rule-title' }, f.title));
      ruleCell.appendChild(miniChain(f.techniques));
      tr.appendChild(ruleCell);

      // score cell
      var scoreCell = mk('td', { class: 'c-score score-cell' });
      scoreCell.appendChild(mk('div', { class: 'score-num mono' }, fmtScore(f.score)));
      var bar = mk('div', { class: 'score-bar' });
      bar.style.setProperty('--c', 'var(--' + sevVar(f.severity) + ')');
      var fill = mk('i');
      fill.style.width = pct(f.score) + '%';
      bar.appendChild(fill);
      scoreCell.appendChild(bar);
      tr.appendChild(scoreCell);

      (function (uid) {
        tr.addEventListener('click', function () { selectFinding(uid); });
        tr.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectFinding(uid); }
        });
      })(f.uid);

      frag.appendChild(tr);
    }
    refs.tbody.appendChild(frag);
    state.animateRows = false;
  }

  function sevVar(sev) {
    var s = normSeverity(sev);
    return s === 'critical' ? 'crit' : s === 'high' ? 'high' : s === 'medium' ? 'med'
      : s === 'low' ? 'low' : 'info';
  }

  /* ============================ RENDER: detail ============================ */
  function selectFinding(uid) {
    state.selectedUid = uid;
    // update row selection
    var rows = refs.tbody.querySelectorAll('tr');
    for (var i = 0; i < rows.length; i++) {
      rows[i].classList.toggle('is-selected', rows[i].getAttribute('data-uid') === uid);
    }
    var f = null;
    for (var j = 0; j < state.findings.length; j++) {
      if (state.findings[j].uid === uid) { f = state.findings[j]; break; }
    }
    if (!f) { refs.detail.hidden = true; refs.detailEmpty.hidden = false; return; }
    renderDetail(f);
  }

  function sectionLabel(ix, text) {
    var lab = mk('div', { class: 'sec-label' });
    lab.appendChild(mk('span', { class: 'ix mono' }, ix));
    lab.appendChild(document.createTextNode(text));
    return lab;
  }

  /* Render text that may contain `inline code` spans (from our own + report
     text). Backtick parsing is purely structural; the text itself is always
     inserted as text nodes, never HTML. */
  function richText(container, text) {
    var parts = String(text).split('`');
    for (var i = 0; i < parts.length; i++) {
      if (parts[i] === '') continue;
      if (i % 2 === 1) container.appendChild(mk('code', null, parts[i]));
      else container.appendChild(document.createTextNode(parts[i]));
    }
    return container;
  }

  function subscore(key, val) {
    var box = mk('div', { class: 'subscore' });
    var row = mk('div', { class: 'row' });
    row.appendChild(mk('span', { class: 'k' }, key));
    row.appendChild(mk('span', { class: 'v mono' }, fmtScore(val)));
    box.appendChild(row);
    var gauge = mk('div', { class: 'gauge' });
    var fill = mk('i');
    fill.style.width = pct(val) + '%';
    gauge.appendChild(fill);
    box.appendChild(gauge);
    return box;
  }

  function renderDetail(f) {
    refs.detailEmpty.hidden = true;
    refs.detail.hidden = false;
    refs.detail.textContent = '';
    refs.detail.scrollTop = 0;

    var sv = sevVar(f.severity);

    /* ---- head ---- */
    var head = mk('div', { class: 'd-head' });
    var top = mk('div', { class: 'top' });
    top.appendChild(severityPill(f.severity));
    top.appendChild(mk('span', { class: 'rule-id mono' }, f.ruleId));
    head.appendChild(top);
    head.appendChild(mk('h2', { class: 'title' }, f.title));

    // hero score + chain meta
    var hero = mk('div', { class: 'score-hero' });
    var big = mk('div', { class: 'big' });
    var val = mk('div', { class: 'val mono' }, fmtScore(f.score));
    val.style.setProperty('--c', 'var(--' + sv + ')');
    big.appendChild(val);
    big.appendChild(mk('div', { class: 'cap' }, 'Composite score'));
    hero.appendChild(big);

    var cols = mk('div', { class: 'meta-cols' });
    var mc1 = mk('div', { class: 'mc' });
    mc1.appendChild(mk('div', { class: 'k' }, 'Chain'));
    mc1.appendChild(mk('div', { class: 'v mono' }, f.chainId || '—'));
    cols.appendChild(mc1);
    var mc2 = mk('div', { class: 'mc' });
    mc2.appendChild(mk('div', { class: 'k' }, 'Length'));
    mc2.appendChild(mk('div', { class: 'v mono' }, (f.chainLength != null ? f.chainLength : f.techniques.length) + ' steps'));
    cols.appendChild(mc2);
    hero.appendChild(cols);
    head.appendChild(hero);

    // magnitude gauge (instrument readout)
    var mag = mk('div', { class: 'mag' });
    var scale = mk('div', { class: 'scale' });
    scale.style.setProperty('--c', 'var(--' + sv + ')');
    var magFill = mk('i');
    magFill.style.width = pct(f.score) + '%';
    scale.appendChild(magFill);
    mag.appendChild(scale);
    var ticks = mk('div', { class: 'ticks' });
    ['0.00', '0.25', '0.50', '0.75', '1.00'].forEach(function (t) { ticks.appendChild(mk('span', null, t)); });
    mag.appendChild(ticks);
    head.appendChild(mag);

    refs.detail.appendChild(head);

    /* ---- chain visualizer ---- */
    var chainBlock = mk('div', { class: 'chain-block' });
    var chHead = mk('div', { class: 'chain-head' });
    chHead.appendChild(sectionLabel('◆', 'Escape chain'));
    chHead.appendChild(mk('span', { class: 'rule-id mono' }, f.techniques.length + ' techniques'));
    chainBlock.appendChild(chHead);
    var sky = mk('div', { class: 'sky' });
    sky.appendChild(mk('span', { class: 'corner tl' }, 'Entry vector'));
    sky.appendChild(mk('span', { class: 'corner tr' }, f.chainId || '—'));
    sky.appendChild(mk('span', { class: 'corner bl' }, severityLabel(f.severity) + ' path'));
    sky.appendChild(mk('span', { class: 'corner br' }, (f.chainLength != null ? f.chainLength : f.techniques.length) + ' hops'));
    var chScroll = mk('div', { class: 'chain-scroll scroll' });
    chScroll.appendChild(buildChainSvg(f));
    sky.appendChild(chScroll);
    chainBlock.appendChild(sky);
    refs.detail.appendChild(chainBlock);

    /* ---- body (spec order) ---- */
    var body = mk('div', { class: 'd-body' });

    // 1. Affected components
    var fc = mk('div', { class: 'field' });
    fc.appendChild(sectionLabel('01', 'Affected components'));
    var comps = mk('div', { class: 'components' });
    if (f.affectedComponents.length) {
      for (var i = 0; i < f.affectedComponents.length; i++) {
        var comp = mk('span', { class: 'component mono' });
        comp.appendChild(mk('span', { class: 'sq' }));
        comp.appendChild(document.createTextNode(f.affectedComponents[i]));
        comps.appendChild(comp);
      }
    } else {
      comps.appendChild(mk('span', { class: 'inert mono' }, '—'));
    }
    fc.appendChild(comps);
    body.appendChild(fc);

    // 2. Impact
    var fi = mk('div', { class: 'field' });
    fi.appendChild(sectionLabel('02', 'Impact'));
    fi.appendChild(richText(mk('p', { class: 'impact-text' }), f.impact || '—'));
    body.appendChild(fi);

    // 3. Recommendation (FIRST, before message)
    var fr = mk('div', { class: 'field' });
    fr.appendChild(sectionLabel('03', 'Recommendation'));
    var reco = mk('div', { class: 'reco' });
    reco.appendChild(richText(mk('p', { class: 'body-text' }), f.recommendation || '—'));
    fr.appendChild(reco);
    body.appendChild(fr);

    // 4. Message
    var fm = mk('div', { class: 'field' });
    fm.appendChild(sectionLabel('04', 'Analysis'));
    fm.appendChild(richText(mk('p', { class: 'body-text' }), f.message || '—'));
    body.appendChild(fm);

    // 5. Sub-scores
    var fs = mk('div', { class: 'field' });
    fs.appendChild(sectionLabel('05', 'Sub-scores'));
    var grid = mk('div', { class: 'subscores' });
    grid.appendChild(subscore('Reliability', f.reliability));
    grid.appendChild(subscore('Stealth', f.stealth));
    grid.appendChild(subscore('Confidence', f.confidence));
    fs.appendChild(grid);
    body.appendChild(fs);

    // 6. Compliance crosswalk
    var fw = mk('div', { class: 'field' });
    fw.appendChild(sectionLabel('06', 'Compliance crosswalk'));
    var cw = mk('div', { class: 'crosswalk' });
    if (f.compliance.length) {
      for (var k = 0; k < f.compliance.length; k++) {
        var row = mk('div', { class: 'cw-row' });
        row.appendChild(mk('div', { class: 'fw' }, f.compliance[k].framework));
        var ids = mk('div', { class: 'cw-ids' });
        if (f.compliance[k].ids.length) {
          for (var m = 0; m < f.compliance[k].ids.length; m++) {
            ids.appendChild(mk('span', { class: 'cw-id mono' }, f.compliance[k].ids[m]));
          }
        } else {
          ids.appendChild(mk('span', { class: 'inert mono' }, '—'));
        }
        row.appendChild(ids);
        cw.appendChild(row);
      }
    } else {
      cw.appendChild(mk('span', { class: 'inert mono' }, '—'));
    }
    fw.appendChild(cw);
    body.appendChild(fw);

    // 7. Reference (only attribute sink — http(s) only)
    var fref = mk('div', { class: 'field reference' });
    fref.appendChild(sectionLabel('07', 'Reference'));
    var safe = safeHttpUrl(f.reference);
    if (safe) {
      var a = mk('a', { href: safe, target: '_blank', rel: 'noopener noreferrer nofollow' });
      var lk = svgEl('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' });
      lk.appendChild(svgEl('path', { d: 'M15 3h6v6' }));
      lk.appendChild(svgEl('path', { d: 'M10 14 21 3' }));
      lk.appendChild(svgEl('path', { d: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6' }));
      a.appendChild(lk);
      a.appendChild(document.createTextNode(safe));
      fref.appendChild(a);
    } else if (f.reference) {
      // non-http scheme: render inert, never as a link
      fref.appendChild(mk('span', { class: 'inert mono' }, f.reference));
    } else {
      fref.appendChild(mk('span', { class: 'inert mono' }, '—'));
    }
    body.appendChild(fref);

    refs.detail.appendChild(body);
  }

  /* ============================ CHAIN SVG (createElementNS) ============================ */
  function sevColor(sev) {
    var map = {
      critical: getCSS('--crit'), high: getCSS('--high'), medium: getCSS('--med'),
      low: getCSS('--low'), info: getCSS('--info')
    };
    return map[normSeverity(sev)] || map.info;
  }
  function getCSS(name) {
    return getComputedStyle(refs.html).getPropertyValue(name).trim() || '#888';
  }

  /* deterministic 0..1 pseudo-random from a string (FNV-ish) */
  function hash01(s) {
    var h = 2166136261;
    s = String(s);
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 16777619) >>> 0; }
    return (h % 100000) / 100000;
  }

  /* Build the escape chain as a constellation star-map (createElementNS only). */
  function buildChainSvg(f) {
    var techs = f.techniques.length ? f.techniques : [{ id: f.ruleId, label: f.ruleId }];
    var n = techs.length;

    var stepX = 164;
    var padX = 84;
    var midY = 92;
    var band = 27;                 // vertical jitter amplitude
    var width = Math.max(padX * 2 + (n - 1) * stepX, 380);
    var height = 212;
    var labY = height - 36;        // labels share a baseline regardless of jitter

    var color = sevColor(f.severity);
    var muted = getCSS('--text-3');
    var textCol = getCSS('--text');
    var starCol = getCSS('--sky-star');
    var solid = getCSS('--sky-solid') || '#0a1120';

    var svg = svgEl('svg', {
      id: 'chain-view', width: width, height: height,
      viewBox: '0 0 ' + width + ' ' + height, role: 'img'
    });
    svg.setAttribute('aria-label', 'Escape chain: ' + techs.map(function (t) { return t.label; }).join(' then '));

    /* ---- defs: glow blur + node halo gradient ---- */
    var defs = svgEl('defs');
    var filt = svgEl('filter', { id: 'cep-glow', x: '-60%', y: '-60%', width: '220%', height: '220%' });
    filt.appendChild(svgEl('feGaussianBlur', { in: 'SourceGraphic', stdDeviation: '3' }));
    defs.appendChild(filt);
    var grad = svgEl('radialGradient', { id: 'cep-halo' });
    grad.appendChild(svgEl('stop', { offset: '0%', 'stop-color': color, 'stop-opacity': '0.55' }));
    grad.appendChild(svgEl('stop', { offset: '65%', 'stop-color': color, 'stop-opacity': '0.10' }));
    grad.appendChild(svgEl('stop', { offset: '100%', 'stop-color': color, 'stop-opacity': '0' }));
    defs.appendChild(grad);
    svg.appendChild(defs);

    /* ---- twinkling backdrop starfield (deterministic per chain) ---- */
    var seed = f.chainId || f.ruleId || 'cep';
    var starN = Math.min(52, 20 + n * 5);
    var gStars = svgEl('g');
    for (var s = 0; s < starN; s++) {
      var star = svgEl('circle', {
        cx: (hash01(seed + 'x' + s) * width).toFixed(1),
        cy: (hash01(seed + 'y' + s) * height).toFixed(1),
        r: (0.5 + hash01(seed + 'r' + s) * 1.3).toFixed(2),
        fill: starCol
      });
      star.setAttribute('class', 'cep-star');
      var hi = 0.35 + hash01(seed + 'h' + s) * 0.5;
      star.style.setProperty('--tw-hi', hi.toFixed(2));
      star.style.setProperty('--tw-lo', (hi * 0.22).toFixed(2));
      star.style.setProperty('--tw-dur', (2.6 + hash01(seed + 'd' + s) * 4).toFixed(2) + 's');
      star.style.animationDelay = (hash01(seed + 'l' + s) * 4).toFixed(2) + 's';
      gStars.appendChild(star);
    }
    svg.appendChild(gStars);

    /* ---- node coordinates (left->right with deterministic jitter) ---- */
    var pts = [];
    for (var i = 0; i < n; i++) {
      var jy = n === 1 ? 0 : (hash01(techs[i].id + '|' + i) * 2 - 1) * band;
      pts.push({ x: padX + i * stepX, y: midY + jy });
    }

    /* ---- connecting constellation path (glow + crisp draw-in) ---- */
    if (n > 1) {
      var d = '', len = 0;
      for (var p = 0; p < n; p++) {
        d += (p === 0 ? 'M' : 'L') + pts[p].x.toFixed(1) + ' ' + pts[p].y.toFixed(1) + ' ';
        if (p > 0) { var ddx = pts[p].x - pts[p - 1].x, ddy = pts[p].y - pts[p - 1].y; len += Math.sqrt(ddx * ddx + ddy * ddy); }
      }
      var glowPath = svgEl('path', {
        d: d, fill: 'none', stroke: color, 'stroke-width': '6',
        'stroke-linecap': 'round', 'stroke-linejoin': 'round', opacity: '0.3', filter: 'url(#cep-glow)'
      });
      glowPath.setAttribute('class', 'cep-path');
      glowPath.style.setProperty('--len', Math.ceil(len));
      svg.appendChild(glowPath);
      var path = svgEl('path', {
        d: d, fill: 'none', stroke: color, 'stroke-width': '1.6',
        'stroke-linecap': 'round', 'stroke-linejoin': 'round'
      });
      path.setAttribute('class', 'cep-path');
      path.style.setProperty('--len', Math.ceil(len));
      svg.appendChild(path);

      /* direction arrowheads at each segment midpoint */
      for (var m = 1; m < n; m++) {
        var a = pts[m - 1], b = pts[m];
        var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        var ang = Math.atan2(b.y - a.y, b.x - a.x) * 180 / Math.PI;
        var tri = svgEl('path', { d: 'M-4 -3.4 L4 0 L-4 3.4 Z', fill: color, opacity: '0.9' });
        tri.setAttribute('transform', 'translate(' + mx.toFixed(1) + ' ' + my.toFixed(1) + ') rotate(' + ang.toFixed(1) + ')');
        svg.appendChild(tri);
      }
    }

    /* ---- nodes rendered as stars ---- */
    var spikes = [[0, -19, 0, 19], [-19, 0, 19, 0], [-11, -11, 11, 11], [11, -11, -11, 11]];
    for (var k = 0; k < n; k++) {
      var cx = pts[k].x, cy = pts[k].y;

      // dashed connector tying the (jittered) node to its label baseline
      var conn = svgEl('line', { x1: cx, y1: cy + 13, x2: cx, y2: labY - 13, stroke: color, 'stroke-width': '1', opacity: '0.22', 'stroke-dasharray': '2 3' });
      svg.appendChild(conn);

      var g = svgEl('g');
      g.setAttribute('class', 'cep-node');
      g.style.animationDelay = (150 + k * 110) + 'ms';

      g.appendChild(svgEl('circle', { cx: cx, cy: cy, r: '26', fill: 'url(#cep-halo)' }));
      for (var sp = 0; sp < spikes.length; sp++) {
        g.appendChild(svgEl('line', {
          x1: cx + spikes[sp][0], y1: cy + spikes[sp][1], x2: cx + spikes[sp][2], y2: cy + spikes[sp][3],
          stroke: color, 'stroke-width': sp < 2 ? '1.4' : '1', 'stroke-linecap': 'round', opacity: sp < 2 ? '0.5' : '0.26'
        }));
      }
      g.appendChild(svgEl('circle', { cx: cx, cy: cy, r: '11', fill: solid, stroke: color, 'stroke-width': '2' }));
      g.appendChild(svgEl('circle', { cx: cx, cy: cy, r: '4.3', fill: color }));
      g.appendChild(svgEl('circle', { cx: cx - 1.3, cy: cy - 1.3, r: '1.3', fill: '#ffffff', opacity: '0.9' }));
      svg.appendChild(g);

      // step badge above node
      var idx = svgEl('text', { x: cx, y: cy - 23, 'text-anchor': 'middle', fill: muted, 'font-size': '9.5', 'font-weight': '600', 'letter-spacing': '0.08em' });
      idx.textContent = String(k + 1).padStart(2, '0');
      svg.appendChild(idx);

      // labels on shared baseline
      var lab = svgEl('g');
      lab.setAttribute('class', 'cep-label');
      lab.style.animationDelay = (280 + k * 110) + 'ms';
      var tid = svgEl('text', { x: cx, y: labY, 'text-anchor': 'middle', fill: textCol, 'font-size': '11', 'font-weight': '600' });
      tid.textContent = truncate(techs[k].id, 17);
      lab.appendChild(tid);
      var tlabel = svgEl('text', { x: cx, y: labY + 15, 'text-anchor': 'middle', fill: muted, 'font-size': '10' });
      tlabel.textContent = truncate(techs[k].label, 20);
      lab.appendChild(tlabel);
      svg.appendChild(lab);
    }
    return svg;
  }

  function truncate(s, max) {
    s = String(s);
    return s.length > max ? s.slice(0, max - 1) + '…' : s;
  }

  /* ============================ EVENTS ============================ */
  function openPicker() { refs.fileInput.click(); }
  refs.openBtn.addEventListener('click', openPicker);
  if (refs.openBtn2) refs.openBtn2.addEventListener('click', openPicker);

  refs.fileInput.addEventListener('change', function (e) {
    if (e.target.files && e.target.files[0]) readFile(e.target.files[0]);
    e.target.value = '';
  });

  // drag & drop
  ['dragenter', 'dragover'].forEach(function (ev) {
    refs.dropZone.addEventListener(ev, function (e) {
      e.preventDefault(); e.stopPropagation();
      refs.dropZone.classList.add('is-drag');
    });
  });
  ['dragleave', 'dragend'].forEach(function (ev) {
    refs.dropZone.addEventListener(ev, function (e) {
      e.preventDefault(); e.stopPropagation();
      refs.dropZone.classList.remove('is-drag');
    });
  });
  refs.dropZone.addEventListener('drop', function (e) {
    e.preventDefault(); e.stopPropagation();
    refs.dropZone.classList.remove('is-drag');
    var dt = e.dataTransfer;
    if (dt && dt.files && dt.files[0]) readFile(dt.files[0]);
  });
  // prevent the window from navigating if a file is dropped outside the zone
  window.addEventListener('dragover', function (e) { e.preventDefault(); });
  window.addEventListener('drop', function (e) { e.preventDefault(); });

  // search + filter
  refs.filter.addEventListener('input', function () {
    state.query = refs.filter.value;
    renderTable();
  });
  refs.severityFilter.addEventListener('change', function () {
    state.sevFilter = refs.severityFilter.value;
    renderTable();
  });
  // stat cards act as severity quick-filters (toggle)
  for (var si = 0; si < refs.stats.length; si++) {
    refs.stats[si].addEventListener('click', function () {
      var sev = this.getAttribute('data-sev');
      state.sevFilter = (state.sevFilter === sev) ? 'all' : sev;
      refs.severityFilter.value = state.sevFilter;
      renderTable();
    });
  }

  // sample loader
  if (refs.loadSample) {
    refs.loadSample.addEventListener('click', loadSample);
  }
  function loadSample() {
    var el = document.getElementById('sample-report');
    if (el) loadText(el.textContent, 'cepheus-demo.sarif');
  }

  /* ============================ BOOT ============================ */
  // Auto-load the embedded sample so the mockup is populated on open.
  loadSample();

})();
/* end of viewer.js */
