const LC_STATUS_TEXT = {
  ACTIVE: 'ACTIVE — upstream 의 1차 지원 단계',
  SECURITY_SUPPORT: 'SECURITY — upstream 이 security 로 명시한 단계',
  EXTENDED_SUPPORT: 'EXTENDED — EOL 이후 upstream 이 밝힌 확장 지원(유료 포함) 단계',
  EOL: 'EOL — upstream 기준 지원 종료',
  UNKNOWN: 'UNKNOWN — 데이터가 없거나, upstream 단계명이 정규화 상태로 명확히 대응되지 않음',
};
const LC_STAT_ORDER = ['ACTIVE', 'SECURITY_SUPPORT', 'EXTENDED_SUPPORT', 'EOL', 'UNKNOWN'];
const LC_WINDOWS = [30, 90, 180];
const LC_ROWS_SHOWN = 6;
const LC_VIEW = { status: '', window: '', linked: false, search: '', sort: 'default', dir: 1 };
let lcLinked = null;
let lcOrder = null;

const lcMeta = slug => (lifecycleData && lifecycleData.products[slug]) || null;
const lcStatus = rel => LC.statusOf(rel, lcMeta(rel.product_slug), lcToday);
const lcNa = title => `<span class="lc-na"${title ? ` title="${escapeHtml(title)}"` : ''}>-</span>`;

function lcDateCell(date, flag, notYet, done) {
  if (date) return escapeHtml(date);
  if (flag === false) return lcNa(notYet);
  if (flag === true) return lcNa(done);
  return lcNa();
}

function lcBadge(status, count, title) {
  return `<span class="lc-badge lc-${status}" title="${escapeHtml(title || LC_STATUS_TEXT[status])}">${
    LC.SHORT[status]}${count != null ? `<b>×${count}</b>` : ''}</span>`;
}

function lcLink(url, text) {
  return isSafeUrl(url) ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)} ↗</a>` : '';
}

function lcHost(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch (e) { return '원출처'; }
}

function lcFetched(ts) {
  const d = new Date(ts || '');
  return isNaN(d) ? '-' : d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function lcReleaseOrder(rel) {
  if (!lcOrder) lcOrder = new Map((lifecycleData.releases || []).map((r, i) => [r, i]));
  return lcOrder.has(rel) ? lcOrder.get(rel) : 1e9;
}

function lcLinkedCounts() {
  if (lcLinked) return lcLinked;
  lcLinked = new Map();
  for (const cve of allCves) {
    for (const e of cveLifecycle(cve).entries) lcLinked.set(e.rel, (lcLinked.get(e.rel) || 0) + 1);
  }
  return lcLinked;
}

function lcCounts(rels) {
  const counts = {};
  for (const s of LC.STATUSES) counts[s] = 0;
  for (const rel of rels) counts[lcStatus(rel)]++;
  return counts;
}

/* ---------- 타임라인 ---------- */

function lcAxis(rels) {
  let lo = null;
  let hi = lcToday;
  for (const rel of rels) {
    for (const seg of LC.timeline(rel, lcMeta(rel.product_slug))) {
      if (!lo || seg.from < lo) lo = seg.from;
      if (seg.to && seg.to > hi) hi = seg.to;
    }
  }
  if (!lo) return null;
  const a = Date.parse(`${lo}T00:00:00Z`);
  const b = Date.parse(`${hi}T00:00:00Z`);
  return { lo: a, hi: b + Math.max(86400000 * 60, (b - a) * 0.04), from: lo.slice(0, 4), to: hi.slice(0, 4) };
}

function lcTimeline(rel, axis) {
  if (!axis) return '';
  const span = axis.hi - axis.lo || 1;
  const pos = d => Math.max(0, Math.min(100, (Date.parse(`${d}T00:00:00Z`) - axis.lo) / span * 100));
  const segs = LC.timeline(rel, lcMeta(rel.product_slug)).filter(s => s.to || s.open).map(s => {
    const left = pos(s.from);
    const right = s.to ? pos(s.to) : 100;
    const label = `${s.label || LC.SHORT[s.status]} (${LC.SHORT[s.status]}): ${s.from} → ${s.to || '종료일 미정'}`;
    return `<span class="lc-seg lc-${s.status}${s.open ? ' is-open' : ''}" style="left:${left.toFixed(2)}%;width:${
      Math.max(0.8, right - left).toFixed(2)}%" title="${escapeHtml(label)}"></span>`;
  }).join('');
  if (!segs) return '<span class="lc-na" title="날짜가 없어 그릴 수 없음">-</span>';
  return `<div class="lc-tl">${segs}<span class="lc-today" style="left:${pos(lcToday).toFixed(2)}%" title="오늘 ${lcToday}"></span></div>`;
}

function lcLegend() {
  return `<div class="lc-legend">${LC_STAT_ORDER.map(s =>
    `<span title="${escapeHtml(LC_STATUS_TEXT[s])}"><i class="lc-dot lc-${s}"></i>${LC.SHORT[s]}</span>`).join('')
  }<span class="lc-legend-today"><i></i>오늘</span></div>`;
}

/* ---------- CVE 상세 ---------- */

function lcRow(rel, axis, extra) {
  const meta = lcMeta(rel.product_slug) || {};
  const labels = meta.labels || {};
  const status = lcStatus(rel);
  const phase = LC.phaseLabel(rel, meta, lcToday);
  const title = `${LC_STATUS_TEXT[status]}${phase ? ` · upstream 단계: ${phase}` : ''}`;
  const sub = [rel.cycle_label && rel.cycle_label !== rel.cycle ? escapeHtml(rel.cycle_label) : '',
               `최신 ${rel.latest_version ? escapeHtml(rel.latest_version) : '-'}`].filter(Boolean).join(' · ');
  return `<tr${extra ? ' class="lc-extra" hidden' : ''}>
    <td><b>${escapeHtml(rel.cycle)}</b><span class="lc-cycle-label">${sub}</span></td>
    <td>${lcBadge(status, null, title)}</td>
    <td>${lcDateCell(rel.release_date)}</td>
    <td>${labels.eoas ? lcDateCell(rel.support_end, rel.support_ended, '날짜 미정 — upstream: 아직 끝나지 않음', '날짜 미상 — upstream: 끝남') : lcNa('upstream 에 별도 단계 없음')}</td>
    <td>${lcDateCell(rel.security_support_end)}</td>
    <td>${labels.eoes ? lcDateCell(rel.extended_support_end, rel.extended_support_ended, '날짜 미정 — upstream: 진행 중', '날짜 미상 — upstream: 끝남') : lcNa('upstream 에 확장 지원 단계 없음')}</td>
    <td>${lcDateCell(rel.eol_date, rel.eol_reached, '날짜 미정 — upstream: 아직 EOL 아님', '날짜 미상 — upstream: EOL')}</td>
    <td class="lc-tl-cell">${lcTimeline(rel, axis)}</td>
  </tr>`;
}

function lcPhaseNames(meta) {
  const l = (meta && meta.labels) || {};
  const parts = [];
  if (l.eoas) parts.push(`지원 종료 = '${l.eoas}' 단계의 끝`);
  if (l.eol) parts.push(`EOL = '${l.eol}' 단계의 끝`);
  if (l.eoes) parts.push(`확장지원 종료 = '${l.eoes}' 단계의 끝`);
  return parts.join(' · ');
}

function lcGroup(slug, entries) {
  const meta = lcMeta(slug) || {};
  const rels = entries.map(e => e.rel).sort((a, b) => lcReleaseOrder(a) - lcReleaseOrder(b));
  const axis = lcAxis(rels);
  const counts = lcCounts(rels);
  const summary = LC.DISPLAY_ORDER.filter(s => counts[s]).map(s => lcBadge(s, counts[s])).join('');
  const byVia = new Map();
  for (const e of entries) {
    if (!byVia.has(e.via)) byVia.set(e.via, new Set());
    if (e.key) byVia.get(e.via).add(e.key);
  }
  const vias = [...byVia].map(([via, keys]) =>
    `<span title="${escapeHtml([...keys].join('\n'))}">${escapeHtml(LC.VIA[via] || via)}${keys.size ? ` ${keys.size}개 키` : ''}</span>`);
  const fixedOnly = entries.some(e => e.basis === 'fixed');
  const rows = rels.map((rel, i) => lcRow(rel, axis, i >= LC_ROWS_SHOWN)).join('');
  const more = rels.length > LC_ROWS_SHOWN
    ? `<button type="button" class="lc-toggle" onclick="lcToggleRows(this)" data-more="${rels.length - LC_ROWS_SHOWN}">나머지 ${rels.length - LC_ROWS_SHOWN}개 사이클 보기</button>` : '';
  return `<div class="lc-group">
    <div class="lc-group-head">
      <b class="lc-product">${escapeHtml(meta.label || slug)}</b>
      ${meta.vendor ? `<span class="lc-vendor">${escapeHtml(meta.vendor)}</span>` : ''}
      <span class="lc-sum">${summary}</span>
    </div>
    <div class="lc-group-meta">연결 근거(키는 마우스를 올리면 보임): ${vias.join(' · ')}${fixedOnly ? ' · OSV 수정 버전 기준 — 수정이 없는 사이클은 목록에 없을 수 있음' : ''}</div>
    <div class="lc-table-wrap"><table class="lc-table">
      <thead><tr><th>사이클 · 최신</th><th>상태</th><th>출시</th><th>지원 종료</th><th>보안지원 종료</th><th>확장지원 종료</th><th>EOL</th>
        <th class="lc-tl-head">${axis ? `<span>${axis.from}</span><span>${axis.to}</span>` : '타임라인'}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    ${more}
    <div class="lc-src">${escapeHtml(lcPhaseNames(meta))}${lcPhaseNames(meta) ? '<br>' : ''}출처: ${
      lcLink(meta.source_url, 'endoflife.date')}${isSafeUrl(meta.original_source_url) ? ` · 원출처 정책: ${lcLink(meta.original_source_url, lcHost(meta.original_source_url))}` : ''} · 수집 ${escapeHtml(lcFetched(meta.fetched_at))}</div>
  </div>`;
}

function lcToggleRows(btn) {
  const group = btn.closest('.lc-group');
  if (!group) return;
  const rows = group.querySelectorAll('tr.lc-extra');
  const open = [...rows].some(r => r.hidden);
  rows.forEach(r => { r.hidden = !open; });
  btn.textContent = open ? '접기' : `나머지 ${btn.dataset.more}개 사이클 보기`;
}

function lcUnresolvedName(slug) {
  const meta = lcMeta(slug);
  if (meta) return meta.label || slug;
  const u = lifecycleMatcher && lifecycleMatcher.unavailable.get(slug);
  return (u && u.name) || slug;
}

function renderLifecycleSection(cve) {
  if (!LC) return '';
  const head = '<h3>⏳ Product Lifecycle <span>영향 제품 릴리스의 지원 상태 · CVE 위험도와 별개</span></h3>';
  if (!lifecycleData) {
    return `<section class="lc-section">${head}<p class="lc-empty">수명주기 데이터(data/lifecycle.json)를 불러오지 못했습니다 — 영향 제품 전부 UNKNOWN 으로 둡니다.</p></section>`;
  }
  const r = cveLifecycle(cve);
  const groups = new Map();
  for (const e of r.entries) {
    if (!groups.has(e.slug)) groups.set(e.slug, []);
    groups.get(e.slug).push(e);
  }
  const blocks = [...groups].map(([slug, entries]) => lcGroup(slug, entries)).join('');
  const unresolved = r.unresolved.map(u => `<div class="lc-unresolved">${lcBadge('UNKNOWN')}<b>${
    escapeHtml(lcUnresolvedName(u.slug))}</b> — ${escapeHtml(LC.REASONS[u.reason] || u.reason || '판단 불가')}${
    lcMeta(u.slug) ? ` · ${lcLink(lcMeta(u.slug).source_url, 'endoflife.date')}` : ''}</div>`).join('');
  const untracked = r.untracked
    ? `<div class="lc-untracked">그 밖의 영향 제품 항목 ${r.untracked}개는 수명주기 데이터가 없습니다 (endoflife.date 추적 대상 아님 → UNKNOWN).</div>` : '';
  const body = blocks || unresolved || untracked
    ? `${blocks}${unresolved}${untracked}`
    : '<p class="lc-empty">영향 제품 정보가 없어 수명주기를 표시할 수 없습니다 (UNKNOWN).</p>';
  return `<section class="lc-section">${head}${blocks ? lcLegend() : ''}${body}
    <div class="lc-foot">날짜·단계명은 endoflife.date 값을 그대로 옮기고 없는 값은 '-' 로 둡니다(추정하지 않음). 상태는 오늘(${escapeHtml(lcToday)}) 기준으로 다시 계산합니다.
      사이클은 영향 버전 문자열에서 읽을 수 있을 때만 연결합니다. 출처: endoflife.date (MIT · Copyright 2020 endoflife.date contributors)</div>
  </section>`;
}

/* ---------- CVE 화면 요약 줄 ---------- */

function renderLifecycleStrip() {
  const box = document.getElementById('lc-strip');
  const stats = document.getElementById('lc-strip-stats');
  if (!box || !stats || !LC || !lifecycleData) return;
  const linked = [...lcLinkedCounts().keys()];
  const counts = lcCounts(linked);
  const soon = LC_WINDOWS.map(n => [n, linked.filter(rel => LC.eolWithin(rel, '<', n, lcToday)).length]);
  stats.innerHTML = LC_STAT_ORDER.map(s =>
    `<span class="lc-stat" title="${escapeHtml(LC_STATUS_TEXT[s])}"><i class="lc-dot lc-${s}"></i>${LC.SHORT[s]} <b>${counts[s].toLocaleString()}</b></span>`).join('')
    + '<span class="lc-stat-sep"></span>'
    + soon.map(([n, c]) => `<span class="lc-stat" title="EOL 날짜가 오늘 이후 ${n}일 미만 남은 릴리스 (eol:<${n}d)">EOL까지 ${n}일 미만 <b>${c.toLocaleString()}</b></span>`).join('');
  box.hidden = false;
}

/* ---------- Product Lifecycle 탭 ---------- */

function lcHaystack(rel) {
  const meta = lcMeta(rel.product_slug) || {};
  const status = lcStatus(rel);
  return [meta.vendor, meta.label, rel.product_slug, rel.cycle, rel.cycle_label, rel.codename, rel.release_date,
          rel.support_end, rel.security_support_end, rel.extended_support_end, rel.eol_date, rel.latest_version,
          status, LC.SHORT[status], LC.phaseLabel(rel, meta, lcToday), rel.source_provider]
    .filter(Boolean).join(' ').toLowerCase();
}

function lcMatchesSearch(rel, query) {
  const { terms, words } = parseQuery(query);
  const meta = lcMeta(rel.product_slug) || {};
  for (const { field, op, value } of terms) {
    if (field === 'lifecycle') {
      const s = LC.queryStatus(value);
      if (!s || lcStatus(rel) !== s) return false;
    } else if (field === 'eol') {
      const days = LC.parseDays(value);
      if (days === null || !LC.eolWithin(rel, op, days, lcToday)) return false;
    } else if (field === 'vendor') {
      if (!String(meta.vendor || '').toLowerCase().includes(value)) return false;
    } else if (field === 'product') {
      if (!`${meta.label || ''} ${rel.product_slug}`.toLowerCase().includes(value)) return false;
    } else if (!lcHaystack(rel).includes(`${field}:${value}`)) {
      return false;
    }
  }
  const hay = lcHaystack(rel);
  return words.every(w => hay.includes(w));
}

function lcSortValue(rel, key, linked) {
  const meta = lcMeta(rel.product_slug) || {};
  switch (key) {
    case 'vendor': return String(meta.vendor || '').toLowerCase();
    case 'product': return String(meta.label || rel.product_slug).toLowerCase();
    case 'release': return rel.release_date || null;
    case 'eol': return rel.eol_date || null;
    case 'status': return LC.DISPLAY_ORDER.indexOf(lcStatus(rel));
    case 'cves': return linked.get(rel) || 0;
    default: return 0;
  }
}

function lcVisibleReleases() {
  const linked = lcLinkedCounts();
  let rels = (lifecycleData.releases || []).slice();
  if (LC_VIEW.linked) rels = rels.filter(rel => linked.get(rel));
  const scope = rels;
  if (LC_VIEW.status) rels = rels.filter(rel => lcStatus(rel) === LC_VIEW.status);
  if (LC_VIEW.window) rels = rels.filter(rel => LC.eolWithin(rel, '<', Number(LC_VIEW.window), lcToday));
  if (LC_VIEW.search.trim()) rels = rels.filter(rel => lcMatchesSearch(rel, LC_VIEW.search));
  const key = LC_VIEW.sort;
  rels.sort((a, b) => {
    if (key !== 'default') {
      const va = lcSortValue(a, key, linked), vb = lcSortValue(b, key, linked);
      // 날짜가 없는 릴리스는 정렬 방향과 관계없이 맨 뒤 — 빈 값을 먼 미래(=지원 중)나 먼 과거로 취급하지 않는다
      if (va === null || vb === null) {
        if (va !== vb) return va === null ? 1 : -1;
      } else if (va < vb) return -LC_VIEW.dir;
      else if (va > vb) return LC_VIEW.dir;
    }
    const pa = lcSortValue(a, 'product', linked), pb = lcSortValue(b, 'product', linked);
    if (pa !== pb) return pa < pb ? -1 : 1;
    return lcReleaseOrder(a) - lcReleaseOrder(b);
  });
  return { rels, scope, linked };
}

function renderLifecycleView() {
  const tbody = document.getElementById('lc-table-body');
  if (!tbody) return;
  if (!LC || !lifecycleData) {
    tbody.innerHTML = '<tr><td colspan="12" class="empty-state"><p>수명주기 데이터(data/lifecycle.json)를 불러오지 못했습니다.</p></td></tr>';
    return;
  }
  const { rels, scope, linked } = lcVisibleReleases();
  const counts = lcCounts(scope);
  const scopeText = LC_VIEW.linked ? 'CVE에 연결된 릴리스' : '추적 중인 전체 릴리스';

  const meta = document.getElementById('lc-meta');
  if (meta) {
    meta.textContent = `데이터: endoflife.date API v1 · 생성 ${lcFetched(lifecycleData.generated_at)} · 제품 ${
      Object.keys(lifecycleData.products).length}개 · 릴리스 ${lifecycleData.releases.length}개 · 상태 기준일 ${lcToday} · 숫자는 모두 릴리스(사이클) 수이며 CVE 수가 아닙니다`;
  }
  const kpis = document.getElementById('lc-kpis');
  if (kpis) {
    kpis.innerHTML = LC_STAT_ORDER.map(s => `<div class="kpi lc-kpi lc-kpi-${s}" title="${escapeHtml(LC_STATUS_TEXT[s])}">
      <div class="kpi-label"><i class="lc-dot lc-${s}"></i>${LC.SHORT[s]}</div>
      <div class="kpi-value">${counts[s].toLocaleString()}</div>
      <div class="kpi-sub">${scopeText}</div></div>`).join('');
  }
  const soon = document.getElementById('lc-soon');
  if (soon) {
    soon.innerHTML = LC_WINDOWS.map(n => {
      const c = scope.filter(rel => LC.eolWithin(rel, '<', n, lcToday)).length;
      return `<div class="lc-soon-tile" title="EOL 날짜가 오늘 이후 ${n}일 미만 남은 릴리스 — 검색 문법 eol:<${n}d"><span>EOL까지 ${n}일 미만</span><b>${c.toLocaleString()}</b><small>${scopeText} 기준</small></div>`;
    }).join('');
  }

  tbody.innerHTML = rels.length ? rels.map(rel => {
    const m = lcMeta(rel.product_slug) || {};
    const labels = m.labels || {};
    const status = lcStatus(rel);
    const phase = LC.phaseLabel(rel, m, lcToday);
    const n = linked.get(rel) || 0;
    return `<tr class="lc-cat-row">
      <td class="lc-muted">${escapeHtml(m.vendor || '-')}</td>
      <td><b>${escapeHtml(m.label || rel.product_slug)}</b></td>
      <td><b>${escapeHtml(rel.cycle)}</b>${rel.cycle_label && rel.cycle_label !== rel.cycle ? `<span class="lc-cycle-label">${escapeHtml(rel.cycle_label)}</span>` : ''}</td>
      <td>${lcDateCell(rel.release_date)}</td>
      <td>${labels.eoas ? lcDateCell(rel.support_end, rel.support_ended, '날짜 미정 — upstream: 아직 끝나지 않음', '날짜 미상 — upstream: 끝남') : lcNa('upstream 에 별도 단계 없음')}</td>
      <td>${lcDateCell(rel.security_support_end)}</td>
      <td>${labels.eoes ? lcDateCell(rel.extended_support_end, rel.extended_support_ended, '날짜 미정 — upstream: 진행 중', '날짜 미상 — upstream: 끝남') : lcNa('upstream 에 확장 지원 단계 없음')}</td>
      <td>${lcDateCell(rel.eol_date, rel.eol_reached, '날짜 미정 — upstream: 아직 EOL 아님', '날짜 미상 — upstream: EOL')}</td>
      <td>${lcBadge(status, null, `${LC_STATUS_TEXT[status]}${phase ? ` · upstream 단계: ${phase}` : ''}`)}</td>
      <td>${rel.latest_version ? `<code>${escapeHtml(rel.latest_version)}</code>` : lcNa()}</td>
      <td class="lc-num">${n ? n.toLocaleString() : '<span class="lc-na">0</span>'}</td>
      <td>${lcLink(m.source_url, 'endoflife.date')}${m.original_source_url ? ` ${lcLink(m.original_source_url, '원출처')}` : ''}</td>
    </tr>`;
  }).join('') : '<tr><td colspan="12" class="empty-state"><p>조건에 맞는 릴리스가 없습니다.</p></td></tr>';

  const count = document.getElementById('lc-count');
  if (count) count.textContent = `${rels.length.toLocaleString()}개 릴리스 표시 · ${scopeText} ${scope.length.toLocaleString()}개 중`;
  const un = document.getElementById('lc-unavailable');
  const unavailable = lifecycleData.unavailable || [];
  if (un) {
    un.hidden = !unavailable.length;
    un.innerHTML = unavailable.length
      ? `<b>endoflife.date 에 없는 추적 요청 제품</b> — ${unavailable.map(u => `${escapeHtml(u.name || u.slug)}${u.vendor ? ` (${escapeHtml(u.vendor)})` : ''}`).join(', ')}. 수명주기 값을 만들지 않으며, 이 제품이 영향 제품인 CVE 는 UNKNOWN 으로 표시합니다.`
      : '';
  }
  document.querySelectorAll('th[data-lcsort]').forEach(th => {
    th.classList.remove('sort-asc', 'sort-desc');
    if (th.dataset.lcsort === LC_VIEW.sort) th.classList.add(LC_VIEW.dir === -1 ? 'sort-desc' : 'sort-asc');
  });
}

function switchView(view) {
  const lifecycle = view === 'lifecycle';
  const cveView = document.getElementById('view-cve');
  const lcView = document.getElementById('view-lifecycle');
  if (!cveView || !lcView) return;
  cveView.hidden = lifecycle;
  lcView.hidden = !lifecycle;
  document.querySelectorAll('.view-tab').forEach(btn => {
    const on = btn.dataset.view === view;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', String(on));
  });
  if (lifecycle) renderLifecycleView();
  try {
    const u = new URL(window.location.href);
    if (lifecycle) u.searchParams.set('view', 'lifecycle'); else u.searchParams.delete('view');
    history.replaceState(null, '', u);
  } catch (e) { /* URL 조작 실패는 무시 — 화면 전환 자체는 된다 */ }
  window.scrollTo({ top: 0 });
}

function initLifecycleView() {
  document.querySelectorAll('[data-view]').forEach(el =>
    el.addEventListener('click', () => switchView(el.dataset.view)));
  const search = document.getElementById('lc-search');
  if (search) {
    let timer;
    search.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => { LC_VIEW.search = search.value; renderLifecycleView(); }, 200);
    });
  }
  document.querySelectorAll('#lc-status-seg .seg-btn').forEach(btn => btn.addEventListener('click', () => {
    LC_VIEW.status = btn.dataset.status || '';
    document.querySelectorAll('#lc-status-seg .seg-btn').forEach(b => b.classList.toggle('active', b === btn));
    renderLifecycleView();
  }));
  document.getElementById('lc-window')?.addEventListener('change', e => { LC_VIEW.window = e.target.value; renderLifecycleView(); });
  document.getElementById('lc-linked')?.addEventListener('change', e => { LC_VIEW.linked = e.target.checked; renderLifecycleView(); });
  document.querySelectorAll('th[data-lcsort]').forEach(th => th.addEventListener('click', () => {
    const key = th.dataset.lcsort;
    if (LC_VIEW.sort === key) LC_VIEW.dir *= -1;
    else { LC_VIEW.sort = key; LC_VIEW.dir = key === 'cves' || key === 'release' ? -1 : 1; }
    renderLifecycleView();
  }));
  setTimeout(renderLifecycleStrip, 0);
  let view = null;
  try { view = new URL(window.location.href).searchParams.get('view'); } catch (e) { view = null; }
  if (view === 'lifecycle') switchView('lifecycle');
}
