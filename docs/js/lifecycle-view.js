/* 제품 수명주기 — CVE 상세의 수명주기 상세와 '제품 수명주기' 화면(제품 중심).
   수명주기는 CVE 가 아니라 제품 릴리스의 상태다. 날짜·단계명은 endoflife.date 값 그대로, 없으면 '-'. */

const LC_STATUS_TEXT = {
  ACTIVE: 'ACTIVE: 제조사의 기본 지원 기간',
  SECURITY_SUPPORT: 'SECURITY: 제조사가 보안 지원으로 밝힌 기간',
  EXTENDED_SUPPORT: 'EXTENDED: EOL 뒤에 제조사가 제공하는 확장 지원(유료 포함)',
  EOL: 'EOL: 제조사 지원 종료',
  UNKNOWN: 'UNKNOWN: 데이터가 없거나, 제조사 단계 이름으로 상태를 정할 수 없음',
};
const LC_STAT_ORDER = ['ACTIVE', 'SECURITY_SUPPORT', 'EXTENDED_SUPPORT', 'EOL', 'UNKNOWN'];
const LC_WINDOWS = [30, 90, 180];
const LC_ROWS_SHOWN = 6;
const LC_VIEW = { status: '', window: '', linked: false, search: '', sort: 'cves', vendor: '', product: '' };
let lcOrder = null;

const lcMeta = slug => (lifecycleData && lifecycleData.products[slug]) || null;
const lcStatus = rel => LC.statusOf(rel, lcMeta(rel.product_slug), lcToday);
const lcNa = title => `<span class="lc-na"${title ? ` title="${escapeHtml(title)}"` : ''}>-</span>`;
const lcKey = rel => `${rel.product_slug}|${rel.cycle}`;

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
  if (!lcOrder || lcOrder.data !== lifecycleData) {
    lcOrder = { data: lifecycleData, map: new Map((lifecycleData.releases || []).map((r, i) => [r, i])) };
  }
  return lcOrder.map.has(rel) ? lcOrder.map.get(rel) : 1e9;
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

/* ---------- CVE 상세: 영향 릴리스 · EOL 날짜 · 연결 방법 · 모름의 사유 ---------- */

function lcRow(rel, axis, extra) {
  const meta = lcMeta(rel.product_slug) || {};
  const labels = meta.labels || {};
  const status = lcStatus(rel);
  const phase = LC.phaseLabel(rel, meta, lcToday);
  const title = `${LC_STATUS_TEXT[status]}${phase ? ` · 제조사 단계: ${phase}` : ''}`;
  const sub = [rel.cycle_label && rel.cycle_label !== rel.cycle ? escapeHtml(rel.cycle_label) : '',
               `최신 ${rel.latest_version ? escapeHtml(rel.latest_version) : '-'}`].filter(Boolean).join(' · ');
  return `<tr${extra ? ' class="lc-extra" hidden' : ''}>
    <td data-label="사이클"><b>${escapeHtml(rel.cycle)}</b><span class="lc-cycle-label">${sub}</span></td>
    <td data-label="상태">${lcBadge(status, null, title)}</td>
    <td data-label="출시">${lcDateCell(rel.release_date)}</td>
    <td data-label="지원 종료">${labels.eoas ? lcDateCell(rel.support_end, rel.support_ended, '날짜 미정 (제조사: 아직 끝나지 않음)', '날짜 미확인 (제조사: 끝남)') : lcNa('제조사 일정에 이 단계가 없음')}</td>
    <td data-label="보안지원 종료">${lcDateCell(rel.security_support_end)}</td>
    <td data-label="확장지원 종료">${labels.eoes ? lcDateCell(rel.extended_support_end, rel.extended_support_ended, '날짜 미정 (제조사: 진행 중)', '날짜 미확인 (제조사: 끝남)') : lcNa('제조사 일정에 확장 지원이 없음')}</td>
    <td data-label="EOL">${lcDateCell(rel.eol_date, rel.eol_reached, '날짜 미정 (제조사: 아직 EOL 아님)', '날짜 미확인 (제조사: EOL)')}</td>
    <td class="lc-tl-cell" data-label="타임라인">${lcTimeline(rel, axis)}</td>
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
    `<span title="${escapeHtml([...keys].join('\n'))}">${escapeHtml(LC.VIA[via] || via)} · ${via === 'override' ? '수동 지정' : '자동 연결'}${keys.size ? ` (키 ${keys.size}개)` : ''}</span>`);
  const fixedOnly = entries.some(e => e.basis === 'fixed');
  const rows = rels.map((rel, i) => lcRow(rel, axis, i >= LC_ROWS_SHOWN)).join('');
  const more = rels.length > LC_ROWS_SHOWN
    ? `<button type="button" class="lc-toggle" onclick="lcToggleRows(this)" data-more="${rels.length - LC_ROWS_SHOWN}">릴리스 ${rels.length - LC_ROWS_SHOWN}개 더 보기</button>` : '';
  return `<div class="lc-group">
    <div class="lc-group-head">
      <b class="lc-product">${escapeHtml(meta.label || slug)}</b>
      ${meta.vendor ? `<span class="lc-vendor">${escapeHtml(meta.vendor)}</span>` : ''}
      <span class="lc-sum">${summary}</span>
    </div>
    <div class="lc-group-meta">연결 기준: ${vias.join(' · ')}${fixedOnly ? ' · OSV 수정 버전으로 연결 (수정이 없는 릴리스는 빠질 수 있음)' : ''}</div>
    <div class="lc-table-wrap"><table class="lc-table">
      <thead><tr><th>릴리스 · 최신</th><th>상태</th><th>출시</th><th>지원 종료</th><th>보안지원 종료</th><th>확장지원 종료</th><th>EOL</th>
        <th class="lc-tl-head">${axis ? `<span>${axis.from}</span><span>${axis.to}</span>` : '타임라인'}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    ${more}
    <div class="lc-src">${escapeHtml(lcPhaseNames(meta))}${lcPhaseNames(meta) ? '<br>' : ''}출처: ${
      lcLink(meta.source_url, 'endoflife.date')}${isSafeUrl(meta.original_source_url) ? ` · 원출처 정책: ${lcLink(meta.original_source_url, lcHost(meta.original_source_url))}` : ''} · 수집 ${escapeHtml(lcFetched(meta.fetched_at))}</div>
  </div>`;
}

function lcToggleRows(btn) {
  const group = btn.closest('.lc-group, .lc-prod');
  if (!group) return;
  const rows = group.querySelectorAll('tr.lc-extra');
  const open = [...rows].some(r => r.hidden);
  rows.forEach(r => { r.hidden = !open; });
  btn.textContent = open ? '접기' : `릴리스 ${btn.dataset.more}개 더 보기`;
}

function lcUnresolvedName(slug) {
  const meta = lcMeta(slug);
  if (meta) return meta.label || slug;
  const u = lifecycleMatcher && lifecycleMatcher.unavailable.get(slug);
  return (u && u.name) || slug;
}

// d: cve-detail.js 의 detailContext 결과 (ctx.reasons 로 '미확인'의 사유를 적는다). 상세에서는 접힌 칸 안에 들어가므로 제목은 없다.
function renderLifecycleSection(cve, d) {
  if (!LC) return '';
  if (!lifecycleData) {
    return '<p class="lc-empty">수명주기 데이터(data/lifecycle.json)를 불러오지 못해 영향 제품을 모두 UNKNOWN으로 둡니다.</p>';
  }
  const r = cveLifecycle(cve);
  const groups = new Map();
  for (const e of r.entries) {
    if (!groups.has(e.slug)) groups.set(e.slug, []);
    groups.get(e.slug).push(e);
  }
  const blocks = [...groups].map(([slug, entries]) => lcGroup(slug, entries)).join('');
  const unresolved = r.unresolved.map(u => `<div class="lc-unresolved">${lcBadge('UNKNOWN')}<b>${
    escapeHtml(lcUnresolvedName(u.slug))}</b> 사유: ${escapeHtml(LC.REASONS[u.reason] || u.reason || '판단 불가')}${
    lcMeta(u.slug) ? ` · ${lcLink(lcMeta(u.slug).source_url, 'endoflife.date')}` : ''}</div>`).join('');
  // 사이클이 이어진 제품이라도 버전을 못 읽은 항목이 더 있으면 따로 적는다 — 위 표 밖의 릴리스일 수 있다.
  const partial = (r.partial || []).map(u => `<div class="lc-unresolved lc-partial">${lcBadge('UNKNOWN')}<b>${
    escapeHtml(lcUnresolvedName(u.slug))}</b>의 다른 영향 항목 사유: ${escapeHtml(LC.REASONS[u.reason] || u.reason || '판단 불가')}.
    위 표에 없는 릴리스일 수 있어 EOL 여부는 정하지 않았습니다</div>`).join('');
  const untracked = r.untracked
    ? `<div class="lc-untracked">${lcBadge('UNKNOWN')} 그 밖의 영향 제품 ${r.untracked}개 사유: 수명주기를 추적하지 않는 제품 (endoflife.date에 연결 안 됨)</div>` : '';
  const reasons = d && d.ctx && d.ctx.states.EOL_AFFECTED === 'unknown' && (d.ctx.reasons.EOL_AFFECTED || []).length
    ? `<div class="lc-why"><b>EOL 여부: 미확인</b> ${d.ctx.reasons.EOL_AFFECTED.map(c => escapeHtml(CTX.REASON[c] || c)).join(' · ')}</div>` : '';
  const body = blocks || unresolved || untracked
    ? `${reasons}${blocks}${partial}${unresolved}${untracked}`
    : '<p class="lc-empty">영향 제품 정보가 없어 수명주기를 표시할 수 없습니다 (UNKNOWN).</p>';
  return `${blocks ? lcLegend() : ''}${body}
    <div class="lc-foot">날짜와 단계 이름은 endoflife.date 값을 그대로 옮기고, 없는 값은 '-'로 둡니다. 상태는 오늘(${escapeHtml(lcToday)}) 기준으로 계산합니다.
      릴리스는 영향 버전 문자열에서 읽을 수 있을 때만 연결합니다. 수동 지정은 data/lifecycle_aliases.json, 자동 연결은 CPE · 제품명 규칙입니다. 출처: endoflife.date (MIT · Copyright 2020 endoflife.date contributors)</div>`;
}

/* ---------- 제품 수명주기 화면 — 제품 중심 + 릴리스별 연결된 CVE ---------- */

function lcThreatStats() {
  if (dataReady && CTX && typeof liveAggregate === 'function') {
    const a = liveAggregate();
    return { releases: a.releases, products: a.products, live: true };
  }
  if (typeof precomputedUsable === 'function' && precomputedUsable()) {
    return { releases: contextData.stats.releases || {}, products: contextData.stats.products || {}, live: false };
  }
  return { releases: {}, products: {}, live: null };
}

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

const LC_SORTERS = {
  product: () => 0,
  eol: (a, b) => {
    const next = g => g.rels.map(r => r.eol_date).filter(dt => dt && dt >= lcToday).sort()[0] || null;
    const x = next(a), y = next(b);
    if (x === y) return 0;
    if (!x) return 1;
    if (!y) return -1;
    return x < y ? -1 : 1;
  },
  cves: (a, b) => (b.stats.cves || 0) - (a.stats.cves || 0),
  kev: (a, b) => (b.stats.kev || 0) - (a.stats.kev || 0),
  exploit: (a, b) => (b.stats.exploit || 0) - (a.stats.exploit || 0),
};

function lcVisible() {
  const th = lcThreatStats();
  let rels = (lifecycleData.releases || []).slice();
  // 범위를 좁히는 조건(벤더 · 제품 · CVE 연결) — 상태별 숫자도 이 범위로 센다.
  if (LC_VIEW.vendor) rels = rels.filter(r => String((lcMeta(r.product_slug) || {}).vendor || '') === LC_VIEW.vendor);
  if (LC_VIEW.product) rels = rels.filter(r => r.product_slug === LC_VIEW.product);
  if (LC_VIEW.linked) rels = rels.filter(r => (th.releases[lcKey(r)] || {}).cves);
  const scope = rels;
  if (LC_VIEW.status) rels = rels.filter(rel => lcStatus(rel) === LC_VIEW.status);
  if (LC_VIEW.window) rels = rels.filter(rel => LC.eolWithin(rel, '<', Number(LC_VIEW.window), lcToday));
  if (LC_VIEW.search.trim()) rels = rels.filter(rel => lcMatchesSearch(rel, LC_VIEW.search));
  rels.sort((a, b) => lcReleaseOrder(a) - lcReleaseOrder(b));
  const bySlug = new Map();
  for (const r of rels) {
    if (!bySlug.has(r.product_slug)) bySlug.set(r.product_slug, []);
    bySlug.get(r.product_slug).push(r);
  }
  const label = slug => String((lcMeta(slug) || {}).label || slug).toLowerCase();
  const groups = [...bySlug].map(([slug, list]) => ({ slug, rels: list, stats: th.products[slug] || {} }));
  const sorter = LC_SORTERS[LC_VIEW.sort] || LC_SORTERS.product;
  groups.sort((a, b) => sorter(a, b) || (label(a.slug) < label(b.slug) ? -1 : 1));
  return { groups, scope, th, count: rels.length };
}

function lcObservations(rel, th) {
  const t = th.releases[lcKey(rel)];
  if (!t) {
    return `<span class="lc-na" title="추적 중인 CVE의 영향 제품 가운데 이 릴리스로 연결된 것이 없습니다">연결된 CVE 없음</span>`;
  }
  const q = `release:${rel.product_slug}/${rel.cycle}`.toLowerCase();
  const items = [
    ['cves', t.cves, 'CVE', q, '이 릴리스에 연결된 CVE'],
    ['kev', t.kev, 'KEV', `${q} has:cisa-kev`, 'CISA KEV 등재'],
    ['exploit', t.exploit, '익스플로잇', `${q} has:exploit`, '공개 익스플로잇 (EDB · MSF · PoC)'],
    ['detection', t.detection, '탐지 룰', `${q} has:detection`, '공개 탐지 룰 · 점검 템플릿'],
  ];
  return items.map(([k, n, label, query, title]) => n
    ? `<button type="button" class="obs obs-${k}" data-query="${escapeHtml(query)}" title="${escapeHtml(title)} ${n}건. 누르면 목록 (${escapeHtml(query)})">${label} <b>${n}</b></button>`
    : `<span class="obs obs-zero" title="${escapeHtml(title)} 0건">${label} 0</span>`).join('');
}

function lcCatalogRow(rel, th, extra) {
  const meta = lcMeta(rel.product_slug) || {};
  const labels = meta.labels || {};
  const status = lcStatus(rel);
  const phase = LC.phaseLabel(rel, meta, lcToday);
  const sub = [rel.cycle_label && rel.cycle_label !== rel.cycle ? escapeHtml(rel.cycle_label) : '',
               `최신 ${rel.latest_version ? escapeHtml(rel.latest_version) : '-'}`].filter(Boolean).join(' · ');
  return `<tr class="lc-cat-row${extra ? ' lc-extra' : ''}"${extra ? ' hidden' : ''}>
    <td data-label="사이클"><b>${escapeHtml(rel.cycle)}</b><span class="lc-cycle-label">${sub}</span></td>
    <td data-label="상태">${lcBadge(status, null, `${LC_STATUS_TEXT[status]}${phase ? ` · 제조사 단계: ${phase}` : ''}`)}</td>
    <td data-label="출시">${lcDateCell(rel.release_date)}</td>
    <td data-label="지원 종료">${labels.eoas ? lcDateCell(rel.support_end, rel.support_ended, '날짜 미정 (제조사: 아직 끝나지 않음)', '날짜 미확인 (제조사: 끝남)') : lcNa('제조사 일정에 이 단계가 없음')}</td>
    <td data-label="보안지원 종료">${lcDateCell(rel.security_support_end)}</td>
    <td data-label="확장지원 종료">${labels.eoes ? lcDateCell(rel.extended_support_end, rel.extended_support_ended, '날짜 미정 (제조사: 진행 중)', '날짜 미확인 (제조사: 끝남)') : lcNa('제조사 일정에 확장 지원이 없음')}</td>
    <td data-label="EOL">${lcDateCell(rel.eol_date, rel.eol_reached, '날짜 미정 (제조사: 아직 EOL 아님)', '날짜 미확인 (제조사: EOL)')}</td>
    <td class="lc-obs" data-label="연결된 CVE">${lcObservations(rel, th)}</td>
  </tr>`;
}

function lcProductCard(group, th, showAll) {
  const { slug, rels, stats } = group;
  const meta = lcMeta(slug) || {};
  const counts = lcCounts(rels);
  const summary = LC.DISPLAY_ORDER.filter(s => counts[s]).map(s => lcBadge(s, counts[s])).join('');
  const totals = stats && stats.cves
    ? `<span class="lc-prod-obs" title="이 제품의 릴리스에 연결된 CVE 수 (한 CVE는 한 번만 셉니다)">
        CVE <b>${stats.cves}</b> · KEV <b>${stats.kev}</b> · 공개 익스플로잇 <b>${stats.exploit}</b> · 탐지 룰 <b>${stats.detection}</b></span>`
    : '<span class="lc-prod-obs lc-na">연결된 CVE 없음</span>';
  const rows = rels.map((rel, i) => lcCatalogRow(rel, th, !showAll && i >= LC_ROWS_SHOWN)).join('');
  const more = !showAll && rels.length > LC_ROWS_SHOWN
    ? `<button type="button" class="lc-toggle" onclick="lcToggleRows(this)" data-more="${rels.length - LC_ROWS_SHOWN}">릴리스 ${rels.length - LC_ROWS_SHOWN}개 더 보기</button>` : '';
  return `<article class="lc-prod" data-slug="${escapeHtml(slug)}">
    <header class="lc-prod-head">
      <div class="lc-prod-name"><b>${escapeHtml(meta.label || slug)}</b>${meta.vendor ? `<span class="lc-vendor">${escapeHtml(meta.vendor)}</span>` : ''}</div>
      <span class="lc-sum">${summary}</span>
      ${totals}
    </header>
    <div class="table-scroll"><table class="lc-catalog">
      <thead><tr><th>릴리스 · 최신</th><th>상태</th><th>출시</th><th title="제조사의 첫 지원 단계(예: Active Support)가 끝나는 날">지원 종료</th>
        <th title="제조사가 보안 지원으로 밝힌 기간이 끝나는 날. 따로 밝히지 않았으면 '-'">보안지원 종료</th>
        <th title="제조사가 제공하는 확장 지원(유료 포함)이 끝나는 날">확장지원 종료</th><th>EOL</th>
        <th title="추적 중인 CVE 가운데 이 릴리스에 연결된 것. 누르면 목록이 열립니다">연결된 CVE</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    ${more}
    <div class="lc-src">${escapeHtml(lcPhaseNames(meta))}${lcPhaseNames(meta) ? '<br>' : ''}출처: ${
      lcLink(meta.source_url, 'endoflife.date')}${isSafeUrl(meta.original_source_url) ? ` · 원출처 정책: ${lcLink(meta.original_source_url, lcHost(meta.original_source_url))}` : ''} · 수집 ${escapeHtml(lcFetched(meta.fetched_at))}</div>
  </article>`;
}

function renderLifecycleView() {
  const box = document.getElementById('lc-products');
  if (!box) return;
  if (!LC || !lifecycleData) {
    box.innerHTML = '<p class="empty-state">수명주기 데이터(data/lifecycle.json)를 불러오지 못했습니다.</p>';
    return;
  }
  const { groups, scope, th, count } = lcVisible();
  const counts = lcCounts(scope);
  const narrowed = [LC_VIEW.product ? (lcMeta(LC_VIEW.product) || {}).label || LC_VIEW.product : LC_VIEW.vendor].filter(Boolean).join('');
  const scopeText = `${narrowed ? `${narrowed} · ` : ''}${LC_VIEW.linked ? 'CVE에 연결된 릴리스' : '추적 중인 전체 릴리스'}`;
  const filtered = !!(LC_VIEW.status || LC_VIEW.window || LC_VIEW.search.trim());

  const meta = document.getElementById('lc-meta');
  if (meta) {
    meta.textContent = `endoflife.date API v1 · 생성 ${lcFetched(lifecycleData.generated_at)} · 제품 ${
      Object.keys(lifecycleData.products).length}개 · 릴리스 ${lifecycleData.releases.length}개 · 상태 기준일 ${lcToday}. 상태별 숫자와 EOL 임박 숫자는 릴리스 수이며 CVE 수가 아닙니다${
      th.live === false ? '. 연결된 CVE 수는 CI 사전 계산 값입니다' : ''}`;
  }
  const kpis = document.getElementById('lc-kpis');
  if (kpis) {
    kpis.innerHTML = LC_STAT_ORDER.map(s => `<div class="kpi lc-kpi lc-kpi-${s}" title="${escapeHtml(LC_STATUS_TEXT[s])}">
      <div class="kpi-label"><span class="lc-dot lc-${s}"></span>${LC.SHORT[s]}</div>
      <div class="kpi-value">${counts[s].toLocaleString()}</div>
      <div class="kpi-sub">${scopeText}</div></div>`).join('');
  }
  const soon = document.getElementById('lc-soon');
  if (soon) {
    soon.innerHTML = LC_WINDOWS.map(n => {
      const c = scope.filter(rel => LC.eolWithin(rel, '<', n, lcToday)).length;
      return `<div class="lc-soon-tile" title="EOL이 오늘부터 ${n}일 안에 오는 릴리스 (검색어 eol:<${n}d)"><span>EOL까지 ${n}일 미만</span><b>${c.toLocaleString()}</b><small>${scopeText} 기준</small></div>`;
    }).join('');
  }

  box.innerHTML = groups.length
    ? groups.map(g => lcProductCard(g, th, filtered)).join('')
    : '<p class="empty-state">조건에 맞는 릴리스가 없습니다.</p>';
  box.querySelectorAll('.obs[data-query]').forEach(b => b.addEventListener('click', () => goToQuery(b.dataset.query)));

  const cnt = document.getElementById('lc-count');
  if (cnt) cnt.textContent = `제품 ${groups.length}개 · 릴리스 ${count.toLocaleString()}개 표시 · ${scopeText} ${scope.length.toLocaleString()}개 중`;
  const un = document.getElementById('lc-unavailable');
  const unavailable = lifecycleData.unavailable || [];
  if (un) {
    un.hidden = !unavailable.length;
    un.innerHTML = unavailable.length
      ? `<b>수명주기 데이터가 없는 제품</b>: ${unavailable.map(u => `${escapeHtml(u.name || u.slug)}${u.vendor ? ` (${escapeHtml(u.vendor)})` : ''}`).join(', ')}. endoflife.date에서 다루지 않아 UNKNOWN으로 둡니다.`
      : '';
  }
  document.querySelectorAll('#lc-status-seg .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.status === LC_VIEW.status));
}

let lcBound = false;

// 벤더 · 제품 고르기 — endoflife.date 제품 목록에서. 제품은 고른 벤더의 것만 보인다.
function lcFillFilters() {
  const vSel = document.getElementById('lc-vendor');
  const pSel = document.getElementById('lc-product');
  if (!lifecycleData || !vSel || !pSel) return;
  const products = Object.entries(lifecycleData.products || {});
  const vendors = [...new Set(products.map(([, m]) => String(m.vendor || '')).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  vSel.innerHTML = `<option value="">전체 벤더 (${vendors.length})</option>${vendors.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('')}`;
  vSel.value = LC_VIEW.vendor;
  lcFillProducts();
}

function lcFillProducts() {
  const pSel = document.getElementById('lc-product');
  if (!lifecycleData || !pSel) return;
  const list = Object.entries(lifecycleData.products || {})
    .filter(([, m]) => !LC_VIEW.vendor || String(m.vendor || '') === LC_VIEW.vendor)
    .map(([slug, m]) => [slug, m.label || slug]).sort((a, b) => a[1].localeCompare(b[1]));
  if (LC_VIEW.product && !list.some(([slug]) => slug === LC_VIEW.product)) LC_VIEW.product = '';
  pSel.innerHTML = `<option value="">전체 제품 (${list.length})</option>${list.map(([slug, label]) => `<option value="${escapeHtml(slug)}">${escapeHtml(label)}</option>`).join('')}`;
  pSel.value = LC_VIEW.product;
}

function initLifecycleView() {
  lcFillFilters();
  if (!lcBound) {
    lcBound = true;
    document.getElementById('lc-vendor')?.addEventListener('change', e => { LC_VIEW.vendor = e.target.value; lcFillProducts(); renderLifecycleView(); });
    document.getElementById('lc-product')?.addEventListener('change', e => { LC_VIEW.product = e.target.value; renderLifecycleView(); });
    const search = document.getElementById('lc-search');
    let t;
    search?.addEventListener('input', () => {
      clearTimeout(t);
      t = setTimeout(() => { LC_VIEW.search = search.value; renderLifecycleView(); }, 200);
    });
    document.querySelectorAll('#lc-status-seg .seg-btn').forEach(b => b.addEventListener('click', () => {
      LC_VIEW.status = b.dataset.status;
      renderLifecycleView();
    }));
    document.getElementById('lc-window')?.addEventListener('change', e => { LC_VIEW.window = e.target.value; renderLifecycleView(); });
    document.getElementById('lc-sort')?.addEventListener('change', e => { LC_VIEW.sort = e.target.value; renderLifecycleView(); });
    document.getElementById('lc-linked')?.addEventListener('change', e => { LC_VIEW.linked = e.target.checked; renderLifecycleView(); });
  }
  if (currentView === 'lifecycle') renderLifecycleView();
}
