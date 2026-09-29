/* 제품 수명주기 — CVE 상세의 수명주기 표(추적 제품 · data/lifecycle.json)와 '제품 수명주기' 화면(endoflife.date 전체 목록).
   수명주기는 CVE 가 아니라 제품 버전의 상태다. 날짜·단계명은 endoflife.date 값 그대로, 없으면 '-'. */

const LC_STATUS_TEXT = {
  ACTIVE: 'ACTIVE: 제조사의 기본 지원 기간',
  SECURITY_SUPPORT: 'SECURITY: 제조사가 보안 지원으로 밝힌 기간',
  EXTENDED_SUPPORT: 'EXTENDED: EOL 뒤에 제조사가 제공하는 확장 지원(유료 포함)',
  EOL: 'EOL: 제조사 지원 종료',
  UNKNOWN: 'UNKNOWN: 데이터가 없거나, 제조사 단계 이름으로 상태를 정할 수 없음',
};
const LC_STAT_ORDER = ['ACTIVE', 'SECURITY_SUPPORT', 'EXTENDED_SUPPORT', 'EOL', 'UNKNOWN'];
const LC_ROWS_SHOWN = 6;
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
    <td data-label="버전"><b>${escapeHtml(rel.cycle)}</b><span class="lc-cycle-label">${sub}</span></td>
    <td data-label="상태">${lcBadge(status, null, title)}</td>
    <td data-label="출시">${lcDateCell(rel.release_date)}</td>
    <td data-label="기본 지원 종료">${labels.eoas ? lcDateCell(rel.support_end, rel.support_ended, '날짜 미정 (제조사: 아직 끝나지 않음)', '날짜 미확인 (제조사: 끝남)') : lcNa('제조사 일정에 이 단계가 없음')}</td>
    <td data-label="보안 지원 종료">${lcDateCell(rel.security_support_end)}</td>
    <td data-label="확장 지원 종료">${labels.eoes ? lcDateCell(rel.extended_support_end, rel.extended_support_ended, '날짜 미정 (제조사: 진행 중)', '날짜 미확인 (제조사: 끝남)') : lcNa('제조사 일정에 확장 지원이 없음')}</td>
    <td data-label="EOL">${lcDateCell(rel.eol_date, rel.eol_reached, '날짜 미정 (제조사: 아직 EOL 아님)', '날짜 미확인 (제조사: EOL)')}</td>
    <td class="lc-tl-cell" data-label="타임라인">${lcTimeline(rel, axis)}</td>
  </tr>`;
}

function lcPhaseNames(meta) {
  const l = (meta && meta.labels) || {};
  const parts = [];
  if (l.eoas) parts.push(`기본 지원 종료 = '${l.eoas}' 단계의 끝`);
  if (l.eol) parts.push(`EOL = '${l.eol}' 단계의 끝`);
  if (l.eoes) parts.push(`확장 지원 종료 = '${l.eoes}' 단계의 끝`);
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
    ? `<button type="button" class="lc-toggle" onclick="lcToggleRows(this)" data-more="${rels.length - LC_ROWS_SHOWN}">버전 ${rels.length - LC_ROWS_SHOWN}개 더 보기</button>` : '';
  return `<div class="lc-group">
    <div class="lc-group-head">
      <b class="lc-product">${escapeHtml(meta.label || slug)}</b>
      ${meta.vendor ? `<span class="lc-vendor">${escapeHtml(meta.vendor)}</span>` : ''}
      <span class="lc-sum">${summary}</span>
    </div>
    <div class="lc-group-meta">연결 기준: ${vias.join(' · ')}${fixedOnly ? ' · OSV 수정 버전으로 연결 (수정이 없는 릴리스는 빠질 수 있음)' : ''}</div>
    <div class="lc-table-wrap"><table class="lc-table">
      <thead><tr><th>버전 · 최신</th><th>상태</th><th>출시</th><th>기본 지원 종료</th><th>보안 지원 종료</th><th>확장 지원 종료</th><th>EOL</th>
        <th class="lc-tl-head">${axis ? `<span>${axis.from}</span><span>${axis.to}</span>` : '타임라인'}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    ${more}
    <div class="lc-src">${escapeHtml(lcPhaseNames(meta))}${lcPhaseNames(meta) ? '<br>' : ''}출처: ${
      lcLink(meta.source_url, 'endoflife.date')}${isSafeUrl(meta.original_source_url) ? ` · 원출처 정책: ${lcLink(meta.original_source_url, lcHost(meta.original_source_url))}` : ''} · 수집 ${escapeHtml(lcFetched(meta.fetched_at))}</div>
  </div>`;
}

function lcToggleRows(btn) {
  const group = btn.closest('.lc-group, .lc-detail');
  if (!group) return;
  const rows = group.querySelectorAll('tr.lc-extra');
  const open = [...rows].some(r => r.hidden);
  rows.forEach(r => { r.hidden = !open; });
  btn.textContent = open ? '접기' : `${btn.dataset.kind || '버전'} ${btn.dataset.more}개 더 보기`;
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

/* ---------- 제품 수명주기 화면 — endoflife.date 전체 목록(data/lifecycle_catalog.json) ----------
   분류(평소 접힘) → 제품 이름 격자 → 누른 제품의 버전 표(그 줄 바로 아래). CVE 와의 연결은 싣지 않는다(CVE 상세에만).
   목록은 이 화면을 처음 열 때 한 번 받고, CVE 데이터(cves.json)를 기다리지 않는다. 상태는 lifecycle.js 로 오늘 기준 계산. */

// 분류 순서 — 보안 점검에서 자주 찾는 순서. 여기 없는 분류가 생기면 뒤에 upstream 이름 그대로 붙인다.
const LC_CATEGORIES = [
  ['os', '운영체제'], ['server-app', '서버 애플리케이션'], ['database', '데이터베이스'], ['lang', '프로그래밍 언어'],
  ['framework', '프레임워크'], ['app', '애플리케이션'], ['service', '클라우드 서비스'], ['device', '기기'], ['standard', '표준'],
];
const LC_SOON_DAYS = 90;
const LC_LIVE_SHOWN = 10;
const LC_PAGE = { q: '', soon: false, open: new Set(), product: null, auto: null };
const lcCatalog = { state: 'idle', data: null, promise: null, today: '', products: [], bySlug: new Map() };
const lcByName = (a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }) || (a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0);

function setLifecycleCatalog(json) {
  const ok = !!(LC && json && json.schema === 1 && json.products && typeof json.products === 'object' && Array.isArray(json.releases));
  lcCatalog.data = ok ? json : null;
  lcCatalog.state = ok ? 'ready' : 'error';
  lcCatalog.today = '';
  lcCatalog.products = [];
  lcCatalog.bySlug = new Map();
}

function loadLifecycleCatalog() {
  if (lcCatalog.promise) return lcCatalog.promise;
  if (typeof fetch !== 'function') { setLifecycleCatalog(null); return Promise.resolve(false); }
  lcCatalog.state = 'loading';
  lcCatalog.promise = fetch('data/lifecycle_catalog.json')
    .then(r => (r.ok ? r.json() : null)).catch(() => null)
    .then(json => {
      setLifecycleCatalog(json);
      if (lcCatalog.state === 'error') lcCatalog.promise = null; // '다시 불러오기'로 다시 받을 수 있게
      if (currentView === 'lifecycle') renderLifecycleView();
      return lcCatalog.state === 'ready';
    });
  return lcCatalog.promise;
}

// 제품마다 버전 · 상태 · 90일 안에 EOL 인 버전(가까운 순) — 기준일(lcToday)이 바뀌면 다시 센다.
function lcIndex() {
  if (lcCatalog.state !== 'ready') return null;
  if (lcCatalog.today === lcToday) return lcCatalog;
  const map = new Map(Object.entries(lcCatalog.data.products).map(([slug, meta]) =>
    [slug, { slug, meta: meta || {}, name: String((meta && meta.label) || slug), rels: [] }]));
  for (const rel of lcCatalog.data.releases) {
    const p = rel && map.get(rel.product_slug);
    if (p) p.rels.push(rel);
  }
  for (const p of map.values()) {
    p.status = p.rels.map(rel => LC.statusOf(rel, p.meta, lcToday));
    p.soon = p.rels.filter(rel => LC.eolWithin(rel, '<=', LC_SOON_DAYS, lcToday))
      .map(rel => ({ rel, days: LC.daysUntil(rel.eol_date, lcToday) })).sort((a, b) => a.days - b.days);
    p.allEol = p.status.length > 0 && p.status.every(s => s === 'EOL');
  }
  lcCatalog.products = [...map.values()].filter(p => p.rels.length).sort(lcByName);
  lcCatalog.bySlug = map;
  lcCatalog.today = lcToday;
  return lcCatalog;
}

function lcCategoryList(products) {
  const known = new Map(LC_CATEGORIES);
  const extra = [...new Set(products.map(p => p.meta.category).filter(c => c && !known.has(c)))].sort();
  return [...LC_CATEGORIES, ...extra.map(c => [c, c])];
}

/* ---------- 검색: 제품 이름 · 별칭 · 제조사 태그, 그리고 버전(사이클 · 라벨 · 코드명) ---------- */

function lcRelMatch(rel, w) {
  const c = String(rel.cycle).toLowerCase();
  if (c === w || c.startsWith(`${w}.`) || c.startsWith(`${w}-`)) return true;
  if (/^[\d.]+$/.test(w)) return false; // 숫자는 사이클 앞부분만 (22 → 22.04 · 22.10)
  return [rel.cycle_label, rel.codename].some(x => x && String(x).toLowerCase().includes(w));
}

// 단어마다 제품 이름 → 별칭 → 태그(통째로 같을 때만) → 버전 순으로 본다. 하나라도 어디에도 없으면 제외.
// 태그를 통째로 비교하는 이유: 'java' 가 'java-runtime' 태그가 붙은 서버 제품 100여 개에 걸린다(실측).
// 숫자만 쓴 단어(22.04 · 2019 · 8)는 버전으로만 본다 — '8' 이 k8s · 'Log4j' 같은 이름에 걸리지 않게.
function lcMatch(p, words) {
  let via = null;
  const hits = new Set();
  for (const w of words) {
    if (!/^[\d.]+$/.test(w)) {
      if (`${p.name} ${p.slug}`.toLowerCase().includes(w)) continue;
      const alias = (p.meta.aliases || []).find(a => String(a).toLowerCase().includes(w));
      if (alias) { via = via || `별칭 ${alias}`; continue; }
      const tag = (p.meta.tags || []).find(t => String(t).toLowerCase() === w);
      if (tag) { via = via || `태그 ${tag}`; continue; }
    }
    const rels = p.rels.filter(rel => lcRelMatch(rel, w));
    if (!rels.length) return null;
    rels.forEach(rel => hits.add(rel.cycle));
  }
  return { via, hits };
}

function lcMark(text, words) {
  const s = String(text);
  for (const w of words) {
    const i = s.toLowerCase().indexOf(w);
    if (i >= 0) return `${escapeHtml(s.slice(0, i))}<mark>${escapeHtml(s.slice(i, i + w.length))}</mark>${escapeHtml(s.slice(i + w.length))}`;
  }
  return escapeHtml(s);
}

/* ---------- 제품 칸 · 버전 표 ---------- */

function lcPickHtml(p, m, words) {
  const open = LC_PAGE.product === p.slug;
  let sub = '';
  if (LC_PAGE.soon && p.soon.length) {
    const first = p.soon[0].rel;
    sub = `${escapeHtml(first.cycle_label || first.cycle)} · ${escapeHtml(first.eol_date)}${p.soon.length > 1 ? ` 외 ${p.soon.length - 1}` : ''}`;
  } else if (m && m.hits.size) {
    const hits = [...m.hits];
    sub = `버전 ${escapeHtml(hits.slice(0, 3).join(', '))}${hits.length > 3 ? ` 외 ${hits.length - 3}` : ''}`;
  } else if (m && m.via) {
    sub = escapeHtml(m.via);
  }
  const near = p.soon[0];
  const chip = near
    ? `<span class="lc-dday">D-${near.days}</span>`
    : p.allEol ? '<span class="lc-gone">전체 EOL</span>' : '';
  const tip = near
    ? `${p.name} — 90일 안에 EOL: ${p.soon.map(s => `${s.rel.cycle} ${s.rel.eol_date} (D-${s.days})`).join(', ')}`
    : p.allEol ? `${p.name} — 모든 버전이 EOL` : '';
  return `<button type="button" class="lc-pick" data-slug="${escapeHtml(p.slug)}"${tip ? ` title="${escapeHtml(tip)}"` : ''} aria-expanded="${open}"${
    open ? ` aria-controls="lc-d-${escapeHtml(p.slug)}"` : ''}><span class="lc-pick-main"><span class="lc-pick-name">${
    words.length ? lcMark(p.name, words) : escapeHtml(p.name)}</span>${sub ? `<span class="lc-pick-sub">${sub}</span>` : ''}</span>${chip}</button>`;
}

function lcReleaseRow(p, rel, status, hidden, hit, cols) {
  const phase = LC.phaseLabel(rel, p.meta, lcToday);
  const days = LC.eolWithin(rel, '<=', LC_SOON_DAYS, lcToday) ? LC.daysUntil(rel.eol_date, lcToday) : null;
  // 라벨이 버전으로 시작하면 겹치는 앞부분은 뺀다 (24.04 'Noble Numbat' (LTS) → 'Noble Numbat' (LTS))
  const raw = rel.cycle_label ? String(rel.cycle_label) : '';
  const label = raw.startsWith(`${rel.cycle} `) ? raw.slice(String(rel.cycle).length + 1) : raw;
  const lts = rel.lts && !/lts/i.test(label) ? '<span class="lc-lts">LTS</span>' : '';
  const dday = days !== null ? `<span class="lc-dday" title="EOL까지 ${days}일">D-${days}</span>` : '';
  const cls = [hidden ? 'lc-extra' : '', hit ? 'is-hit' : '', days !== null ? 'is-soon' : ''].filter(Boolean).join(' ');
  const cells = [
    ['버전', `<b>${escapeHtml(rel.cycle)}</b>${lts}${label ? `<span class="lc-cycle-label">${escapeHtml(label)}</span>` : ''}`],
    ['상태', `${lcBadge(status, null, `${LC_STATUS_TEXT[status]}${phase ? ` · 제조사 단계: ${phase}` : ''}`)}${
      status === 'UNKNOWN' && phase ? `<span class="lc-phase">제조사 단계: ${escapeHtml(phase)}</span>` : ''}`],
    ['출시', lcDateCell(rel.release_date)],
  ];
  if (cols.eoas) {
    cells.push(['기본 지원 종료', lcDateCell(rel.support_end, rel.support_ended, '날짜 미정 (제조사: 아직 끝나지 않음)', '날짜 미확인 (제조사: 끝남)')]);
  }
  cells.push(['EOL', `${lcDateCell(rel.eol_date, rel.eol_reached, '날짜 미정 (제조사: 아직 EOL 아님)', '날짜 미확인 (제조사: EOL)')}${dday}`, 'lc-eol']);
  if (cols.eoes) {
    cells.push(['확장 지원 종료', lcDateCell(rel.extended_support_end, rel.extended_support_ended, '날짜 미정 (제조사: 진행 중)', '날짜 미확인 (제조사: 끝남)')]);
  }
  cells.push(['최신 버전', rel.latest_version
    ? `<span class="lc-latest">${escapeHtml(rel.latest_version)}${rel.latest_release_date ? `<small>${escapeHtml(rel.latest_release_date)}</small>` : ''}</span>`
    : lcNa()]);
  // 좁은 화면: 날짜 칸들 대신 한 줄 요약(표 칸은 CSS 로 숨긴다)
  const sum = [['출시', rel.release_date]];
  if (cols.eoas) sum.push(['기본 지원 종료', rel.support_end]);
  sum.push(['EOL', rel.eol_date, dday]);
  if (cols.eoes) sum.push(['확장 지원 종료', rel.extended_support_end]);
  sum.push(['최신', rel.latest_version]);
  const msum = sum.map(([k, v, extra]) => `<span${extra ? ' class="is-soon"' : ''}><i>${k}</i> ${v ? escapeHtml(v) : '-'}${extra || ''}</span>`).join('');
  return `<tr${cls ? ` class="${cls}"` : ''}${hidden ? ' hidden' : ''}>${
    cells.map(([k, html, c]) => `<td data-label="${k}"${c ? ` class="${c}"` : ''}>${html}</td>`).join('')}<td class="lc-msum">${msum}</td></tr>`;
}

// 지원 중인 버전 먼저(최대 LC_LIVE_SHOWN 개) — 없으면 가장 최근 버전 하나. 검색에 걸린 버전은 늘 보인다. 나머지는 '더 보기'.
function lcShownReleases(p, hits) {
  const live = p.rels.filter((rel, i) => p.status[i] !== 'EOL');
  const shown = new Set(live.slice(0, LC_LIVE_SHOWN));
  if (!shown.size && p.rels.length) shown.add(p.rels[0]);
  p.rels.forEach(rel => { if (hits.has(rel.cycle)) shown.add(rel); });
  return shown;
}

function lcDetailHtml(p, m) {
  const labels = p.meta.labels || {};
  const cols = { eoas: !!labels.eoas, eoes: !!labels.eoes };
  const counts = {};
  p.status.forEach(s => { counts[s] = (counts[s] || 0) + 1; });
  const hits = (m && m.hits) || new Set();
  const shown = lcShownReleases(p, hits);
  const rest = p.rels.filter(rel => !shown.has(rel));
  const kind = rest.every(rel => p.status[p.rels.indexOf(rel)] === 'EOL') ? '지난 버전' : '버전';
  const rows = p.rels.map((rel, i) => lcReleaseRow(p, rel, p.status[i], !shown.has(rel), hits.has(rel.cycle), cols)).join('');
  const head = [['버전'], ['상태'], ['출시']];
  if (cols.eoas) head.push(['기본 지원 종료', `제조사의 '${labels.eoas}' 단계가 끝나는 날`]);
  head.push(['EOL', labels.eol ? `제조사의 '${labels.eol}' 단계가 끝나는 날. 이후 지원 없음` : '']);
  if (cols.eoes) head.push(['확장 지원 종료', `제조사의 '${labels.eoes}' 단계가 끝나는 날`]);
  head.push(['최신 버전']);
  const aliases = (p.meta.aliases || []).filter(a => a && String(a).toLowerCase() !== p.slug);
  const names = lcPhaseNames(p.meta);
  return `<div class="lc-detail" id="lc-d-${escapeHtml(p.slug)}" role="region" aria-label="${escapeHtml(p.name)} 버전별 지원 일정">
    <div class="lc-detail-head">
      <b class="lc-detail-name">${escapeHtml(p.name)}</b>
      <span class="lc-sum">${LC.DISPLAY_ORDER.filter(s => counts[s]).map(s => lcBadge(s, counts[s])).join('')}</span>
      <button type="button" class="lc-close" data-lc-close aria-label="${escapeHtml(p.name)} 버전 표 닫기">×</button>
    </div>
    ${aliases.length ? `<div class="lc-alias">별칭 ${aliases.map(a => escapeHtml(a)).join(' · ')}</div>` : ''}
    <div class="table-scroll"><table class="lc-rel">
      <thead><tr>${head.map(([h, t]) => `<th${t ? ` title="${escapeHtml(t)}"` : ''}>${h}</th>`).join('')}</tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    ${rest.length ? `<button type="button" class="lc-toggle" onclick="lcToggleRows(this)" data-more="${rest.length}" data-kind="${kind}">${kind} ${rest.length}개 더 보기</button>` : ''}
    <div class="lc-src">${escapeHtml(names)}${names ? '<br>' : ''}출처: ${lcLink(p.meta.source_url, 'endoflife.date')}${
      isSafeUrl(p.meta.original_source_url) ? ` · 원출처 정책: ${lcLink(p.meta.original_source_url, lcHost(p.meta.original_source_url))}` : ''} · 수집 ${
      escapeHtml(lcFetched(p.meta.fetched_at))}</div>
  </div>`;
}

/* ---------- 화면 ---------- */

function lcCategoryHtml({ cat, label, all, list }, words, filtering) {
  const open = filtering || LC_PAGE.open.has(cat);
  const soonN = all.filter(p => p.soon.length).length;
  const meta = !filtering
    ? `<span>제품 <b>${all.length}</b></span>${soonN ? `<span class="lc-hot" title="EOL 날짜가 90일 안에 오는 버전이 있는 제품">90일 안에 EOL <b>${soonN}</b></span>` : ''}`
    : `<span>${LC_PAGE.soon && !words.length ? '90일 안에 EOL' : '일치'} <b>${list.length}</b> / ${all.length}</span>`;
  const sel = open ? list.find(x => x.p.slug === LC_PAGE.product) : null;
  // 검색 · 90일 보기에서는 맞는 분류를 모두 펼쳐 두므로 머리글을 누를 수 없게 둔다.
  const inner = `<svg class="lc-chev" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>
        <span class="lc-cat-name">${escapeHtml(label)}</span><span class="lc-cat-meta">${meta}</span>`;
  const headHtml = filtering
    ? `<div class="lc-cat-head is-static">${inner}</div>`
    : `<button type="button" class="lc-cat-head" data-cat="${escapeHtml(cat)}" aria-expanded="${open}" aria-controls="lc-c-${escapeHtml(cat)}">${inner}</button>`;
  return `<section class="lc-cat" data-cat="${escapeHtml(cat)}">
      ${headHtml}
      <div class="lc-cat-body" id="lc-c-${escapeHtml(cat)}"${open ? '' : ' hidden'}>${open
        ? `<div class="lc-grid">${list.map(x => lcPickHtml(x.p, x.m, words)).join('')}${sel ? lcDetailHtml(sel.p, sel.m) : ''}</div>` : ''}</div>
    </section>`;
}

function renderLifecycleView() {
  const box = document.getElementById('lc-cats');
  if (!box) return;
  const count = document.getElementById('lc-count');
  const idx = lcIndex();
  if (!idx) {
    if (lcCatalog.state === 'idle') loadLifecycleCatalog();
    box.innerHTML = lcCatalog.state === 'error'
      ? `<p class="empty-state">제품 수명주기 목록(data/lifecycle_catalog.json)을 불러오지 못했습니다.
          <button type="button" class="lc-toggle" data-lc-retry>다시 불러오기</button></p>`
      : '<p class="empty-state">제품 수명주기 목록을 불러오는 중…</p>';
    if (count) count.textContent = '';
    return;
  }
  const words = LC_PAGE.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const filtering = words.length > 0 || LC_PAGE.soon;
  const cats = lcCategoryList(idx.products).map(([cat, label]) => {
    const all = idx.products.filter(p => p.meta.category === cat);
    let list = all.map(p => ({ p, m: words.length ? lcMatch(p, words) : null })).filter(x => !words.length || x.m);
    if (LC_PAGE.soon) list = list.filter(x => x.p.soon.length).sort((a, b) => a.p.soon[0].days - b.p.soon[0].days || lcByName(a.p, b.p));
    return { cat, label, all, list };
  }).filter(c => c.all.length && (!filtering || c.list.length));
  const found = cats.reduce((n, c) => n + c.list.length, 0);
  // 검색 결과가 제품 하나면 그 제품의 버전 표를 연다 — 같은 검색어에서는 한 번만(닫으면 다시 열지 않는다).
  const key = words.join(' ');
  if (!words.length) LC_PAGE.auto = null;
  else if (found === 1 && LC_PAGE.auto !== key) {
    LC_PAGE.product = cats.find(c => c.list.length).list[0].p.slug;
    LC_PAGE.auto = key;
  }
  box.innerHTML = cats.length
    ? cats.map(c => lcCategoryHtml(c, words, filtering)).join('')
    : '<p class="empty-state">찾는 제품이 없습니다. 제품 이름, 별칭(예: k8s), 버전(예: 22.04)으로 찾을 수 있습니다.</p>';
  lcPlaceDetails(box);

  const soonProducts = idx.products.filter(p => p.soon.length);
  const releases = idx.data.releases.length;
  const asof = document.getElementById('lc-asof');
  if (asof) {
    asof.innerHTML = `endoflife.date 제품 <b>${idx.products.length.toLocaleString()}</b>개 · 버전 <b>${releases.toLocaleString()}</b>개의 지원 일정 · 상태 기준일 ${escapeHtml(lcToday)}`;
  }
  const meta = document.getElementById('lc-meta');
  if (meta) meta.textContent = `endoflife.date API v1 · 매일 확인하고 바뀐 날만 새로 씁니다 · 마지막 변경 ${lcFetched(idx.data.generated_at)}`;
  const soonN = document.getElementById('lc-soon-n');
  if (soonN) soonN.textContent = soonProducts.length.toLocaleString();
  const soonBtn = document.getElementById('lc-soon');
  if (soonBtn) soonBtn.setAttribute('aria-pressed', String(LC_PAGE.soon));
  if (count) {
    const shownRels = cats.reduce((n, c) => n + c.list.reduce((k, x) => k + x.p.soon.length, 0), 0);
    count.innerHTML = !filtering ? ''
      : LC_PAGE.soon && !words.length
        ? `제품 <b>${found.toLocaleString()}</b>개 · 버전 <b>${shownRels.toLocaleString()}</b>개 · 기준일 ${escapeHtml(lcToday)}`
        : `제품 <b>${found.toLocaleString()}</b>개 · 분류 <b>${cats.length}</b>개`;
  }
}

// 고른 제품의 버전 표를 그 제품 칸이 있는 줄 바로 아래로 옮긴다 — 열 수는 화면 폭에 따라 다르므로 위치로 판단한다.
function lcPlaceDetails(root) {
  if (!root || typeof root.querySelectorAll !== 'function') return;
  root.querySelectorAll('.lc-grid').forEach(grid => {
    const panel = grid.querySelector('.lc-detail');
    const sel = grid.querySelector('.lc-pick[aria-expanded="true"]');
    if (!panel || !sel) return;
    grid.appendChild(panel);
    const cells = [...grid.querySelectorAll('.lc-pick')];
    let last = sel;
    for (const c of cells.slice(cells.indexOf(sel) + 1)) {
      if (c.offsetTop !== sel.offsetTop) break;
      last = c;
    }
    last.after(panel);
  });
}

// 다시 그린 뒤 누른 버튼으로 초점을 돌려 둔다(키보드로 쓰는 경우).
function lcRefocus(selector) {
  try {
    const el = document.querySelector(selector);
    if (el && typeof el.focus === 'function') el.focus({ preventScroll: true });
  } catch (e) { /* 선택자 오류는 무시 */ }
}

const lcSel = v => (typeof CSS !== 'undefined' && CSS.escape ? CSS.escape(v) : String(v).replace(/["\\]/g, '\\$&'));

function lcOnClick(e) {
  const t = e.target;
  if (!t || typeof t.closest !== 'function') return;
  if (t.closest('[data-lc-retry]')) {
    lcCatalog.state = 'idle';
    renderLifecycleView();
    return;
  }
  const head = t.closest('button.lc-cat-head');
  if (head) {
    const cat = head.dataset.cat;
    if (LC_PAGE.open.has(cat)) {
      LC_PAGE.open.delete(cat);
      const sel = LC_PAGE.product && lcCatalog.bySlug.get(LC_PAGE.product);
      if (sel && sel.meta.category === cat) LC_PAGE.product = null;
    } else {
      LC_PAGE.open.add(cat);
    }
    renderLifecycleView();
    lcRefocus(`button.lc-cat-head[data-cat="${lcSel(cat)}"]`);
    return;
  }
  if (t.closest('[data-lc-close]')) {
    const slug = LC_PAGE.product;
    LC_PAGE.product = null;
    renderLifecycleView();
    if (slug) lcRefocus(`.lc-pick[data-slug="${lcSel(slug)}"]`);
    return;
  }
  const pick = t.closest('.lc-pick');
  if (pick) {
    const slug = pick.dataset.slug;
    LC_PAGE.product = LC_PAGE.product === slug ? null : slug;
    renderLifecycleView();
    lcRefocus(`.lc-pick[data-slug="${lcSel(slug)}"]`);
  }
}

let lcBound = false;

// 화면을 열기 전(첫 로드)에 한 번 — CVE 데이터를 기다리지 않는다.
function initLifecycleView() {
  if (lcBound) return;
  const box = document.getElementById('lc-cats');
  const search = document.getElementById('lc-search');
  const soon = document.getElementById('lc-soon');
  if (!box || !search || !soon) return;
  lcBound = true;
  box.addEventListener('click', lcOnClick);
  let t;
  search.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(() => { LC_PAGE.q = search.value; LC_PAGE.product = null; renderLifecycleView(); }, 150);
  });
  search.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || !search.value) return;
    search.value = '';
    LC_PAGE.q = '';
    LC_PAGE.product = null;
    renderLifecycleView();
  });
  soon.addEventListener('click', () => {
    LC_PAGE.soon = !LC_PAGE.soon;
    LC_PAGE.product = null;
    renderLifecycleView();
  });
  let rt;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => lcPlaceDetails(box), 120); });
}
