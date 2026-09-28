/* 대시보드 — 서로 다른 출처의 사실이 겹치는 곳을 보고 목록으로 들어간다. 모든 숫자는 누르면 같은 조건의 목록이 열린다.
   여러 신호를 합친 위험 점수는 만들지 않는다. 전체 데이터(cves.json)가 오기 전에는 CI 사전 계산(cve-context.json)으로
   먼저 그리고, 오면 오늘 기준으로 다시 센다. 값의 정의는 뷰 모델(viewmodel.js) · 판정 규칙은 context.js 한 곳. */

let dashAggregate = null;

function aggregateDays() {
  return CTX ? CTX.trendDays(statsData && statsData.generated_at, 30) : [];
}

function liveAggregate() {
  const key = `${lcToday}|${allCves.length}|${(statsData && statsData.generated_at) || ''}|${ctxVersion}`;
  if (dashAggregate && dashAggregate.key === key) return dashAggregate.value;
  const items = allCves.map(cve => CTX.aggregateItem(cve, cveContext(cve), lifecycleData ? cveLifecycle(cve) : null));
  const value = CTX.aggregate(items, { days: aggregateDays() });
  dashAggregate = { key, value };
  return value;
}

function precomputedUsable() {
  if (!contextData || !contextData.stats || !CTX || !statsData || !statsData.cve) return false;
  return contextData.inputs && contextData.inputs.cves === `${statsData.generated_at || ''}|${statsData.cve.total || 0}`;
}

function dashSource() {
  if (!CTX) return null;
  if (dataReady && allCves.length) return { live: true, stats: liveAggregate(), asOf: lcToday };
  if (precomputedUsable()) return { live: false, stats: contextData.stats, asOf: contextData.as_of };
  return null;
}

const fmt = n => (Number(n) || 0).toLocaleString();
const pct = (n, d) => (d ? `${((n / d) * 100).toFixed(1)}%` : '–');

function renderDashboard() {
  const src = dashSource();
  renderDashMeta(src);
  renderKpis(src);
  renderOverview(src);
  renderCorrelations(src);
  renderRecent(src);
  renderMatrix(src);
}

function bindQueries(box) {
  box.querySelectorAll('[data-query]').forEach(b => b.addEventListener('click', () => goToQuery(b.dataset.query)));
}

function renderDashMeta(src) {
  const el = document.getElementById('dash-meta');
  if (!el) return;
  const gen = new Date((statsData && statsData.generated_at) || '');
  const when = isNaN(gen) ? '-' : gen.toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'short' });
  const how = !src ? '파생 계산 준비 중'
    : src.live ? `파생 계산: 브라우저 (${contextValid ? 'CI 매핑 사용' : 'CI 결과 없음·불일치 → 직접 매칭'})`
    : 'CI 사전 계산 값 — 전체 데이터를 받으면 다시 계산';
  el.innerHTML = `CVE 기준 <b>${escapeHtml(when)}</b> · 수명주기 기준일 <b>${escapeHtml(src ? src.asOf : '-')}</b> · ${escapeHtml(how)}`;
}

/* ---------- KPI — 6칸. 숫자 = 누르면 열리는 목록 건수 ---------- */

const KPI_ACCENT = { total: 'is-total', recent: 'is-recent', kev: 'is-exploit', weaponized: 'is-weapon', poc: 'is-weapon', ai: 'is-src' };

function renderKpis(src) {
  const box = document.getElementById('dash-kpis');
  if (!box || !VM) return;
  const s = (statsData && statsData.cve) || {};
  box.innerHTML = VM.kpis(src ? src.stats : null, statsData).map(k => {
    const value = k.id === 'stat-total' ? (s.total || allCves.length)
      : (() => { const n = kpiCount(k.id); return n !== null ? n : k.value; })();
    const sub = k.id === 'stat-24h' ? '<span class="kpi-sub" id="stat-24h-sub">알림을 보냈거나 상태가 바뀐 CVE — 신규 공개만이 아님</span>'
      : `<span class="kpi-sub">${escapeHtml(k.sub || '')}</span>`;
    const go = k.query ? `목록 <code>${escapeHtml(k.query)}</code> →` : '전체 목록 →';
    return `<button type="button" class="kpi kpi-link ${KPI_ACCENT[k.key] || ''}" data-query="${escapeHtml(k.query)}" title="${escapeHtml(k.title || '')}">
      <span class="kpi-label">${escapeHtml(k.label)}</span>
      <span class="kpi-value" id="${k.id}">${value === null || value === undefined ? '-' : fmt(value)}</span>
      ${sub}
      <span class="kpi-go">${go}</span>
    </button>`;
  }).join('');
  bindQueries(box);
}

/* ---------- Threat Overview — 최근 30일 CVE 공개일별 건수 (한 계열 막대, 칸마다 심각도 내역) ---------- */

let overviewModel = null;

function niceMax(n) {
  if (n <= 1) return 1;
  const p = 10 ** Math.floor(Math.log10(n));
  return [1, 2, 5, 10].map(m => m * p).find(v => v >= n);
}

function renderOverview(src) {
  const box = document.getElementById('dash-overview');
  if (!box) return;
  if (!src || !VM) { box.innerHTML = '<p class="dash-wait">데이터를 불러오는 중…</p>'; return; }
  const ov = VM.overview(src.stats);
  overviewModel = ov;
  if (!ov.days.length) { box.innerHTML = '<p class="dash-wait">일별 집계가 없습니다.</p>'; return; }
  const top = niceMax(ov.max);
  const peak = ov.days.reduce((a, d, i) => (ov.totals[i] > ov.totals[a] ? i : a), 0);
  const sevSum = k => ov.days.reduce((a, d) => a + (d[k] || 0), 0);
  const s = (statsData && statsData.cve) || {};
  const covered = typeof s.trend_covered === 'number' && s.total && s.trend_covered < s.total
    ? `<span>공개일 확인 ${fmt(s.trend_covered)}/${fmt(s.total)}건 기준</span>` : '';
  const md = iso => iso.slice(5).replace('-', '.');
  const bars = ov.days.map((d, i) => {
    const t = ov.totals[i];
    return `<div class="ov-col${t ? '' : ' is-empty'}" data-i="${i}"><div class="ov-bar" style="height:${(t / top * 100).toFixed(2)}%"></div></div>`;
  }).join('');
  const rows = ov.days.map((d, i) => `<tr><td>${escapeHtml(d.date)}</td><td><b>${fmt(ov.totals[i])}</b></td>${
    ['Critical', 'High', 'Medium', 'Low', 'None'].map(k => `<td>${fmt(d[k])}</td>`).join('')}</tr>`).reverse().join('');
  box.innerHTML = `
    <div class="ov-sum">
      <span><b>${fmt(ov.sum)}</b>건 · 30일 공개</span>
      <span><b>${fmt(sevSum('Critical'))}</b>Critical</span>
      <span><b>${fmt(sevSum('High'))}</b>High</span>
      <span>하루 최대 <b>${fmt(ov.totals[peak])}</b>(${escapeHtml(md(ov.days[peak].date))})</span>
      ${sevSum('None') ? `<span>점수 없음 ${fmt(sevSum('None'))}건 포함</span>` : ''}
      ${covered}
    </div>
    <div class="ov-chart" role="img" aria-label="최근 30일 CVE 공개일별 건수 막대 그래프 — 합계 ${fmt(ov.sum)}건, 하루 최대 ${fmt(ov.totals[peak])}건. 아래 '표로 보기'에 날짜별 숫자">
      <div class="ov-y" aria-hidden="true"><span style="top:0">${fmt(top)}</span><span style="top:50%">${fmt(top / 2)}</span><span style="top:100%">0</span></div>
      <div class="ov-plot">
        <div class="ov-grid" style="top:0"></div><div class="ov-grid" style="top:50%"></div>
        <div class="ov-bars">${bars}</div>
      </div>
      <div class="ov-x" aria-hidden="true"><span>${escapeHtml(md(ov.days[0].date))}</span><span>${escapeHtml(md(ov.days[Math.floor(ov.days.length / 2)].date))}</span><span>${escapeHtml(md(ov.days[ov.days.length - 1].date))}</span></div>
    </div>
    <details class="ov-table"><summary>표로 보기</summary>
      <div class="table-scroll"><table class="d-table"><thead><tr><th>공개일</th><th>합계</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>점수 없음</th></tr></thead><tbody>${rows}</tbody></table></div>
    </details>`;
  const barsEl = box.querySelector('.ov-bars');
  if (barsEl) {
    barsEl.addEventListener('pointermove', e => {
      const col = e.target.closest('.ov-col');
      if (col) showOverviewTip(col, e);
    });
    barsEl.addEventListener('pointerleave', hideVizTip);
  }
}

function vizTip() {
  let tip = document.getElementById('viz-tip');
  if (!tip) {
    tip = document.createElement('div');
    tip.id = 'viz-tip';
    tip.className = 'viz-tip';
    tip.hidden = true;
    document.body.appendChild(tip);
  }
  return tip;
}

function hideVizTip() {
  const tip = document.getElementById('viz-tip');
  if (tip) tip.hidden = true;
  document.querySelectorAll('.ov-col.is-hot').forEach(c => c.classList.remove('is-hot'));
}

function showOverviewTip(col, e) {
  const ov = overviewModel;
  const i = Number(col.dataset.i);
  if (!ov || !ov.days[i]) return;
  const d = ov.days[i];
  document.querySelectorAll('.ov-col.is-hot').forEach(c => c.classList.remove('is-hot'));
  col.classList.add('is-hot');
  const tip = vizTip();
  tip.innerHTML = `<div class="tip-head">${escapeHtml(d.date)} 공개 · <b>${fmt(ov.totals[i])}</b>건</div>${
    [['Critical', 'Critical'], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low'], ['None', '점수 없음']]
      .filter(([k]) => d[k]).map(([k, l]) => `<div class="tip-row"><span>${l}</span><b>${fmt(d[k])}</b></div>`).join('') || '<div class="tip-row"><span>없음</span></div>'}`;
  tip.hidden = false;
  const r = tip.getBoundingClientRect();
  const x = Math.min(window.innerWidth - r.width - 8, e.clientX + 14);
  const y = e.clientY - r.height - 12 < 8 ? e.clientY + 16 : e.clientY - r.height - 12;
  tip.style.left = `${Math.max(8, x)}px`;
  tip.style.top = `${y}px`;
}

/* ---------- Top Threat Correlations — 두 사실이 모두 확인된 CVE 수 ---------- */

const PART_GROUP = {
  CISA_KEV: 'exploit', EXPLOITATION_CONFIRMED: 'exploit', RANSOMWARE: 'exploit', PUBLIC_EXPLOIT: 'weapon',
  AUTOMATABLE: 'auto', EOL_AFFECTED: 'lifecycle', PATCH_AVAILABLE: 'defense', PUBLIC_DETECTION: 'defense',
  HIGH_EPSS: 'score', CRITICAL_CVSS: 'sev',
};

function partLabel(p) {
  const sig = CTX.SIGNAL[p.code];
  const label = p.negated && p.code === 'PATCH_AVAILABLE' ? '수정 기록 없음' : p.negated ? `${sig.short} 없음` : sig.short;
  return `<span class="corr-part g-${PART_GROUP[p.code] || 'src'}"><i></i>${escapeHtml(label)}</span>`;
}

function renderCorrelations(src) {
  const box = document.getElementById('dash-corr');
  if (!box) return;
  if (!src || !VM) { box.innerHTML = '<li class="dash-wait">데이터를 불러오는 중…</li>'; return; }
  const list = VM.correlations(src.stats);
  const max = Math.max(1, ...list.map(c => c.n));
  box.innerHTML = list.map(c => `<li><button type="button" class="corr-card${c.n ? '' : ' is-zero'}" data-query="${escapeHtml(c.query)}"
      title="${escapeHtml(c.label)} — 누르면 목록: ${escapeHtml(c.query)}">
    <span class="corr-parts">${partLabel(c.parts[0])}<em>×</em>${partLabel(c.parts[1])}</span>
    <span class="corr-n">${fmt(c.n)}</span>
    <span class="corr-track" aria-hidden="true"><span style="width:${(c.n / max * 100).toFixed(1)}%"></span></span>
    <span class="corr-label">${escapeHtml(c.label)}</span>
    <span class="corr-scope">${escapeHtml(c.scopeText)}${c.share !== null ? ` · ${pct(c.n, c.scope)}` : ''}</span>
  </button></li>`).join('');
  bindQueries(box);
}

/* ---------- Recent CVEs — 공개일 순 ---------- */

function renderRecent(src) {
  const box = document.getElementById('dash-recent');
  if (!box) return;
  let list = null;
  if (dataReady && allCves.length && CTX) list = CTX.recentOf(allCves, cveContext, 8);
  else if (precomputedUsable() && Array.isArray(contextData.recent)) list = contextData.recent;
  if (!list || !VM) { box.innerHTML = '<li class="dash-wait">데이터를 불러오는 중…</li>'; return; }
  const items = VM.recent(list, statsData && statsData.generated_at);
  box.innerHTML = items.map(r => `<li><button type="button" class="recent-item" data-cve="${escapeHtml(r.id)}" title="${escapeHtml(r.title)}">
    <span class="badge badge-sev sev-${escapeHtml(r.severity)}">${escapeHtml(r.severity)}</span>
    <span class="r-top"><span class="cve-id">${escapeHtml(r.id)}</span><span>${r.cvss ? `CVSS ${r.cvss.toFixed(1)}` : 'CVSS 모름'}</span><span>${escapeHtml(r.ago || r.published)}</span></span>
    <span class="r-title">${escapeHtml(r.title)}</span>
    ${r.signalLabels.length ? `<span class="r-sig">${r.signals.filter(k => k !== 'EXPLOITATION_CONFIRMED' || !r.signals.includes('CISA_KEV'))
      .map(k => `<span class="g-${PART_GROUP[k] || 'src'}"><i class="sig-dot"></i>${escapeHtml(CTX.SIGNAL[k].short)}</span>`).join('')}</span>` : ''}
  </button></li>`).join('') || '<li class="dash-wait">최근 공개된 추적 CVE 가 없습니다.</li>';
  box.querySelectorAll('[data-cve]').forEach(b => b.addEventListener('click', () => openCve(b.dataset.cve)));
}

/* ---------- 신호 동시 발생 행렬 + 관련 검색어 ---------- */

// 순차 램프 5단계 — 경계는 최댓값의 (k/5)² (작은 값이 한 칸에 몰리지 않게). 칸에는 실제 건수를 적는다.
function matrixBins(max) {
  const edges = [];
  for (let k = 1; k <= 5; k++) edges.push(Math.max(1, Math.ceil(max * (k / 5) ** 2)));
  return edges;
}
const binOf = (n, edges) => (n <= 0 ? 0 : edges.findIndex(e => n <= e) + 1 || 5);

function renderMatrix(src) {
  const box = document.getElementById('dash-matrix');
  const chips = document.getElementById('dash-rel-chips');
  if (!box) return;
  const mx = src && VM ? VM.matrix(src.stats) : null;
  if (!mx) { box.innerHTML = '<p class="dash-wait">데이터를 불러오는 중…</p>'; if (chips) chips.innerHTML = ''; return; }
  const edges = matrixBins(mx.max);
  const ax = mx.axes;
  // 줄 · 칸 머리에 그 신호 전체('있음') 건수 — 대각선 대신. 누르면 그 신호 전체 목록.
  const axisBtn = a => `<button type="button" class="mx-row" data-query="${escapeHtml(a.query)}"
      title="${escapeHtml(a.short)} 있음 전체 ${fmt(a.total)}건 — 누르면 목록: ${escapeHtml(a.query)}">${escapeHtml(a.short)}<small>${fmt(a.total)}</small></button>`;
  const head = `<tr><th></th>${ax.slice(1).map(a => `<th scope="col" title="${escapeHtml(CTX.SIGNAL[a.code].def)}">${axisBtn(a)}</th>`).join('')}</tr>`;
  const body = ax.slice(0, -1).map((a, i) => `<tr><th scope="row">${axisBtn(a)}</th>${
    ax.slice(1).map((b, jj) => {
      const j = jj + 1;
      if (j <= i) return '<td></td>';
      const c = mx.cells[`${i}|${j}`];
      const bin = binOf(c.n, edges);
      const label = `${a.short} × ${b.short}: 둘 다 있음 ${fmt(c.n)}건`;
      return c.n
        ? `<td><button type="button" class="mx-cell mx-${bin}" data-query="${escapeHtml(c.query)}" title="${escapeHtml(label)} — 누르면 목록: ${escapeHtml(c.query)}" aria-label="${escapeHtml(label)}">${fmt(c.n)}</button></td>`
        : `<td><span class="mx-cell mx-0" title="${escapeHtml(label)}">0</span></td>`;
    }).join('')}</tr>`).join('');
  const ranges = edges.map((e, k) => [k === 0 ? 1 : edges[k - 1] + 1, e]).filter(([lo, hi]) => lo <= hi);
  box.innerHTML = `<p class="mx-hint">좌우로 밀어 전체 보기 →</p><table class="matrix"><thead>${head}</thead><tbody>${body}</tbody></table>
    <div class="mx-legend"><span>칸 = 두 신호 모두 '있음'인 CVE 수 · 색이 진할수록 많음</span>${
      ranges.map(([lo, hi]) => `<span><i class="mx-${edges.indexOf(hi) + 1}"></i>${fmt(lo)}${hi > lo ? `–${fmt(hi)}` : ''}</span>`).join('')}
      <span>줄 · 칸 이름 밑 숫자 = 그 신호 전체 '있음' · 누르면 목록</span></div>`;
  bindQueries(box);
  if (chips) {
    const pairs = Object.values(mx.cells).filter(c => c.n > 0).sort((x, y) => y.n - x.n).slice(0, 6);
    chips.innerHTML = pairs.length
      ? `<span>많이 겹치는 조합</span>${pairs.map(c => `<button type="button" class="rel-chip" data-query="${escapeHtml(c.query)}" title="누르면 목록"><code>${escapeHtml(c.query)}</code><b>${fmt(c.n)}</b></button>`).join('')}`
      : '';
    bindQueries(chips);
  }
}
