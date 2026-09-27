/* 대시보드 — 현황 파악용. 모든 숫자에 범위를 적고, 연결(상관)은 누르면 같은 조건의 목록이 열린다.
   전체 데이터가 오기 전에는 CI 사전 계산(cve-context.json)으로 먼저 그리고, 오면 오늘 기준으로 다시 센다. */

let dashAggregate = null;

function liveAggregate() {
  if (dashAggregate && dashAggregate.today === lcToday && dashAggregate.n === allCves.length) return dashAggregate.value;
  const items = allCves.map(cve => {
    const x = cveContext(cve);
    const lc = lifecycleData ? cveLifecycle(cve) : null;
    return {
      id: cve.id, states: x.states, correlations: x.correlations,
      releases: lc ? lc.entries.map(e => `${e.slug}|${e.rel.cycle}`) : [],
      productOnly: !!lc && !lc.entries.length && lc.unresolved.length > 0,
    };
  });
  const value = CTX.aggregate(items);
  dashAggregate = { today: lcToday, n: allCves.length, value };
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
  renderCorrelations(src);
  renderCoverage(src);
  renderQuality(src);
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

function kpiTile({ id, label, value, sub, query, accent, title }) {
  return `<button type="button" class="kpi kpi-link ${accent || ''}" ${query ? `data-query="${escapeHtml(query)}"` : ''} title="${escapeHtml(title || '')}">
    <div class="kpi-label">${escapeHtml(label)}</div>
    <div class="kpi-value"${id ? ` id="${id}"` : ''}>${value}</div>
    <div class="kpi-sub">${sub}</div>
    ${query ? `<span class="kpi-go">목록 <code>${escapeHtml(query)}</code> →</span>` : ''}
  </button>`;
}

function renderKpis(src) {
  const box = document.getElementById('dash-kpis');
  if (!box) return;
  const s = statsData.cve || {};
  const sig = src ? src.stats.signals : null;
  const lcm = src ? src.stats.lifecycle : null;
  const v = (code, st) => (sig ? fmt(sig[code][st]) : '-');
  box.innerHTML = [
    kpiTile({ id: 'stat-total', label: '추적 중 CVE', value: fmt(s.total || allCves.length),
              sub: `<span id="stat-24h-sub">최근 24시간 ${fmt(s.recent_24h)}건 신규</span> · 최근 90일 · 악용·고위험 신호가 있는 것만 저장`,
              title: '악용 신호가 관측됐거나 고위험이 될 가능성이 있는 건만 여기 올라옵니다. 점수만 높고 근거가 없는 건은 저장하지 않습니다.' }),
    kpiTile({ label: 'CVSS 9.0 이상', value: v('CRITICAL_CVSS', 'yes'), accent: 'is-sev',
              sub: `심각도 Critical · CVSS 점수 없음 ${v('CRITICAL_CVSS', 'unknown')}건은 모름`, query: 'cvss:>=9',
              title: 'CVSS 기본 점수 기준 — 악용 여부와는 별개' }),
    kpiTile({ label: 'CISA KEV', value: v('CISA_KEV', 'yes'), accent: 'is-exploit',
              sub: `CISA 카탈로그 등재 · VulnCheck · SSVC 를 더한 악용 근거는 ${v('EXPLOITATION_CONFIRMED', 'yes')}건`, query: 'has:cisa-kev',
              title: 'CISA Known Exploited Vulnerabilities 카탈로그 등재 — 실제 악용 근거' }),
    kpiTile({ label: 'EOL 릴리스 영향 CVE', value: v('EOL_AFFECTED', 'yes'), accent: 'is-lifecycle',
              sub: `영향 릴리스 중 EOL 포함 · 수명주기 연결 ${lcm ? fmt(lcm.mapped) : '-'}건 기준, 나머지 ${v('EOL_AFFECTED', 'unknown')}건은 모름`,
              query: 'lifecycle:eol', title: '제품 릴리스의 지원 상태(endoflife.date) — 취약점 심각도가 아닙니다' }),
  ].join('');
  box.querySelectorAll('[data-query]').forEach(b => b.addEventListener('click', () => goToQuery(b.dataset.query)));
}

const PART_GROUP = {
  CISA_KEV: 'exploit', EXPLOITATION_CONFIRMED: 'exploit', RANSOMWARE: 'exploit', PUBLIC_EXPLOIT: 'weapon',
  AUTOMATABLE: 'auto', EOL_AFFECTED: 'lifecycle', PATCH_AVAILABLE: 'defense', PUBLIC_DETECTION: 'defense',
  HIGH_EPSS: 'score', CRITICAL_CVSS: 'sev',
};

function partLabel(p) {
  const neg = p[0] === '!';
  const code = neg ? p.slice(1) : p;
  const sig = CTX.SIGNAL[code];
  const label = neg && code === 'PATCH_AVAILABLE' ? '수정 기록 없음' : neg ? `${sig.short} 없음` : sig.short;
  return `<span class="corr-part g-${PART_GROUP[code] || 'src'}"><i></i>${escapeHtml(label)}</span>`;
}

function renderCorrelations(src) {
  const box = document.getElementById('dash-corr');
  if (!box) return;
  if (!src) { box.innerHTML = '<p class="dash-wait">데이터를 불러오는 중…</p>'; return; }
  const st = src.stats;
  box.innerHTML = CTX.CORRELATIONS.map(c => {
    const n = st.correlations[c.code] || 0;
    const scope = (st.correlation_scope || {})[c.code];
    const first = CTX.SIGNAL[c.parts[0]];
    const second = CTX.SIGNAL[c.parts[1].replace('!', '')];
    // 둘째 사실이 '없음'을 주지 않는 신호(랜섬웨어: KEV 는 Known/Unknown 뿐)면 비율이 늘 100% 라 비율을 쓰지 않는다.
    const secondCode = c.parts[1].replace('!', '');
    const canBeNo = st.signals[secondCode].no > 0;
    const scopeText = scope == null ? ''
      : canBeNo
        ? `${first.short} ${fmt(st.signals[c.parts[0]].yes)}건 중 ${second.short} 확인 ${fmt(scope)}건 기준 · ${pct(n, scope)}`
        : `${first.short} ${fmt(st.signals[c.parts[0]].yes)}건 중 출처가 '있음'으로 표기한 것만 — 나머지는 모름`;
    return `<button type="button" class="corr-card${n ? '' : ' is-zero'}" data-query="${escapeHtml(c.query)}"
        title="${escapeHtml(c.label)} — 누르면 목록: ${escapeHtml(c.query)}">
      <span class="corr-parts">${partLabel(c.parts[0])}<em>×</em>${partLabel(c.parts[1])}</span>
      <span class="corr-n">${fmt(n)}</span>
      <span class="corr-label">${escapeHtml(c.label)}</span>
      <span class="corr-scope">${escapeHtml(scopeText)}</span>
    </button>`;
  }).join('');
  box.querySelectorAll('[data-query]').forEach(b => b.addEventListener('click', () => goToQuery(b.dataset.query)));
}

// 근거 커버리지 — 신호마다 있음 · 없음 · 모름 한 줄 막대(같은 세 색, 범례 하나). 칸을 누르면 그 상태의 목록.
function renderCoverage(src) {
  const box = document.getElementById('dash-coverage');
  if (!box) return;
  if (!src) { box.innerHTML = '<p class="dash-wait">데이터를 불러오는 중…</p>'; return; }
  const st = src.stats;
  const total = st.total || 1;
  const rows = CTX.SIGNALS.map(sgl => {
    const c = st.signals[sgl.code];
    const seg = (state, n) => {
      if (!n) return '';
      const q = state === 'yes' ? (sgl.code === 'CRITICAL_CVSS' ? 'cvss:>=9' : sgl.code === 'EOL_AFFECTED' ? 'lifecycle:eol' : `has:${sgl.key}`)
        : `${state}:${sgl.key}`;
      return `<button type="button" class="cov-seg cov-${state}" style="flex-grow:${n}" data-query="${escapeHtml(q)}"
        title="${escapeHtml(sgl.short)} — ${STATE_LABEL[state]} ${fmt(n)}건 (${pct(n, total)}) · ${escapeHtml(q)}"
        aria-label="${escapeHtml(sgl.short)} ${STATE_LABEL[state]} ${fmt(n)}건"></button>`;
    };
    return `<div class="cov-row">
      <span class="cov-name" title="${escapeHtml(sgl.def)}">${escapeHtml(sgl.short)}</span>
      <span class="cov-bar">${seg('yes', c.yes)}${seg('no', c.no)}${seg('unknown', c.unknown)}</span>
      <span class="cov-nums"><b>${fmt(c.yes)}</b><span>${fmt(c.no)}</span><span class="u">${fmt(c.unknown)}</span></span>
    </div>`;
  }).join('');
  box.innerHTML = `<div class="cov-legend"><span><i class="cov-yes"></i>있음</span><span><i class="cov-no"></i>없음(출처가 명시)</span><span><i class="cov-unknown"></i>모름</span><span class="cov-legend-n">있음 · 없음 · 모름</span></div>
    <div class="cov-rows">${rows}</div>`;
  box.querySelectorAll('[data-query]').forEach(b => b.addEventListener('click', () => goToQuery(b.dataset.query)));
}

const STATE_LABEL = { yes: '있음', no: '없음', unknown: '모름' };

function renderQuality(src) {
  const box = document.getElementById('dash-quality');
  if (!box) return;
  // 형식이 잘못된 시각 하나 때문에 대시보드 전체가 멈추지 않게 한다.
  const t = ts => { const d = new Date(ts || ''); return isNaN(d) ? '-' : d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC'; };
  const files = [
    ['CVE export (cves.json · stats.json)', statsData && statsData.generated_at, '매시'],
    ['영향 제품 (cve-products.json)', rawFiles.products && rawFiles.products.generated_at, '매시'],
    ['수명주기 (lifecycle.json · endoflife.date)', lifecycleData && lifecycleData.generated_at, '매일'],
    ['CI 사전 계산 (cve-context.json)', contextData && contextData.generated_at,
     contextData ? (contextValid ? '지금 받은 파일과 지문 일치' : dataReady ? '지문 불일치 → 브라우저 계산' : '확인 중') : '없음 → 브라우저 계산'],
  ];
  const cov = src ? src.stats : null;
  const scope = cov ? [
    ['수명주기 연결', `${fmt(cov.lifecycle.cycle_level)}건 사이클까지 · ${fmt(cov.lifecycle.product_only)}건 제품만 · ${fmt(cov.total - cov.lifecycle.mapped)}건 추적 밖`],
    ['OSV 기록', `${fmt(cov.signals.PATCH_AVAILABLE.yes + cov.signals.PATCH_AVAILABLE.no)}건 (수정 버전 ${fmt(cov.signals.PATCH_AVAILABLE.yes)})`],
    ['CISA SSVC 판정', `${fmt(cov.total - cov.signals.AUTOMATABLE.unknown)}건`],
    ['EPSS 채점', `${fmt(cov.total - cov.signals.HIGH_EPSS.unknown)}건`],
  ] : [];
  let checks = [];
  if (dataReady && CTX) checks = CTX.qualityChecks(allCves, { lifecycle: lifecycleData });
  else if (contextData && contextData.quality) checks = contextData.quality;
  const shown = checks.filter(q => q.status !== 'ok');
  const okCount = checks.filter(q => q.status === 'ok').length;
  box.innerHTML = `
    <div class="q-files">${files.map(([n, ts, note]) => `<div><span>${escapeHtml(n)}</span><b>${escapeHtml(t(ts))}</b><small>${escapeHtml(note)}</small></div>`).join('')}</div>
    ${scope.length ? `<div class="q-scope">${scope.map(([k, v]) => `<div><span>${escapeHtml(k)}</span><b>${escapeHtml(v)}</b></div>`).join('')}</div>` : ''}
    <div class="q-checks">
      ${shown.map(q => `<div class="q-check q-${q.status}" title="${escapeHtml(q.note || '')}${q.examples && q.examples.length ? ' · 예: ' + escapeHtml(q.examples.join(', ')) : ''}">
        <span class="q-badge">${q.status === 'warn' ? '경고' : q.status === 'info' ? '정보' : '건너뜀'}</span>
        <span class="q-label">${escapeHtml(q.label)}</span><b>${fmt(q.count)}</b></div>`).join('')}
      ${checks.length ? `<div class="q-check q-ok"><span class="q-badge">정상</span><span class="q-label">그 밖의 점검 ${okCount}개 통과 (ID 형식 · 중복 · KEV 일관성 · 링크 중복 · 수명주기 형식)</span></div>` : ''}
    </div>`;
}
