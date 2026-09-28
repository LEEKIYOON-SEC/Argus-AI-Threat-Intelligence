/* 데이터 출처 — 출처마다 무엇을 주는지, 추적 중인 CVE 가운데 몇 건을 '있음'으로 기록했는지, 언제 받았는지.
   출처별 이용 · 재배포 · 표기 조건은 하단 '데이터 출처 및 라이선스' 표 한 곳에만 둔다(INVARIANTS §9-1). 여기에 되풀이하지 않는다. */

const STATE_LABEL = { yes: '있음', no: '없음', unknown: '미확인' };
const KIND_LABEL = { source: '원 출처', derived: 'Argus 계산', ai: 'AI 작성' };

function renderSources() {
  const src = typeof dashSource === 'function' ? dashSource() : null;
  renderSourceMeta(src);
  renderRegistry(src);
  renderCoverage(src);
  renderConflictList(src);
  renderQuality(src);
  // 원 출처 파일 정보(KEV 카탈로그 판 · Exploit-DB 항목 수)는 cve-evidence.json 에 있다 — 처음 열 때 받는다.
  if (detailFiles.evidence === undefined) {
    loadAuxFile('evidence').then(got => { if (got && currentView === 'sources') renderSources(); });
  }
}

function openLicense(e) {
  if (e && e.preventDefault) e.preventDefault();
  const d = document.getElementById('source-license');
  if (!d) return;
  d.open = true;
  d.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderSourceMeta(src) {
  const el = document.getElementById('src-meta');
  if (!el) return;
  el.innerHTML = src
    ? `추적 중 CVE <b>${fmt(src.stats.total)}</b>건 기준 · ${src.live ? '브라우저에서 계산' : 'CI 사전 계산 값'} · 수명주기 기준일 <b>${escapeHtml(src.asOf || '-')}</b>`
    : '집계를 준비하는 중';
}

function upstreamNote(id) {
  const ev = detailFiles.evidence;
  const s = ev && ev.sources ? ev.sources[id] : null;
  if (!s) return '';
  const bits = [];
  if (s.catalog_version) bits.push(`카탈로그 판 ${s.catalog_version}`);
  if (s.released) bits.push(`발표 ${fmtTime(s.released)}`);
  if (s.entries != null && id !== 'cisa-kev') bits.push(`원본 항목 ${fmt(s.entries)}`);
  if (s.modules != null) bits.push(`원본 모듈 ${fmt(s.modules)}`);
  if (s.fetched_at) bits.push(`원본 받은 시각 ${fmtTime(s.fetched_at)}`);
  return bits.join(' · ');
}

// 룰 소스별 범위 — cves.json 의 rule_engines 를 출처 엔티티로 묶어 센다(전체 데이터가 있을 때만).
function engineCoverage() {
  if (!dataReady || !CTX) return {};
  const out = {};
  for (const c of allCves) {
    for (const sid of new Set((c.rule_engines || []).map(e => CTX.ENGINE_SID[e]).filter(Boolean))) out[sid] = (out[sid] || 0) + 1;
  }
  return out;
}
const NO_COVERAGE = { nvd: 'CVE마다 어느 값을 NVD에서 보충했는지는 저장하지 않음', argus: 'Argus가 계산한 판정이라 출처 건수가 없음',
                      gemma: '제목 · 요약 번역 (원문은 상세의 기술 정보)', gemini: 'AI 분석. 사실과 판정에는 쓰지 않음' };

function renderRegistry(src) {
  const box = document.getElementById('src-registry');
  if (!box) return;
  if (!EN || !VM) { box.innerHTML = '<tbody><tr><td class="dash-wait">출처 정보 모듈(entities.js)을 불러오지 못했습니다.</td></tr></tbody>'; return; }
  const engines = engineCoverage();
  const rows = VM.sources(EN, src ? src.stats : null, detailFileTimes()).map(r => (r.coverage || engines[r.id] == null ? r
    : Object.assign({}, r, { coverage: { n: engines[r.id], text: `룰 있음 ${fmt(engines[r.id])} (Argus 룰 색인 기준)` } })));
  box.innerHTML = `<thead><tr><th>출처</th><th>주는 정보</th><th>Argus에서 쓰는 곳</th><th>'있음'으로 기록한 CVE</th><th>갱신 주기</th><th>파일과 생성 시각</th></tr></thead>
    <tbody>${rows.map(r => {
      const note = upstreamNote(r.id);
      return `<tr id="src-${escapeHtml(r.id)}">
        <td><b>${r.url ? linkHtml(r.url, r.name) : escapeHtml(r.name)}</b>${r.provider && r.provider !== r.name ? `<small>${escapeHtml(r.provider)}</small>` : ''}
          <span class="src-kind${r.kind === 'ai' ? ' k-ai' : ''}">${escapeHtml(KIND_LABEL[r.kind] || r.kind)}</span></td>
        <td><div class="src-types">${r.types.map(t => `<span>${escapeHtml(t.label)}</span>`).join('')}</div></td>
        <td>${escapeHtml(r.role)}</td>
        <td class="src-cov">${r.coverage ? `<b>${fmt(r.coverage.n)}</b><small>${escapeHtml(r.coverage.text)}</small>`
          : `<span class="lc-na">-</span>${NO_COVERAGE[r.id] ? `<small>${escapeHtml(NO_COVERAGE[r.id])}</small>` : ''}`}${note ? `<small>${escapeHtml(note)}</small>` : ''}</td>
        <td>${escapeHtml(r.cadence)}</td>
        <td class="src-files">${r.files.map(f => `<div><code>${escapeHtml(f.name)}</code> ${f.at ? escapeHtml(fmtTime(f.at)) : `<span class="lc-na">${f.name === 'cve-facts.json' || f.name === 'cve-evidence.json' ? '아직 받지 않음' : '-'}</span>`}</div>`).join('')}</td>
      </tr>`;
    }).join('')}</tbody>`;
}

// 신호별 확인 현황 — 신호마다 있음 · 없음 · 미확인 한 줄 막대(같은 세 색, 범례 하나). 칸을 누르면 그 상태의 목록.
function renderCoverage(src) {
  const box = document.getElementById('dash-coverage');
  if (!box) return;
  if (!src) { box.innerHTML = '<p class="dash-wait">불러오는 중…</p>'; return; }
  const st = src.stats;
  const total = st.total || 1;
  const rows = CTX.SIGNALS.map(sgl => {
    const c = st.signals[sgl.code];
    const seg = (state, n) => {
      if (!n) return '';
      const q = state === 'yes' ? CTX.yesQuery(sgl.code) : `${state}:${sgl.key}`;
      return `<button type="button" class="cov-seg cov-${state}" style="flex-grow:${n}" data-query="${escapeHtml(q)}"
        title="${escapeHtml(`${sgl.short} ${STATE_LABEL[state]} ${fmt(n)}건 (${pct(n, total)}). 누르면 목록이 열립니다 (${q})`)}"
        aria-label="${escapeHtml(sgl.short)} ${STATE_LABEL[state]} ${fmt(n)}건"></button>`;
    };
    return `<div class="cov-row">
      <span class="cov-name" title="${escapeHtml(sgl.def)}">${escapeHtml(sgl.short)}</span>
      <span class="cov-bar">${seg('yes', c.yes)}${seg('no', c.no)}${seg('unknown', c.unknown)}</span>
      <span class="cov-nums"><b>${fmt(c.yes)}</b><span>${fmt(c.no)}</span><span class="u">${fmt(c.unknown)}</span></span>
    </div>`;
  }).join('');
  box.innerHTML = `<div class="cov-legend"><span><i class="cov-yes"></i>있음</span><span><i class="cov-no"></i>없음 (출처가 없다고 기록)</span><span><i class="cov-unknown"></i>미확인</span><span class="cov-legend-n">있음 · 없음 · 미확인</span></div>
    <div class="cov-rows">${rows}</div>`;
  bindQueries(box);
}

// 출처 간 차이 — 어느 쪽 값도 지우지 않고 건수와 판단 기준을 보여 준다. 누르면 conflict:<키> 목록.
function renderConflictList(src) {
  const box = document.getElementById('src-conflicts');
  if (!box) return;
  if (!src || !VM) { box.innerHTML = '<p class="dash-wait">불러오는 중…</p>'; return; }
  box.innerHTML = `<div class="cf-list">${VM.conflicts(src.stats).map(c => `<button type="button" class="cf-item" data-query="${escapeHtml(c.query)}"
      title="누르면 목록이 열립니다 (${escapeHtml(c.query)})">
    <b>${escapeHtml(c.subject)}: ${escapeHtml(c.label)}</b><span class="cf-n">${fmt(c.n)}</span>
    <span>판단 기준: ${escapeHtml(c.rule)}</span><code>${escapeHtml(c.query)}</code>
  </button>`).join('')}</div>`;
  bindQueries(box);
}

function renderQuality(src) {
  const box = document.getElementById('dash-quality');
  if (!box) return;
  // 형식이 잘못된 시각 하나 때문에 화면 전체가 멈추지 않게 한다.
  const t = ts => { const d = new Date(ts || ''); return isNaN(d) ? '-' : d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC'; };
  const ft = detailFileTimes();
  const files = [
    ['CVE export (cves.json · stats.json)', ft.cves, '매시'],
    ['영향 제품 (cve-products.json)', ft.products, '매시'],
    ['원문 · 발급 기관 (cve-facts.json)', ft.facts, detailFiles.facts === undefined ? '상세를 열면 받음' : detailFiles.facts ? '매시 (바뀐 CVE만 다시 씀)' : '없음. 상세의 원문은 미확인으로 표시'],
    ['원 출처 날짜 (cve-evidence.json · CI)', ft.evidence, detailFiles.evidence === undefined ? '받는 중' : detailFiles.evidence ? '매시 (원본 캐시가 있는 회차)' : '없음. KEV 등재일과 Exploit-DB 공개일은 미확인으로 표시'],
    ['수명주기 (lifecycle.json · endoflife.date)', ft.lifecycle, '매일'],
    ['CI 사전 계산 (cve-context.json)', ft.context,
     contextData ? (contextValid ? '지금 받은 파일과 같은 판' : dataReady ? '받은 파일과 판이 달라 브라우저에서 계산' : '확인 중') : '없음. 브라우저에서 계산'],
  ];
  const cov = src ? src.stats : null;
  const scope = cov ? [
    ['수명주기 연결', `릴리스까지 ${fmt(cov.lifecycle.cycle_level)}건 · 제품까지만 ${fmt(cov.lifecycle.product_only)}건 · 연결 안 됨 ${fmt(cov.total - cov.lifecycle.mapped)}건`],
    ['OSV 기록', `${fmt(cov.signals.PATCH_AVAILABLE.yes + cov.signals.PATCH_AVAILABLE.no)}건 (수정 버전 ${fmt(cov.signals.PATCH_AVAILABLE.yes)})`],
    ['CISA SSVC 판정', `${fmt(cov.total - cov.signals.AUTOMATABLE.unknown)}건`],
    ['EPSS 채점', `${fmt(cov.total - cov.signals.HIGH_EPSS.unknown)}건`],
  ] : [];
  let checks = [];
  if (dataReady && CTX) {
    checks = CTX.qualityChecks(allCves, { lifecycle: lifecycleData, evidence: detailFiles.evidence || null });
    // CI 만 할 수 있는 점검(원 출처 카탈로그 대조 등)은 같은 판의 사전 계산 결과를 덧붙인다.
    if (precomputedUsable() && Array.isArray(contextData.quality)) {
      const have = new Set(checks.map(q => q.id));
      checks = checks.concat(contextData.quality.filter(q => !have.has(q.id)).map(q => Object.assign({}, q, { ci: true })));
    }
  } else if (contextData && contextData.quality) {
    checks = contextData.quality;
  }
  const shown = checks.filter(q => q.status !== 'ok');
  const okCount = checks.filter(q => q.status === 'ok').length;
  box.innerHTML = `<div class="q-grid">
    <div>
      <div class="q-files">${files.map(([n, ts, note]) => `<div><span>${escapeHtml(n)}</span><b>${escapeHtml(t(ts))}</b><small>${escapeHtml(note)}</small></div>`).join('')}</div>
      ${scope.length ? `<div class="q-scope">${scope.map(([k, v]) => `<div><span>${escapeHtml(k)}</span><b>${escapeHtml(v)}</b></div>`).join('')}</div>` : ''}
    </div>
    <div class="q-checks">
      ${shown.map(q => `<div class="q-check q-${q.status}" title="${escapeHtml(q.note || '')}${q.examples && q.examples.length ? ` 예: ${escapeHtml(q.examples.join(', '))}` : ''}">
        <span class="q-badge">${q.status === 'warn' ? '경고' : q.status === 'info' ? '정보' : '건너뜀'}</span>
        <span class="q-label">${escapeHtml(q.label)}${q.ci ? ' <small>(CI)</small>' : ''}</span><b>${fmt(q.count)}</b></div>`).join('')}
      ${checks.length ? `<div class="q-check q-ok"><span class="q-badge">정상</span><span class="q-label">나머지 점검 ${okCount}개 통과 (ID 형식 · 중복 · 값 범위 · CWE 형식 · KEV 일관성 · 링크 · 출처 연결 · 수명주기 형식)</span></div>` : '<p class="dash-wait">점검을 준비하는 중…</p>'}
    </div>
  </div>`;
}
