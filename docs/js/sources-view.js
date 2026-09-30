/* 데이터 출처 — 출처마다 주는 정보, 추적 중인 CVE 가운데 그 출처에 기록이 있는 건수, 예약 주기, 이용 조건.
   출처별 이용 · 재배포 · 표기 조건은 이 화면 한 곳에만 둔다(INVARIANTS §9-1). 하단에는 늘 보여야 하는 고지만 둔다. */

function renderSources() {
  const src = typeof dashSource === 'function' ? dashSource() : null;
  renderSourceMeta(src);
  renderRegistry(src);
}

// 하단 고지 · 상세 각주의 '데이터 출처' 링크 — 이 화면을 열고, anchor 가 있으면 그 칸으로 옮긴다.
function openSources(e, anchor) {
  if (e && e.preventDefault) e.preventDefault();
  switchView('sources', { push: true });
  const el = anchor ? document.getElementById(anchor) : null;
  if (el && el.scrollIntoView) el.scrollIntoView({ block: 'start' });
  else jumpTo(0);
}

function renderSourceMeta(src) {
  const el = document.getElementById('src-meta');
  if (!el) return;
  const when = dataTime();
  const total = src ? src.stats.total : (statsData && statsData.cve && statsData.cve.total) || 0;
  el.textContent = when ? `${when} 기준 · 추적 중 CVE ${fmt(total)}건` : '집계를 준비하는 중';
}

// 룰 저장소별 건수 — 집계에는 엔진별 수만 있어, 전체 목록을 받은 뒤 룰이 온 곳(ET Open · Snort Community …)으로 센다.
function ruleSourceCounts() {
  if (!dataReady || !CTX || !CTX.ruleSource) return {};
  const out = { sigma: 0, 'et-open': 0, 'snort-community': 0, splunk: 0, yara: 0 };
  for (const c of allCves) {
    const r = c.rules || {};
    const seen = new Set(['sigma', 'splunk', 'yara'].filter(k => r[k]));
    for (const n of r.network || []) seen.add(CTX.ruleSource(n));
    for (const sid of seen) if (sid in out) out[sid] += 1;
  }
  return out;
}

// CWE — CWE 번호가 MITRE 목록(약점 · 분류)에 있는 CVE. 번호 자체는 CVE 레코드에 있어, 전체 목록을 받은 뒤 센다.
function cweSourceCount() {
  if (!dataReady || !CWE) return {};
  let n = 0;
  for (const c of allCves) if (CWE.listOf(c.cwe).some(id => CWE.officialName(id))) n += 1;
  return { cwe: n };
}

function renderRegistry(src) {
  const box = document.getElementById('src-registry');
  if (!box) return;
  if (!EN || !VM) { box.innerHTML = '<tbody><tr><td class="dash-wait">출처 정보 모듈(entities.js)을 불러오지 못했습니다.</td></tr></tbody>'; return; }
  const groups = VM.sources(EN, src ? src.stats : null, Object.assign(ruleSourceCounts(), cweSourceCount()));
  const named = (url, text) => (isSafeUrl(url) ? linkHtml(url, text) : escapeHtml(text));
  box.innerHTML = `<thead><tr><th>출처</th><th>주는 정보</th>
      <th class="num" title="추적 중인 CVE 가운데 이 출처에 기록이 있는 건수">기록 있는 CVE</th><th title="Argus가 출처에서 다시 받도록 걸어 둔 주기. 실제 실행은 GitHub 사정으로 늦어질 수 있습니다">예약 주기</th><th>이용 조건</th></tr></thead>
    ${groups.map(g => `<tbody>
      <tr class="src-group"><th colspan="5" scope="colgroup">${escapeHtml(g.label)}</th></tr>
      ${g.rows.map(r => `<tr id="src-${escapeHtml(r.id)}">
        <td class="src-name"><b>${named(r.url, r.name)}</b>${r.provider ? `<small>${escapeHtml(r.provider)}</small>` : ''}</td>
        <td data-label="주는 정보">${escapeHtml(r.role)}</td>
        <td class="num" data-label="기록 있는 CVE">${r.count == null ? '<span class="lc-na">-</span>' : `<b>${fmt(r.count)}</b>`}</td>
        <td class="src-cad" data-label="예약 주기">${escapeHtml(r.cadence)}</td>
        <td class="src-terms" data-label="이용 조건">${r.terms.map(t => `<div><b>${named(t.url, t.label)}</b>${t.note ? `<small>${escapeHtml(t.note)}</small>` : ''}</div>`).join('')}</td>
      </tr>`).join('')}
    </tbody>`).join('')}`;
}
