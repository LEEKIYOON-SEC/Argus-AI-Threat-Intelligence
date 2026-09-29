'use strict';
process.env.TZ = 'UTC';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadDashboard, withFixture, readJson, filterIds, RESET } = require('./helpers/dashboard_vm');
const { collect, rowIds } = require('./helpers/dashboard_scenarios');
const { build } = require('../src/build_context.js');

const TODAY = '2026-09-27';
const ALIASES = require('../data/lifecycle_aliases.json');
// 화면 핵심(뷰 모델 · 목록 · 상세 · 대시보드) — 파생 모듈(lifecycle.js · context.js · entities.js)이 없어도 동작해야 한다.
const CORE = [{ file: 'docs/js/viewmodel.js' }, { file: 'docs/js/cve-dashboard.js' }, { file: 'docs/js/cve-detail.js' },
              { file: 'docs/js/dashboard-view.js' }, { file: 'docs/js/sources-view.js' }];
const FULL = [{ file: 'docs/js/lifecycle.js' }, { file: 'docs/js/context.js' }, { file: 'docs/js/entities.js' }, ...CORE,
              { file: 'docs/js/lifecycle-view.js' }];

function dashboard({ files = FULL, lifecycle = true } = {}) {
  const d = withFixture(loadDashboard(files));
  if (lifecycle) {
    d.ctx.__lc = [readJson('lifecycle_sample.json'), ALIASES];
    d.run(`setLifecycle(__lc[0], __lc[1]); lcToday = ${JSON.stringify(TODAY)};`);
  }
  d.run('dataReady = true;');
  return d;
}

const BASELINE = readJson('dashboard_baseline.json').result;
const ids = arr => [...arr].sort();
const search = (d, q) => ids(filterIds(d, `activeFilters.search = ${JSON.stringify(q)};`));
const ALL = ids(BASELINE.searches['']);
const cve = n => `CVE-2026-${String(n).padStart(4, '0')}`;
const unesc = t => String(t).replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&quot;/g, '"').replace(/&amp;/g, '&');

// 변경 전(0f68020) 기준과 의미로 비교한다 — 목록·상세는 새 화면이라 HTML 대신 행 ID 순서·ID·제목만.
// has:nuclei · has:edb · has:ransom · has:foo 는 기존 버그(전부 통과)를 고쳤으므로 아래에서 따로 확인한다.
const FIXED_BUGS = ['has:nuclei', 'has:edb', 'has:ransom', 'has:foo'];
// 의도한 변경 — 대시보드 KPI 정의(INVARIANTS §6): CISA KEV 는 is_kev 만, 무기화 = Metasploit ∪ Exploit-DB(nuclei 제외),
// 24시간 칸 설명은 '신규'가 아니라 '알림·갱신'. 새 값은 아래 'KPI' 테스트가 확인한다. 예전 묶음(KPI_TILES)은 그대로 비교한다.
const CHANGED_KPI = ['stat-kev', 'stat-weapon', 'stat-24h-sub'];
// 영향 제품 순위의 툴팁 문구만 바꿨다(말투 정리). 칸 구성 · 숫자 · 누르면 거는 필터는 그대로 비교한다.
const noTitles = html => String(html).replace(/ title="[^"]*"/g, '');
function semantic(out) {
  const o = JSON.parse(JSON.stringify(out));
  o.ui.rows = rowIds(o.ui.rows);
  o.ui.emptyRows = /empty-state/.test(o.ui.emptyRows);
  for (const k of Object.keys(o.detail)) o.detail[k] = { id: o.detail[k].id, title: o.detail[k].title };
  for (const q of FIXED_BUGS) delete o.searches[q];
  for (const k of CHANGED_KPI) delete o.stats[k];
  o.stats.products = noTitles(o.stats.products);
  return o;
}

test('회귀: 검색·필터·정렬·페이지·통계·필터 목록·CSV/JSON/STIX 가 변경 전과 같다', () => {
  const now = semantic(collect(dashboard()));
  const base = semantic(BASELINE);
  for (const section of Object.keys(base)) {
    for (const key of Object.keys(base[section])) {
      assert.deepEqual(now[section][key], base[section][key], `${section}.${key}`);
    }
  }
});

test('회귀: 수명주기 데이터를 못 받아도 기존 동작이 같다', () => {
  assert.deepEqual(semantic(collect(dashboard({ lifecycle: false }))), semantic(BASELINE));
});

test('회귀: 수명주기·파생 모듈이 없어도 목록·검색·내보내기가 동작한다', () => {
  assert.deepEqual(semantic(collect(dashboard({ files: CORE, lifecycle: false }))), semantic(BASELINE));
});

test('기존 has:* 는 뜻 그대로, 전부 통과하던 has:nuclei · edb · ransom · 잘못된 값은 고쳤다', () => {
  const d = dashboard();
  assert.deepEqual(search(d, 'has:kev'), [cve(1), cve(4), cve(10)]);
  assert.deepEqual(search(d, 'has:msf'), [cve(1), cve(2), cve(7), cve(11)], '기존 무기화 묶음(MSF · EDB · nuclei) 그대로');
  assert.deepEqual(search(d, 'has:poc'), [cve(3), cve(14)]);
  assert.deepEqual(search(d, 'has:rules'), [cve(1), cve(9)]);
  assert.deepEqual(search(d, 'has:ai'), [cve(5)]);
  assert.deepEqual(search(d, 'has:auto'), [cve(6)]);
  assert.deepEqual(search(d, 'has:patched'), [cve(8)]);
  for (const q of ['has:kev', 'has:msf', 'has:poc', 'has:rules', 'has:ai', 'has:auto', 'has:patched']) {
    assert.deepEqual(search(d, q), ids(BASELINE.searches[q]), `${q} 는 변경 전과 같다`);
  }
  assert.deepEqual(BASELINE.searches['has:nuclei'].length, ALL.length, '변경 전: 전부 통과(버그)');
  assert.deepEqual(search(d, 'has:nuclei'), [cve(2), cve(7)]);
  assert.deepEqual(search(d, 'has:edb'), [cve(2), cve(11)]);
  assert.deepEqual(search(d, 'has:ransom'), [cve(1)]);
  assert.deepEqual(search(d, 'has:foo'), [], '모르는 값은 아무것도 통과시키지 않는다');
});

test('새 검색어 — 출처별 · 파생 신호 · 없음(no:) · 모름(unknown:)', () => {
  const d = dashboard();
  assert.deepEqual(search(d, 'has:cisa-kev'), [cve(1), cve(10)]);
  assert.deepEqual(search(d, 'has:vulncheck-kev'), [cve(4)]);
  assert.deepEqual(search(d, 'has:ssvc-active'), [cve(4)]);
  assert.deepEqual(search(d, 'has:exploit'), [cve(1), cve(2), cve(3), cve(11), cve(14)], 'EDB · MSF · PoC (nuclei 제외)');
  assert.deepEqual(search(d, 'has:metasploit'), [cve(1)]);
  assert.deepEqual(search(d, 'has:detection'), [cve(1), cve(2), cve(7), cve(9)], '룰 + nuclei 점검 템플릿');
  assert.deepEqual(search(d, 'has:patch'), search(d, 'has:patched'));
  assert.deepEqual(search(d, 'no:patch'), [cve(3)], 'OSV 에 패키지는 있는데 수정 버전 기록이 없음');
  assert.deepEqual(search(d, 'unknown:patch'), ALL.filter(x => ![cve(3), cve(8)].includes(x)), 'OSV 기록 없음은 모름');
  assert.deepEqual(search(d, 'has:high-epss'), [cve(1), cve(2), cve(6), cve(10), cve(14)]);
  assert.deepEqual(search(d, 'unknown:high-epss'), [cve(16)], 'EPSS 0 은 미채점');
  assert.deepEqual(search(d, 'has:critical'), search(d, 'cvss:>=9'));
  assert.deepEqual(search(d, 'unknown:critical'), [cve(5)], 'CVSS 0 은 점수 없음');
  assert.deepEqual(search(d, 'has:eol'), search(d, 'lifecycle:eol'));
  assert.deepEqual(search(d, 'unknown:ransom'), ALL.filter(x => x !== cve(1)), '랜섬웨어는 Known 이 아니면 모름');
  assert.deepEqual(search(d, 'no:ransom'), [], 'KEV 는 "아님"을 주지 않는다');
  assert.deepEqual(search(d, 'unknown:auto'), ALL.filter(x => x !== cve(6)));
  assert.deepEqual(search(d, 'lifecycle:security-support'), search(d, 'lifecycle:security'));
  assert.deepEqual(search(d, 'release:windows/7-sp1'), [cve(10)]);
  assert.deepEqual(search(d, 'release:nginx/1.25'), [cve(2)]);
  assert.deepEqual(search(d, 'release:windows'), [], '제품/사이클 형식이 아니면 통과시키지 않는다');
  assert.deepEqual(search(d, 'no:bogus'), []);
  assert.deepEqual(search(d, 'corr:bogus'), []);
});

test('상관 — corr:<코드> · 카드 검색어 · 집계 숫자가 모두 같다 (대시보드 숫자 = 누른 뒤 목록)', () => {
  const d = dashboard();
  const agg = d.run('liveAggregate()');
  for (const c of d.run('ArgusContext.CORRELATIONS')) {
    const byCode = search(d, `corr:${c.code.toLowerCase()}`);
    const byQuery = search(d, c.query);
    assert.deepEqual(byQuery, byCode, `${c.code}: ${c.query}`);
    assert.equal(agg.correlations[c.code], byCode.length, `${c.code} 집계`);
  }
  assert.deepEqual(search(d, 'corr:kev_eol'), [cve(10)]);
  assert.deepEqual(search(d, 'corr:exploit_no_fix'), [cve(3)], '공개 exploit + OSV 수정 기록 없음');
  assert.deepEqual(search(d, 'corr:kev_ransomware'), [cve(1)]);
});

test('KPI — 6칸, 정의가 바뀐 칸(CISA KEV · 무기화 · 24시간)과 숫자 = 누른 뒤 목록 건수', () => {
  const d = dashboard();
  d.run('renderStats(); renderDashboard();');
  const kpis = d.el('dash-kpis').innerHTML;
  const tiles = [...kpis.matchAll(/data-query="([^"]*)"[\s\S]*?kpi-label">([^<]+)<\/span>\s*<span class="kpi-value" id="([^"]+)">([\d,-]+)</g)]
    .map(m => ({ query: m[1], label: m[2], id: m[3], value: Number(m[4].replace(/,/g, '')) }));
  assert.deepEqual(tiles.map(t => t.label), ['추적 중 CVE', '24시간 알림·갱신', 'CISA KEV', '무기화', '공개 PoC', 'AI 발견']);
  assert.deepEqual(tiles.map(t => t.value), [16, 5, 2, 3, 2, 1]);
  assert.deepEqual(tiles.map(t => t.query), ['', 'recent:24h', 'has:cisa-kev', 'has:weaponized', 'has:poc', 'has:ai']);
  for (const t of tiles) assert.equal(search(d, t.query).length, t.value, `${t.label}: ${t.query || '(전체)'}`);
  assert.deepEqual(search(d, 'has:cisa-kev'), [cve(1), cve(10)], 'CISA KEV 만 — VulnCheck · SSVC active 는 악용 근거(has:kev)에만');
  assert.deepEqual(search(d, 'has:weaponized'), [cve(1), cve(2), cve(11)], 'Metasploit ∪ Exploit-DB — nuclei 점검 템플릿(CVE-7)은 넣지 않는다');
  assert.deepEqual(search(d, 'recent:24h'), [cve(12), cve(13), cve(14), cve(15), cve(16)], 'export 시각 기준 24시간 안의 Argus 시각');
  // 숫자 아래 줄 — 변화를 셀 수 없으면(KEV 등재일 파일 전) 출처별 건수를 적는다
  assert.match(kpis, /id="stat-kev">2<\/span>\s*<span class="kpi-sub">악용 근거 전체 3건</, 'CVE-1 · 4(VulnCheck + SSVC active) · 10');
  assert.match(kpis, /<span class="kpi-sub">MSF 1 · EDB 2</);
  assert.match(kpis, /title="Metasploit\(MSF\) 모듈이나 Exploit-DB\(EDB\) 항목이 있는 CVE입니다\. Metasploit 1건 · Exploit-DB 2건/, '약칭은 설명에 풀어 쓴다');
  assert.match(kpis, /id="stat-24h">5<\/span>\s*<span class="kpi-sub">Critical 0 · KEV 0</, '24시간 알림·갱신 중 Critical · CISA KEV');
  assert.match(kpis, /id="stat-total">16<\/span>\s*<span class="kpi-sub">최근 7일 공개 없음</);
  assert.doesNotMatch(kpis, /—/, '칸 안의 설명에 줄표를 쓰지 않는다');
  // renderStats 가 쓰는 칸(예전 id)도 같은 값
  assert.deepEqual(['stat-total', 'stat-24h', 'stat-kev', 'stat-weapon', 'stat-poc', 'stat-ai'].map(id => d.el(id).textContent), ['16', '5', '2', '3', '2', '1']);
  assert.equal(d.el('stat-24h-sub').textContent, '새 공개와 상태 변경 포함');
  // 예전 KPI 네 칸의 신호 묶음은 기존 검색어(has:kev · has:msf)의 뜻으로 남는다
  assert.deepEqual(JSON.parse(JSON.stringify(d.run('KPI_TILES.map(sig => allCves.filter(c => cveHasSignal(c, sig)).length)'))), BASELINE.stats.kpi);
});

test('대시보드 — 추이 · 상관 · 최근 CVE · 동시 발생 행렬 · 관련 검색어 (숫자 = 목록)', () => {
  const d = dashboard();
  d.run('renderDashboard();');
  assert.match(d.el('dash-meta').innerHTML, /수명주기 기준일 <b>2026-09-27<\/b>/);
  assert.match(d.el('dash-asof').textContent, /기준 · 추적 중 CVE 16건$/);
  // 추이 — 최근 30일(2026-08-29 ~ 09-27) CVE 공개일별. 공개일 09-19 인 13건만 창 안에 있다. 선 하나 + 날짜마다 마우스 칸.
  const ov = d.el('dash-overview').innerHTML;
  assert.equal((ov.match(/class="ov-col/g) || []).length, 30);
  assert.equal((ov.match(/class="ov-line"/g) || []).length, 1, '한 계열 선');
  assert.match(ov, /합계 <b>13<\/b>건 · 하루 최대 <b>13<\/b>건\(09\.19\) · 최근 7일 <b>0<\/b>건/);
  assert.match(ov, /<td>2026-09-19<\/td><td><b>13<\/b><\/td><td>3<\/td>/, '표로 보기 — 날짜 · 합계 · 심각도별');
  // 상관 — 10개, 건수순, 누르면 같은 조건
  const corr = d.el('dash-corr').innerHTML;
  assert.equal((corr.match(/class="corr-card/g) || []).length, 10);
  assert.match(corr, /data-query="has:cisa-kev lifecycle:eol"[\s\S]*?corr-n">1</);
  assert.match(corr, /data-query="has:cisa-kev has:ransom"[\s\S]*?corr-scope">나머지는 미확인</, '랜섬웨어처럼 "없음"이 없는 신호는 비율을 쓰지 않는다');
  assert.match(corr, /data-query="has:cisa-kev has:exploit"[\s\S]*?corr-scope">CISA KEV 중 50%</, '분모가 첫 신호 전체면 그 이름으로');
  assert.match(corr, /data-query="has:cisa-kev lifecycle:eol"[\s\S]*?corr-scope">판정된 1건 중 100%</, 'EOL 여부를 아는 CVE 만 분모');
  const nums = [...corr.matchAll(/corr-n">([\d,]+)</g)].map(m => Number(m[1]));
  assert.deepEqual(nums, [...nums].sort((a, b) => b - a), '건수 많은 순');
  // 최근 CVE — 공개일 순, 같은 날이면 Argus 시각 순
  const recent = [...d.el('dash-recent').innerHTML.matchAll(/data-cve="([^"]+)"/g)].map(m => m[1]);
  assert.deepEqual(recent, [16, 15, 14, 13, 12, 10, 9, 8].map(cve));
  // 행렬 — 칸마다 두 신호 모두 있음 건수 = 그 검색어의 목록 건수
  const mx = d.el('dash-matrix').innerHTML;
  const cells = [...mx.matchAll(/class="mx-cell mx-(\d)" data-query="([^"]+)"[^>]*>([\d,]+)</g)];
  assert.ok(cells.length > 0);
  for (const [, , q, n] of cells) assert.equal(search(d, unesc(q)).length, Number(n.replace(/,/g, '')), q);
  const zeros = (mx.match(/class="mx-cell mx-0"/g) || []).length;
  assert.equal(cells.length + zeros, 36, '9개 신호의 두 개씩 조합');
  assert.match(mx, /class="mx-row" data-query="has:cisa-kev"/, '줄 이름 = 그 신호 전체');
  const axes = [...mx.matchAll(/class="mx-row" data-query="([^"]+)"[\s\S]*?<small>([\d,]+)<\/small>/g)];
  assert.equal(new Set(axes.map(m => m[1])).size, 9, '신호 9개 모두 줄 또는 칸 머리에 전체 건수');
  for (const [, q, n] of axes) assert.equal(search(d, unesc(q)).length, Number(n.replace(/,/g, '')), `전체 ${q}`);
  const chips = [...d.el('dash-rel-chips').innerHTML.matchAll(/data-query="([^"]+)"[^>]*><span class="rel-name">[^<]+<\/span><code>[^<]+<\/code><b>([\d,]+)</g)];
  assert.ok(chips.length > 0 && chips.length <= 6);
  for (const [, q, n] of chips) assert.equal(search(d, unesc(q)).length, Number(n), q);
});

test('Data Sources — 외부 출처 한 표에 건수 · 갱신 · 이용 조건(라이선스 전문 링크), 이용 조건은 이 표 한 곳에만', () => {
  const d = dashboard();
  d.run('renderSources();');
  const reg = d.el('src-registry').innerHTML;
  const ids = d.run('ArgusEntities.SOURCE_GROUPS').flatMap(g => g.ids);
  for (const id of ids) assert.equal((reg.match(new RegExp(`id="src-${id}"`, 'g')) || []).length, 1, id);
  assert.equal((reg.match(/<tr id="src-/g) || []).length, ids.length);
  for (const hidden of ['gemma', 'gemini', 'argus', 'rule-index', 'nvd']) assert.doesNotMatch(reg, new RegExp(`id="src-${hidden}"`), hidden);
  assert.doesNotMatch(reg, /Gemma|Gemini|Google AI Studio|무료 티어/, 'AI 도구 · 요금제는 출처 표에 싣지 않는다');
  assert.doesNotMatch(reg, /\.json|캐시/, '파일 이름 · 캐시 설명은 싣지 않는다');
  assert.match(reg, /id="src-cisa-kev"[\s\S]*?<b>2<\/b>/, 'CISA KEV 에 기록이 있는 추적 CVE 2건');
  assert.match(reg, /id="src-sigma"[\s\S]*?<b>1<\/b>/, 'Sigma 룰이 있는 CVE 1건 — 전체 목록에서 룰이 온 곳으로 센다');
  assert.match(reg, /id="src-et-open"[\s\S]*?href="https:\/\/rules\.emergingthreats\.net\/open\/suricata-7\.0\/LICENSE"[^>]*>BSD/);
  assert.match(reg, /id="src-snort-community"[\s\S]*?href="https:\/\/www\.gnu\.org\/licenses\/old-licenses\/gpl-2\.0\.html"[^>]*>GPLv2/);
  assert.match(reg, /id="src-sigma"[\s\S]*?href="https:\/\/github\.com\/SigmaHQ\/Detection-Rule-License"[^>]*>DRL 1\.1/);
  assert.match(reg, /id="src-splunk"[\s\S]*?href="https:\/\/github\.com\/splunk\/security_content\/blob\/develop\/LICENSE"[^>]*>Apache-2\.0/);
  assert.match(reg, /id="src-cve-record"[\s\S]*?Legal\/TermsOfUse"[^>]*>CVE 이용약관[\s\S]*?terms-of-use"[^>]*>NVD 이용약관/, 'NVD 는 CVE 레코드 행에 합친다');
  assert.match(d.el('src-meta').textContent, /기준 · 추적 중 CVE 16건/);
  // 예약 주기 — yml 예약 · 캐시 수명 그대로. CVE 레코드는 5분 수집(변경분), SSVC 는 CVE 레코드 안에 함께 온다
  assert.match(reg, /<th[^>]*>예약 주기<\/th>/);
  assert.doesNotMatch(reg, /<th>갱신<\/th>/);
  assert.match(reg, /id="src-cve-record"[\s\S]*?data-label="예약 주기">5분마다 \(변경분\)</);
  assert.match(reg, /id="src-cisa-adp"[\s\S]*?data-label="예약 주기">5분마다 \(CVE 레코드와 함께\)</);
  assert.match(reg, /id="src-cisa-kev"[\s\S]*?data-label="예약 주기">매시</);
});

test('탐지 룰 본문 — 라이선스 전문 · 룰 원문 링크를 붙이고, 라이선스가 없는 YARA 는 본문 없이 링크만', () => {
  const d = dashboard();
  const html = d.run(`renderRulesSection({ id: 'CVE-X', rules: {
    sigma: { code: 'title: s', source: 'SigmaHQ', license: 'DRL 1.1', author: 'A', url: 'https://github.com/SigmaHQ/sigma/blob/master/r.yml' },
    network: [{ engine: 'suricata7', source: 'Suricata 7 ET Open', license: 'MIT', code: 'alert x' }],
    yara: { engine: 'yara', source: 'YARA Forge', license: '룰별 상이', license_url: 'N/A', author: 'B',
            url: 'https://github.com/fboldewin/YARA-rules/blob/x/r.yar', code: 'rule leak {}' } } })`);
  assert.match(html, /라이선스 <a href="https:\/\/github\.com\/SigmaHQ\/Detection-Rule-License"[^>]*>DRL 1\.1/);
  assert.match(html, /작성자 A · <a href="https:\/\/github\.com\/SigmaHQ\/sigma\/blob\/master\/r\.yml"[^>]*>룰 원문/);
  assert.match(html, /라이선스 <a href="https:\/\/rules\.emergingthreats\.net\/open\/suricata-7\.0\/LICENSE"[^>]*>BSD[^<]*<\/a> · © 2003-2026 Emerging Threats/);
  assert.doesNotMatch(html, /License: |MIT/, '옛 표기(ET Open MIT)를 그대로 싣지 않는다');
  assert.doesNotMatch(html, /rule leak/, '라이선스가 없는 저장소의 YARA 본문은 싣지 않는다');
  assert.match(html, /원 저장소에 라이선스 파일이 없어 본문은 싣지 않습니다/);
  assert.match(html, /href="https:\/\/github\.com\/fboldewin\/YARA-rules\/blob\/x\/r\.yar"[^>]*>원문 보기/);
  // BSD · MIT 저장소의 YARA 룰은 저작권 문구를 룰 위에 함께 적는다 (문구는 export 가 원 저장소 LICENSE 에서 옮김)
  const bsd = d.run(`renderRulesSection({ id: 'CVE-Y', rules: { yara: { engine: 'yara', source: 'YARA Forge', license: 'BSD-2-Clause',
    holder: 'Copyright 2022 by Volexity, Inc.', license_url: 'https://github.com/volexity/threat-intel/blob/x/LICENSE.txt',
    author: 'threatintel@volexity.com', url: 'https://github.com/volexity/threat-intel/blob/x/y.yar', code: 'rule v {}' } } })`);
  assert.match(bsd, /라이선스 <a href="https:\/\/github\.com\/volexity\/threat-intel\/blob\/x\/LICENSE\.txt"[^>]*>BSD-2-Clause[^<]*<\/a> · Copyright 2022 by Volexity, Inc\. · 작성자 threatintel@volexity\.com/);
  assert.match(bsd, /rule v \{\}/);
});

test('대시보드 — 전체 데이터 전에 CI 사전 계산으로 먼저 그리고, 숫자는 같다', () => {
  const live = dashboard();
  live.run('renderDashboard();');
  const liveCorr = live.el('dash-corr').innerHTML;
  const fx = { cves: readJson('dashboard_cves.json'), stats: readJson('dashboard_stats.json'),
               products: readJson('dashboard_products.json'), packages: readJson('dashboard_packages.json') };
  const ctx = build(Object.assign({ lifecycle: readJson('lifecycle_sample.json'), aliases: ALIASES }, fx),
                    new Date(`${TODAY}T12:00:00Z`));
  const early = withFixture(loadDashboard(FULL));
  early.ctx.__ctx = ctx;
  early.run('allCves = []; dataReady = false; setContext(__ctx); renderDashboard();');
  assert.match(early.el('dash-meta').innerHTML, /CI 사전 계산/);
  const earlyCorr = early.el('dash-corr').innerHTML;
  const nums = html => [...html.matchAll(/corr-n">([\d,]+)</g)].map(m => m[1]);
  assert.deepEqual(nums(earlyCorr), nums(liveCorr));
  early.run("statsData = Object.assign({}, statsData, { generated_at: 'other' }); renderDashboard();");
  assert.match(early.el('dash-corr').innerHTML, /불러오는 중/, '다른 판의 사전 계산은 쓰지 않는다');
});

test('사전 계산 매핑 — 지문이 맞으면 쓰고, 결과는 직접 매칭과 같다', () => {
  const fx = { cves: readJson('dashboard_cves.json'), stats: readJson('dashboard_stats.json'),
               products: readJson('dashboard_products.json'), packages: readJson('dashboard_packages.json') };
  const lcData = readJson('lifecycle_sample.json');
  const ctx = build(Object.assign({ lifecycle: lcData, aliases: ALIASES }, fx), new Date(`${TODAY}T12:00:00Z`));
  const plain = dashboard();
  const pre = withFixture(loadDashboard(FULL));
  Object.assign(pre.ctx, { __ctx: ctx, __raw: fx, __lc: [lcData, ALIASES] });
  pre.run(`rawFiles.products = __raw.products; rawFiles.packages = __raw.packages; setContext(__ctx);
           setLifecycle(__lc[0], __lc[1]); lcToday = ${JSON.stringify(TODAY)}; dataReady = true;`);
  assert.equal(pre.run('contextValid'), true);
  for (const c of fx.cves) {
    const q = `JSON.stringify((r => ({ e: r.entries.map(e => [e.slug, e.rel.cycle, e.via]), u: r.unresolved, n: r.untracked, p: r.partial }))(cveLifecycle(allCves.find(x => x.id === ${JSON.stringify(c.id)}))))`;
    assert.equal(pre.run(q), plain.run(q), c.id);
  }
  pre.run("rawFiles.products = Object.assign({}, rawFiles.products, { generated_at: 'changed' }); validateContext();");
  assert.equal(pre.run('contextValid'), false, '영향 제품 파일이 바뀌면 사전 계산 매핑을 버린다');
});

test('목록 — 6칸, 출처가 확인한 것만 칩, 없음 · 미확인은 빈칸', () => {
  const d = dashboard();
  filterIds(d, '');
  const html = d.el('cve-table-body').innerHTML;
  const row = id => html.split('<tr ').find(r => r.includes(`showDetail('${id}')`));
  assert.equal(rowIds(html).length, 16);
  assert.equal((row(cve(1)).match(/<td /g) || []).length, 6, 'CVE · 요약·영향 제품 · CVSS·EPSS · 위협 신호 · 지원 상태 · 탐지·수정');
  assert.match(row(cve(1)), /ev-chip ev-exploit[^>]*><i><\/i>KEV<\/span>/, '악용 근거는 출처 이름으로 짧게');
  assert.match(row(cve(1)), /ev-chip ev-exploit[^>]*><i><\/i>랜섬웨어<\/span>/, '랜섬웨어는 따로 한 칩');
  assert.match(row(cve(1)), /ev-chip ev-weapon[^>]*><i><\/i>MSF<\/span>/);
  assert.match(row(cve(2)), /ev-chip ev-weapon[^>]*><i><\/i>EDB<\/span>/);
  assert.doesNotMatch(row(cve(2)), /ev-exploit/, 'nuclei · EDB 만으로 악용 근거가 되지 않는다');
  assert.match(row(cve(6)), /ev-chip ev-auto/);
  assert.match(row(cve(12)), /<span class="c-none" aria-label="확인된 위협 신호 없음"><\/span>/, '신호가 없으면 빈칸');
  assert.match(row(cve(5)), /점수 없음/, 'CVSS 0 은 미확인');
  assert.match(row(cve(16)), /미채점/, 'EPSS 0 은 미확인');
  assert.match(row(cve(5)), /class="sc-sub"[^>]*>0\.04%</, '0.1% 미만은 0.0% 로 적지 않는다');
  assert.deepEqual(['epssPct(0.99999, 1)', 'epssPct(0.99999, 2)', 'epssPct(1, 1)', 'epssPct(0.1234, 2)'].map(x => d.run(x)),
                   ['99.9', '99.99', '100.0', '12.34'], '1 미만 확률을 100% 로 반올림하지 않는다');
  assert.match(row(cve(8)), /class="df df-fix"[^>]*>수정</, 'OSV 수정 버전');
  assert.doesNotMatch(row(cve(3)), /df-fix/, '수정 기록 없음은 빈칸 (상세에 기록 없음으로)');
  assert.match(row(cve(1)), /class="df df-det"[^>]*>탐지</);
  assert.match(row(cve(14)), /lc-badge lc-ACTIVE[^>]*>ACTIVE<em>/, '지원 상태 + 릴리스 이름');
  assert.match(row(cve(5)), /<td class="c-lc" data-label="지원 상태"><\/td>/, '지원 상태를 모르면 빈칸');
  assert.match(row(cve(3)), /class="c-prod"[^>]*>PHP Group PHP<span class="c-ver"> · 8\.1\.\* 부터 8\.1\.29 이전 외 1<\/span>/, '영향 버전 한 줄 표기');
  assert.match(row(cve(6)), /Oracle Java SE<span class="c-ver"> · 8u112<\/span>/, '단일 버전');
  assert.doesNotMatch(html, /badge-kev|badge-msf/, '예전 위협 배지 스타일을 쓰지 않는다');
  filterIds(d, "activeFilters.search = 'nomatch';");
  assert.match(d.el('cve-table-body').innerHTML, /colspan="6" class="empty-state"/, '6칸');
});

test('영향 버전 한 줄 표기 — 수집 단계 형식을 줄이고, 하한이 없으면 상한만', () => {
  const d = dashboard();
  const short = v => d.run(`ArgusViewModel.shortVersions(${JSON.stringify(v)})`);
  assert.equal(short('0 부터 1.2.3 이전'), '1.2.3 이전', '하한 0 은 적지 않는다');
  assert.equal(short('unspecified 부터 12.2 이전'), '12.2 이전');
  assert.equal(short('1.0 부터 1.4 이하'), '1.0 부터 1.4 이하');
  assert.equal(short('1.0 부터 1.4 이전, 2.0 부터 2.3 이전, 3.0 부터 3.1 이전'), '1.0 부터 1.4 이전 외 2');
  assert.equal(short('16 (단일 버전), 15 (단일 버전), 14 (단일 버전), 13 (단일 버전), 12 (단일 버전)'), '16, 15, 14, 13 외 1', '단일 버전은 넷까지');
  assert.equal(short('1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 (단일 버전)'), '커밋 1da177e', '커밋 해시는 짧게');
  assert.equal(short('모든 버전'), '모든 버전');
  assert.equal(short('정보 없음'), '', '없으면 비운다');
  assert.equal(short('n/a (단일 버전)'), '');
});

test('조건 칩 · 검색어 이동 · URL — 필터 상태는 검색줄 한 곳에만', () => {
  const d = dashboard();
  d.run(RESET);
  d.run("toggleQueryTerm('has:cisa-kev')");
  assert.equal(d.run('activeFilters.search'), 'has:cisa-kev');
  d.run("toggleQueryTerm('lifecycle:eol')");
  assert.equal(d.run('activeFilters.search'), 'has:cisa-kev lifecycle:eol');
  assert.deepEqual(ids(d.run('filteredCves.map(c => c.id)')), [cve(10)]);
  d.run("toggleQueryTerm('has:cisa-kev')");
  assert.equal(d.run('activeFilters.search'), 'lifecycle:eol');
  d.run("activeFilters.cvssMin = 9.5; activeFilters.vendor = 'acme'; goToQuery('has:exploit no:patch')");
  assert.equal(d.run('currentView'), 'cves');
  assert.equal(d.run('activeFilters.cvssMin'), null, '대시보드에서 오면 다른 필터를 푼다');
  assert.deepEqual(ids(d.run('filteredCves.map(c => c.id)')), [cve(3)]);
  assert.match(d.run('history.last'), /view=cves/);
  assert.match(decodeURIComponent(d.run('history.last')).replace(/\+/g, ' '), /q=has:exploit no:patch/);
  d.run("switchView('dashboard')");
  assert.doesNotMatch(d.run('history.last'), /view=|q=/, '대시보드는 기본 화면이라 URL 에 남기지 않는다');
});

test('자동완성 — 필드와 값을 제안한다', () => {
  const d = dashboard();
  const vals = f => d.run(`suggestValues(${JSON.stringify(f)}).map(x => x[0])`);
  assert.ok(vals('has').includes('cisa-kev'));
  assert.ok(vals('corr').includes('kev_eol'));
  assert.ok(vals('no').includes('patch'));
  assert.ok(vals('lifecycle').includes('eol'));
  d.run('buildVendorFilter();');
  assert.ok(vals('vendor').includes('microsoft'));
});

// 상세 본문의 칸 — 위에서부터 이 순서. 칸 하나는 다음 칸이 시작하는 곳까지.
const DETAIL_SECS = ['d-threat', 'd-remedy', 'd-product', 'd-lifecycle', 'd-evidence', 'd-tech', 'd-ai'];
function detailSec(body, id) {
  const start = body.indexOf(`id="${id}"`);
  const ends = DETAIL_SECS.map(x => body.indexOf(`id="${x}"`)).filter(i => i > start);
  return body.slice(start, ends.length ? Math.min(...ends) : body.length);
}
// 가짜 브라우저 기록 — pushState 를 받고, 주소를 실제처럼 바꾼다(뒤로 가기 시험용).
function trackHistory(d) {
  d.run(`history.pushed = [];
    history.pushState = function (state, title, url) { this.pushed.push(String(url)); this.last = String(url); location.href = String(url); };
    history.replaceState = function (state, title, url) { this.last = String(url); location.href = String(url); };`);
}
const edit = (d, changes) => d.run(`(() => { const ch = ${JSON.stringify(changes)};
  for (const [n, o] of Object.entries(ch)) Object.assign(allCves.find(c => c.id === 'CVE-2026-' + String(n).padStart(4, '0')), o); })()`);

test('상세 — 머리글 수치 → 확인된 위협 신호 → 조치 · 영향 제품 → 접어 둔 수명주기 · 근거 · 기술 정보 · AI', () => {
  const d = dashboard();
  d.run(`allCves.find(c => c.id === 'CVE-2026-0001').analysis = { root_cause: 'AI-ROOT-CAUSE-TEXT', mitigation: ['AI-STEP'] };`);
  d.run("showDetail('CVE-2026-0001')");
  const body = d.el('modal-body').innerHTML;
  const order = DETAIL_SECS.map(id => body.indexOf(`id="${id}"`));
  assert.ok(order.every(i => i >= 0), `섹션 모두 있음 ${order}`);
  assert.deepEqual(order, [...order].sort((a, b) => a - b), '확인된 사실 → 조치 · 제품 → 접어 둔 항목 → AI');
  for (const id of ['d-lifecycle', 'd-evidence', 'd-tech', 'd-ai']) {
    assert.match(body, new RegExp(`<details class="d-sec d-fold[^"]*" id="${id}">`), `${id} 는 접어 둔다`);
  }
  assert.doesNotMatch(body, /<details[^>]* open/, '처음에는 모두 접혀 있다');
  const sec = id => detailSec(body, id);
  assert.match(sec('d-threat'), /yes-row ans-exploitation[\s\S]*?CISA KEV 등재/);
  assert.match(sec('d-threat'), /yes-row ans-weaponization[\s\S]*?Metasploit 모듈 1개/);
  assert.match(sec('d-threat'), /yes-row ans-ransomware/);
  assert.match(sec('d-threat'), /yes-row ans-detection[\s\S]*?Sigma/, '탐지 룰도 위협 신호 안에');
  assert.doesNotMatch(sec('d-threat'), /yes-row ans-remediation/, 'OSV 기록이 없으면 확인된 줄에 없다');
  assert.match(sec('d-threat'), /없음 0 · 미확인 3/, '없음 · 미확인은 한 줄로 접는다');
  assert.match(sec('d-threat'), /st-chip st-unknown[^>]*>수정 버전 <b>미확인<\/b>/, 'OSV 기록 없음 → 미확인');
  assert.match(sec('d-threat'), /class="ctx-chip" data-query="has:cisa-kev has:ransom"/, '신호 조합 → 같은 조건 목록');
  assert.match(sec('d-threat'), /ev-row ev-hit[\s\S]*?CISA KEV[\s\S]*?조치 기한 2026-10-10/);
  assert.match(sec('d-threat'), /ev-row ev-miss[\s\S]*?VulnCheck KEV/);
  assert.match(sec('d-threat'), /ev-row ev-unknown[\s\S]*?CISA SSVC[\s\S]*?판정 없음/);
  assert.match(sec('d-threat'), /id="d-ev-detection"[\s\S]*?Sigma/);
  assert.match(sec('d-product'), /Windows 11 version 22H3[\s\S]*?연결 안 됨/, '22H3 은 연결하지 않는다');
  assert.match(sec('d-product'), /제품명 규칙 · 자동 연결/);
  assert.match(sec('d-product'), /microsoft:windows_server_2019/, '정규화 키(CPE 형식) — CPE 원문이 아님을 밝힌다');
  assert.match(sec('d-product'), /<summary>제품 1개 더 보기<\/summary>/, '셋이 넘으면 접는다');
  assert.match(sec('d-lifecycle'), /Microsoft Windows Server[\s\S]*<b>2019<\/b>/);
  assert.match(sec('d-lifecycle'), /사유: 수명주기를 추적하지 않는 제품/);
  assert.match(sec('d-remedy'), /CISA KEV 필요 조치 · 기한 2026-10-10 \(13일 남음\)/);
  assert.match(sec('d-evidence'), /EXPLOITATION_CONFIRMED=yes/);
  assert.match(sec('d-evidence'), /RANSOMWARE=yes/);
  assert.match(sec('d-evidence'), /KEV_RANSOMWARE/);
  assert.match(sec('d-evidence'), /endoflife\.date/);
  assert.match(sec('d-evidence'), /신호별 관측 시각은 저장하지 않습니다/);
  assert.match(sec('d-tech'), /원문 파일\(cve-facts\.json\)을 받는 중/, '원문을 아직 못 받았으면 받는 중이라고 적는다');
  assert.match(sec('d-ai'), /AI 작성 · 참고용/);
  assert.match(sec('d-ai'), /AI-ROOT-CAUSE-TEXT/);
  const beforeAi = body.slice(0, body.indexOf('id="d-ai"'));
  assert.doesNotMatch(beforeAi, /AI-ROOT-CAUSE-TEXT|AI-STEP/, 'AI 분석은 사실 · 판정 칸에 섞이지 않는다');
  assert.match(d.el('modal-sev-badge').innerHTML, /Argus · 관측된 악용/, '알림 등급은 Argus 판정으로 표기');
  assert.match(d.el('modal-summary').innerHTML, /origin-tag[^>]*>제목 번역 · 요약 원문</,
               '원문 파일 전에는 글자로만 판단 — 한국어 제목은 번역, 영문 요약은 원문');
  const facts = d.el('modal-scores').innerHTML;
  assert.match(facts, /CVSS 3\.1<\/span><span class="vl">9\.8 <span class="band band-Critical">Critical/);
  assert.match(facts, /CISA KEV 등재<\/span><span class="vl"><span class="vl-unknown">불러오는 중<\/span>/, '등재일 파일을 받기 전');
  assert.match(facts, /조치 기한 2026-10-10 \(13일 남음\)/);
  assert.equal(d.el('detail-origin').textContent, '대시보드', '돌아가기 = 들어오기 전 화면');
});

test('상세 — 원문(cve-facts) · 원 출처 날짜(cve-evidence)가 있으면 출처와 함께 보인다', () => {
  const d = dashboard();
  d.ctx.__files = {
    facts: { schema: 1, generated_at: '2026-09-27T03:00:00+00:00', facts: {
      'CVE-2026-0001': { o: ['ai', 'ai'], t: 'Windows RCE original title', d: 'Original English description.', a: 'microsoft' },
      'CVE-2026-0003': { o: ['source', 'ai'] } } },
    evidence: { schema: 1, generated_at: '2026-09-27T03:10:00Z', sources: { 'cisa-kev': { catalog_version: '2026.09.26' } },
      actions: ['Apply mitigations per vendor instructions.'],
      kev: { 'CVE-2026-0001': ['2026-09-01', '2026-10-10', 0, ['https://example.com/advisory'], 'Microsoft Windows RCE'] },
      edb: { 'CVE-2026-0002': [['51234', '2026-09-10', '2026-09-11', 1, 'remote', 'windows']] },
      msf: { 'CVE-2026-0001': [['exploit/windows/http/example_rce', 600, '2026-08-30', 'exploit', 1]] } },
  };
  d.run('detailFiles.facts = __files.facts; detailFiles.evidence = __files.evidence;');
  d.run("showDetail('CVE-2026-0001')");
  const body = d.el('modal-body').innerHTML;
  assert.match(d.el('modal-scores').innerHTML, /CISA KEV 등재<\/span><span class="vl">2026-09-01/);
  assert.match(detailSec(body, 'd-threat'), /KEV 등재일 <b>2026-09-01<\/b>/);
  assert.match(detailSec(body, 'd-threat'), /필요 조치 \(CISA 원문\): Apply mitigations per vendor instructions\./);
  assert.match(detailSec(body, 'd-threat'), /exploit\/windows\/http\/example_rce<\/code> · 등급 excellent · check 지원 · 취약점 공개일 2026-08-30/);
  assert.match(detailSec(body, 'd-remedy'), /Apply mitigations per vendor instructions\./);
  assert.match(detailSec(body, 'd-evidence'), /2026-09-01<small>KEV 등재일<\/small>/, '원 출처 날짜 칸');
  assert.match(detailSec(body, 'd-evidence'), /cve-evidence\.json 생성 시각/);
  assert.match(detailSec(body, 'd-tech'), /lang="en">Windows RCE original title<\/span><span class="origin-tag is-source"/);
  assert.match(detailSec(body, 'd-tech'), /CNA \(발급 기관\)<\/span><span class="detail-value">microsoft/);
  assert.match(d.el('modal-summary').innerHTML, />AI 번역·요약</);
  d.run("showDetail('CVE-2026-0002')");
  const b2 = d.el('modal-body').innerHTML;
  assert.match(detailSec(b2, 'd-threat'), /EDB-51234 ↗<\/a> · 공개 2026-09-10 · 검증됨 · remote\/windows/);
  assert.match(detailSec(b2, 'd-evidence'), /2026-09-10<small>Exploit-DB 공개일 \(가장 이른 항목\)<\/small>/);
  assert.match(detailSec(b2, 'd-tech'), /이 CVE는 원문 파일에 아직 없습니다/, '파일은 받았지만 이 CVE 는 없음');
  d.run("showDetail('CVE-2026-0003')");
  assert.match(d.el('modal-summary').innerHTML, />제목 원문 · 요약 AI 번역</);
  d.run('detailFiles.facts = null;');
  d.run("showDetail('CVE-2026-0001')");
  assert.match(detailSec(d.el('modal-body').innerHTML, 'd-tech'), /원문 파일\(cve-facts\.json\)을 받지 못했습니다/);
});

test('출처 간 차이 — 어느 쪽도 지우지 않고 목록 · 상세 · 검색어가 같은 판단', () => {
  const d = dashboard();
  d.run(`Object.assign(allCves.find(c => c.id === 'CVE-2026-0010'), { ssvc_exploitation: 'none', cvss_alt: { '4.0': 6.9, '3.1': 9.9 } });`);
  assert.deepEqual(search(d, 'conflict:exploitation'), [cve(10)]);
  assert.deepEqual(search(d, 'conflict:cvss'), [cve(10)]);
  assert.deepEqual(search(d, 'conflict:any'), [cve(10)]);
  assert.deepEqual(search(d, 'has:conflict'), [cve(10)]);
  filterIds(d, "activeFilters.search = 'conflict:any';");
  assert.match(d.el('cve-table-body').innerHTML, /class="sc-flag"/, '목록 CVSS 칸에 등급 차이 표시');
  d.run("showDetail('CVE-2026-0010')");
  const threat = detailSec(d.el('modal-body').innerHTML, 'd-threat');
  assert.match(threat, /class="d-flag"><b>출처 간 차이<\/b> KEV에는 있는데 CISA SSVC 판정은 Exploitation: active가 아님/, '악용 근거 차이는 접지 않고 보인다');
  assert.match(threat, /출처 간 차이: 악용 근거[\s\S]*?CISA KEV 등재[\s\S]*?CISA SSVC Exploitation: none/);
  assert.match(threat, /출처 간 차이: CVSS[\s\S]*?CVSS 4\.0 6\.9 \(Medium\)[\s\S]*?CVSS 3\.1 9\.9 \(Critical\)/);
  assert.match(threat, /data-query="conflict:exploitation"/);
  assert.match(d.el('modal-scores').innerHTML, /class="warn"[^>]*>v4\.0은 6\.9 Medium</, '버전별 등급 차이는 머리글 수치에');
});

test('화면 전환 — 좁은 화면: 상세는 한 화면, URL 의 cve, 닫으면 들어오기 전 화면으로', () => {
  const d = dashboard();
  d.run('innerWidth = 900;');
  d.run("switchView('cves')");
  filterIds(d, "activeFilters.search = 'has:poc';");
  d.run("showDetail('CVE-2026-0003')");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.run('splitOpen'), false, '1200px 미만은 나란히 보기를 쓰지 않는다');
  assert.match(d.run('history.last'), /cve=CVE-2026-0003/);
  assert.match(decodeURIComponent(d.run('history.last')), /view=cves&q=has:poc/, '목록 맥락은 URL 에 남긴다');
  assert.doesNotMatch(d.run('history.last'), /full=1/, 'full 은 넓은 화면에서만');
  assert.equal(d.el('side-detail').disabled, false);
  assert.equal(d.el('side-detail-id').textContent, 'CVE-2026-0003');
  assert.equal(d.el('detail-origin').textContent, 'CVE 목록');
  d.run('closeModal()');
  assert.equal(d.run('currentView'), 'cves');
  assert.doesNotMatch(d.run('history.last'), /cve=/);
  d.run("switchView('dashboard'); openCve('CVE-2026-0002')");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('detail-pos').textContent, '', '대시보드에서 하나만 열면 이전 · 다음 없음');
  d.run('closeModal()');
  assert.equal(d.run('currentView'), 'dashboard', '대시보드에서 열었으면 대시보드로');
  assert.doesNotMatch(d.run('history.last'), /view=|cve=/);
  d.run("location.href = 'https://example.test/cve.html?view=cves&q=has%3Akev&cve=CVE-2026-0004'; applyUrlState(); openFromUrl();");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('modal-id').textContent, 'CVE-2026-0004');
  assert.equal(d.run('activeFilters.search'), 'has:kev');
  d.run('closeModal()');
  assert.equal(d.run('currentView'), 'cves');
  d.run("location.href = 'https://example.test/cve.html?cve=CVE-2026-0003'; applyUrlState(); openFromUrl();");
  assert.equal(d.el('detail-pos').textContent, '', '공유 링크로 연 상세는 이전 · 다음 없음');
  assert.equal(d.el('detail-bottom').hidden, true, '넘길 CVE 가 없으면 아래 막대도 감춘다');
  d.run("location.href = 'https://example.test/cve.html?cve=CVE-1999-0001'; applyUrlState(); openFromUrl();");
  assert.match(d.el('modal-body').innerHTML, /추적 목록\(최근 90일/, '추적 밖 CVE 는 없다고 알린다');
});

test('나란히 보기 — 넓은 화면의 목록에서 상세를 오른쪽에 열고, 행을 바꿔도 기록을 늘리지 않는다', () => {
  const d = dashboard();
  trackHistory(d);
  d.run("goToQuery('has:poc')");
  const base = d.run('history.pushed.length');
  assert.deepEqual(d.run('filteredCves.map(c => c.id)'), [cve(14), cve(3)], '알림 등급 순');
  d.run("showDetail('CVE-2026-0003')");
  assert.equal(d.run('currentView'), 'cves', '목록은 그대로');
  assert.equal(d.run('splitOpen'), true);
  assert.equal(d.run('history.pushed.length'), base + 1, '처음 열 때만 기록');
  assert.match(decodeURIComponent(d.run('location.href')), /view=cves&q=has:poc&cve=CVE-2026-0003$/);
  assert.equal(d.el('detail-pos').textContent, '2 / 2');
  assert.equal(d.run('document.documentElement.dataset.nav'), 'rail', '1680px 미만에서는 메뉴를 아이콘으로 접는다');
  d.run('stepDetail(-1)');
  assert.equal(d.run('detailId'), cve(14));
  d.run("showDetail('CVE-2026-0003')");
  assert.equal(d.run('history.pushed.length'), base + 1, '이전 · 다음 · 다른 행은 기록을 늘리지 않는다');
  d.run('openFull()');
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.run('splitOpen'), false);
  assert.match(d.run('location.href'), /full=1/, '새로 고쳐도 한 화면으로');
  assert.equal(d.el('detail-pos').textContent, '2 / 2', '한 화면에서도 목록 순서로 이전 · 다음');
  d.run("location.href = 'https://example.test/cve.html?view=cves&q=has%3Apoc&cve=CVE-2026-0003'; onPopState({ state: null });");
  assert.equal(d.run('splitOpen'), true, '뒤로 가기로 나란히 보기에 돌아온다');
  d.run('detailPushed = false; closeModal()');
  assert.equal(d.run('splitOpen'), false);
  assert.equal(d.run('currentView'), 'cves');
  assert.doesNotMatch(d.run('location.href'), /cve=/);
  assert.equal(d.run('document.documentElement.dataset.nav'), undefined, '닫으면 메뉴를 다시 편다');
  d.run("localStorage.setItem('argus-nav', 'open'); showDetail('CVE-2026-0003')");
  assert.equal(d.run('document.documentElement.dataset.nav'), undefined, '사용자가 고른 메뉴 상태가 먼저');
});

test('방문 기록 — 대시보드 숫자 · 제품 순위 · 화면 이동은 기록을 남기고, 뒤로 가기는 주소대로 화면을 되돌린다', () => {
  const d = dashboard();
  trackHistory(d);
  d.run("goToQuery('has:cisa-kev')");
  assert.equal(d.run('currentView'), 'cves');
  assert.equal(d.run('history.pushed.length'), 1);
  assert.match(decodeURIComponent(d.run('history.pushed[0]')), /view=cves&q=has:cisa-kev/);
  d.run("switchView('dashboard', { push: true })");
  assert.equal(d.run('history.pushed.length'), 2);
  d.run("filterByProduct('Java SE')");
  assert.equal(d.run('history.pushed.length'), 3, '영향 제품 순위도 기록을 남긴다');
  assert.equal(d.run('activeFilters.product'), 'java se');
  d.run("location.href = 'https://example.test/cve.html'; onPopState({ state: { scroll: 0 } });");
  assert.equal(d.run('currentView'), 'dashboard');
  d.run("location.href = 'https://example.test/cve.html?view=cves&q=has%3Apoc'; onPopState({ state: { scroll: 120 } });");
  assert.equal(d.run('currentView'), 'cves');
  assert.equal(d.run('activeFilters.search'), 'has:poc');
  d.run("location.href = 'https://example.test/cve.html?view=cves&q=has%3Apoc&cve=CVE-2026-0003&full=1'; onPopState({ state: null });");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.run('splitOpen'), false);
  assert.equal(d.el('modal-id').textContent, 'CVE-2026-0003');
});

test('검색 미리보기 — 목록 밖에서는 화면을 옮기지 않고 결과를 보여 주며, Enter 를 눌러야 목록으로 간다', () => {
  const d = dashboard();
  trackHistory(d);
  d.run("renderSearchPreview('windows')");
  assert.equal(d.run('currentView'), 'dashboard', '입력만으로 화면을 옮기지 않는다');
  const ids = JSON.parse(JSON.stringify(d.run('previewState.ids')));
  assert.deepEqual([...ids].sort(), search(d, 'windows'), '미리보기 건수 = 그 검색어로 연 목록');
  const box = d.el('search-preview').innerHTML;
  assert.match(box, new RegExp(`CVE ${ids.length}건`));
  assert.match(box, new RegExp(`목록에서 ${ids.length}건 보기`));
  assert.equal((box.match(/class="sp-item"/g) || []).length, Math.min(5, ids.length));
  assert.equal(d.run('history.pushed.length'), 0, '미리보기는 기록을 남기지 않는다');
  d.run('openPreviewItem(0)');
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('detail-pos').textContent, `검색 "windows" · 1 / ${ids.length}`, '이전 · 다음은 검색 결과 순서');
  d.run("switchView('dashboard')");
  d.el('search-input').value = 'has:poc';
  d.run('submitSearch()');
  assert.equal(d.run('currentView'), 'cves');
  assert.equal(d.run('activeFilters.search'), 'has:poc');
  assert.match(decodeURIComponent(d.run('history.pushed[history.pushed.length - 1]')), /view=cves&q=has:poc/, 'Enter 는 기록을 남긴다');
  d.run("switchView('dashboard')");
  d.el('search-input').value = 'cve-2026-0003';
  d.run('submitSearch()');
  assert.equal(d.run('currentView'), 'detail', 'CVE ID 를 정확히 넣으면 그 상세');
  assert.equal(d.el('modal-id').textContent, 'CVE-2026-0003');
  d.run("switchView('cves'); renderSearchPreview('windows')");
  assert.equal(d.el('search-preview').hidden, true, '목록 화면에서는 입력하는 대로 목록이 거른다');
});

test('새 검색어 — sev · published · kev · due (기준일 = 데이터를 만든 시각의 UTC 날짜, Nd 는 기준일 포함 N일)', () => {
  const d = dashboard();
  edit(d, { 2: { published: '2026-09-21', kev_due_date: '2026-09-28' }, 3: { published: '2026-09-20' }, 4: { published: '2026-09-27' },
            5: { published: '2026-09-28' }, 10: { kev_due_date: '2026-09-29' }, 1: { kev_due_date: '2026-09-30' } });
  assert.equal(d.run('refDay()'), '2026-09-27');
  assert.deepEqual(search(d, 'sev:critical'), [cve(1), cve(7), cve(10)]);
  assert.deepEqual(search(d, 'sev:none'), [cve(5)], 'CVSS 점수 없음');
  assert.deepEqual(search(d, 'published:7d'), [cve(2), cve(4)], '09-21 ~ 09-27, 기준일 뒤 날짜는 넣지 않는다');
  assert.deepEqual(search(d, 'published:1d'), [cve(4)], '기준일 당일');
  assert.deepEqual(search(d, 'published:7'), [], '단위가 없으면 아무것도 통과시키지 않는다');
  assert.deepEqual(search(d, 'due:3d'), [cve(10)], 'CISA KEV 인 것만, 기준일부터 3일 안(09-27 ~ 09-29)');
  assert.deepEqual(search(d, 'kev:7d'), [], '등재일 파일(cve-evidence.json) 전에는 셀 수 없다');
  d.run(`detailFiles.evidence = { schema: 1, kev: { 'CVE-2026-0001': ['2026-09-21', '2026-10-10'], 'CVE-2026-0010': ['2026-09-20', '2026-09-29'] } };`);
  assert.deepEqual(search(d, 'kev:7d'), [cve(1)], 'CISA KEV 등재일 기준');
  assert.deepEqual(search(d, 'kev:30d'), [cve(1), cve(10)]);
});

test('대시보드 최근 동향 — 카드 숫자 = 그 검색어로 연 목록 건수, KPI 아래 변화도 같은 검색어로 센다', () => {
  const d = dashboard();
  edit(d, { 2: { published: '2026-09-21' }, 4: { published: '2026-09-27' }, 5: { published: '2026-09-25' },
            15: { severity: 'Critical', cvss: 9.1 }, 10: { kev_due_date: '2026-09-27' } });
  d.run('renderDashboard()');
  assert.match(d.el('dash-today').innerHTML, /KEV 신규 등재[\s\S]*?등재일 정보를 받는 중/, '등재일 파일 전');
  assert.match(d.el('dash-kpis').innerHTML, /id="stat-kev">2<\/span>\s*<span class="kpi-sub">악용 근거 전체 3건</, '변화를 셀 수 없으면 출처 건수');
  d.run(`detailFiles.evidence = { schema: 1, kev: { 'CVE-2026-0001': ['2026-09-22', '2026-10-10'], 'CVE-2026-0010': ['2026-09-26', '2026-09-27'] } };
    renderDashboard();`);
  const today = d.el('dash-today').innerHTML;
  const cards = [...today.matchAll(/data-card="(\w+)"[\s\S]*?class="t-n" data-query="([^"]+)"[^>]*>(\d+)</g)]
    .map(m => ({ key: m[1], q: unesc(m[2]), n: Number(m[3]) }));
  assert.deepEqual(cards.map(c => c.key), ['kev', 'crit', 'exp']);
  for (const c of cards) assert.equal(search(d, c.q).length, c.n, `${c.key}: ${c.q}`);
  assert.deepEqual(cards.map(c => c.n), [2, 1, 1]);
  const card = key => today.slice(today.indexOf(`data-card="${key}"`), today.indexOf('</article>', today.indexOf(`data-card="${key}"`)));
  assert.deepEqual([...card('kev').matchAll(/data-cve="([^"]+)"/g)].map(m => m[1]), [cve(10), cve(1)], '등재일 최신순');
  assert.match(card('kev'), /data-query="due:3d"[^>]*>조치 기한 3일 안 1건</);
  assert.match(card('kev'), /등재 09-26 ·<\/span><span class="t-key"><em class="t-due">기한 오늘<\/em>/, '조치 기한은 줄여도 남는 칸에');
  assert.match(card('kev'), />2건 모두 보기 →</);
  assert.match(card('crit'), /알림·갱신 5건 중/);
  assert.match(card('exp'), /최근 7일 공개 3건 중/);
  assert.match(card('exp'), /data-cve="CVE-2026-0002"/);
  d.run("openCveFrom('CVE-2026-0001', todayLists.kev)");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('detail-pos').textContent, 'KEV 신규 등재 · 2 / 2', '이전 · 다음은 그 카드의 순서');
  assert.equal(d.el('detail-origin').textContent, '대시보드');
  const kpis = d.el('dash-kpis').innerHTML;
  assert.match(kpis, /id="stat-total">16<\/span>\s*<span class="kpi-sub"><b class="kpi-up">\+3<\/b> 최근 7일 공개/);
  assert.equal(search(d, 'published:7d').length, 3);
  assert.match(kpis, /id="stat-kev">2<\/span>\s*<span class="kpi-sub"><b class="kpi-up">\+2<\/b> 최근 7일 등재/);
  assert.equal(search(d, 'kev:7d').length, 2);
  assert.match(kpis, /id="stat-24h">5<\/span>\s*<span class="kpi-sub">Critical 1 · KEV 0</);
  assert.match(kpis, /id="stat-ai">1<\/span>\s*<span class="kpi-sub"><b class="kpi-up">\+1<\/b> 최근 7일 공개/);
  assert.equal(search(d, 'published:7d has:ai').length, 1);
  d.run('detailFiles.evidence = null; renderDashboard();');
  assert.match(d.el('dash-today').innerHTML, /받지 못해 셀 수 없습니다[\s\S]*?data-query="has:cisa-kev"[^>]*>CISA KEV 전체 보기/,
               '등재일 파일을 못 받으면 0 대신 셀 수 없다고');
});

test('테마 — 시스템 → 라이트 → 다크 → 시스템, 고른 값은 저장', () => {
  const d = dashboard();
  const theme = () => d.run('currentTheme()');
  assert.equal(theme(), 'system');
  d.run('cycleTheme()');
  assert.equal(theme(), 'light');
  assert.equal(d.run("localStorage.getItem('argus-theme')"), 'light');
  assert.equal(d.el('theme-toggle').title, '테마: 라이트 (누르면 다크)');
  d.run('cycleTheme()');
  assert.equal(theme(), 'dark');
  d.run('cycleTheme()');
  assert.equal(theme(), 'system');
  assert.equal(d.run("localStorage.getItem('argus-theme')"), null);
});

test('상세 — 미확인의 사유 (점수 없음 · 추적 밖 제품 · endoflife.date 미제공 · 수정 기록 없음)', () => {
  const d = dashboard();
  d.run("showDetail('CVE-2026-0005')");
  assert.match(d.el('modal-scores').innerHTML, /점수 없음<\/span><\/span><span class="sub">0점이 아니라 미확인/);
  const b5 = d.el('modal-body').innerHTML;
  assert.match(b5, /class="none-card"[\s\S]*?확인된 위협 신호 없음[\s\S]*?7개 항목 중 없음 3 · 미확인 4/);
  assert.match(b5, /st-chip st-unknown" title="수명주기를 추적하지 않는 제품이 있음[^"]*">EOL <b>미확인<\/b>/, '미확인은 사유를 붙인다');
  assert.doesNotMatch(d.el('modal-signals').innerHTML, /c-none|lc-none/, '머리글에는 확인된 것만');
  d.run("showDetail('CVE-2026-0012')");
  assert.match(d.el('modal-body').innerHTML, /lc-unresolved[\s\S]*OpenSSH[\s\S]*사유: endoflife\.date에 없는 제품/);
  d.run("showDetail('CVE-2026-0003')");
  const b3 = d.el('modal-body').innerHTML;
  assert.match(b3, /st-chip st-no">수정 버전 <b>기록 없음<\/b>/);
  assert.match(detailSec(b3, 'd-remedy'), /OSV에 영향 패키지는 있지만 수정 버전 기록이 없습니다/);
});

test('Product Lifecycle — 제품 중심, 릴리스별 관찰된 위협, 필터·정렬', () => {
  const d = dashboard();
  const view = code => { d.run(`Object.assign(LC_VIEW, { status: '', window: '', linked: false, search: '', sort: 'cves' }); ${code}; renderLifecycleView();`); };
  const html = () => d.el('lc-products').innerHTML;
  const rows = () => (html().match(/<tr class="lc-cat-row/g) || []).length;
  view('');
  assert.equal(rows(), 35);
  const kpi = d.el('lc-kpis').innerHTML;
  const tile = s => Number(kpi.match(new RegExp(`lc-kpi-${s}[\\s\\S]*?kpi-value">(\\d+)<`))[1]);
  assert.deepEqual(['ACTIVE', 'SECURITY_SUPPORT', 'EXTENDED_SUPPORT', 'EOL', 'UNKNOWN'].map(tile), [14, 7, 5, 7, 2]);
  assert.match(d.el('lc-meta').textContent, /CVE 수가 아닙니다/);
  assert.match(html(), /data-query="release:windows\/7-sp1"[^>]*>CVE <b>1<\/b>/);
  assert.match(html(), /data-query="release:windows\/7-sp1 has:cisa-kev"[^>]*>KEV <b>1<\/b>/);
  // 릴리스마다 화면 숫자 = 누른 뒤 열리는 목록 건수
  const perRelease = Object.entries(d.run('liveAggregate().releases'));
  assert.ok(perRelease.length >= 5, `연결된 릴리스 ${perRelease.length}개`);
  for (const [key, t] of perRelease) {
    const q = `release:${key.replace('|', '/')}`;
    assert.equal(search(d, q).length, t.cves, q);
    assert.equal(search(d, `${q} has:cisa-kev`).length, t.kev, `${q} has:cisa-kev`);
    assert.equal(search(d, `${q} has:exploit`).length, t.exploit, `${q} has:exploit`);
    assert.equal(search(d, `${q} has:detection`).length, t.detection, `${q} has:detection`);
  }
  view("LC_VIEW.status = 'EOL'");
  assert.equal(rows(), 7);
  view("LC_VIEW.window = '30'");
  assert.equal(rows(), 2);
  view('LC_VIEW.linked = true');
  assert.equal(rows(), 21);
  view("LC_VIEW.search = 'windows'");
  assert.equal(rows(), 9);
  view("LC_VIEW.search = 'lifecycle:eol windows'");
  assert.equal(rows(), 1);
  view("LC_VIEW.search = 'eol:<180d'");
  assert.equal(rows(), 5);
  view("LC_VIEW.search = 'vendor:microsoft 2019'");
  assert.equal(rows(), 1);
  const firstProduct = () => (html().match(/<article class="lc-prod" data-slug="([^"]+)"/) || [])[1];
  view("LC_VIEW.sort = 'cves'");
  const prodStats = d.run('liveAggregate().products');
  const best = Object.entries(prodStats).sort((a, b) => b[1].cves - a[1].cves || (a[0] < b[0] ? -1 : 1))[0][0];
  assert.equal(firstProduct(), best, '연결 CVE 가 가장 많은 제품이 맨 위');
  view("LC_VIEW.sort = 'product'");
  assert.equal(firstProduct(), 'apache-http-server', '이름순');
  assert.match(d.el('lc-unavailable').innerHTML, /OpenSSH/);
});

test('내보내기 스키마는 그대로 — 파생 값을 CVE 행에 섞지 않는다', () => {
  const d = dashboard();
  filterIds(d, '');
  d.run('filteredCves.forEach(cveContext)');
  const json = d.run('JSON.stringify(filteredCves)');
  assert.doesNotMatch(json, /lifecycle|"entries"|"unresolved"|EXPLOITATION_CONFIRMED|correlations/);
  assert.equal(d.run('toCsv(filteredCves)').split('\n')[0], BASELINE.exports.csv.split('\n')[0]);
});
