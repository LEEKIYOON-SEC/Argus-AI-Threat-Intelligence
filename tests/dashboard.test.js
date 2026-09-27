'use strict';
process.env.TZ = 'UTC';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadDashboard, withFixture, readJson, filterIds, RESET } = require('./helpers/dashboard_vm');
const { collect, rowIds } = require('./helpers/dashboard_scenarios');
const { build } = require('../src/build_context.js');

const TODAY = '2026-09-27';
const ALIASES = require('../data/lifecycle_aliases.json');
const CORE = [{ file: 'docs/js/cve-dashboard.js' }, { file: 'docs/js/cve-detail.js' }, { file: 'docs/js/dashboard-view.js' }];
const FULL = [{ file: 'docs/js/lifecycle.js' }, { file: 'docs/js/context.js' }, ...CORE, { file: 'docs/js/lifecycle-view.js' }];

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

// 변경 전(0f68020) 기준과 의미로 비교한다 — 목록·상세는 새 화면이라 HTML 대신 행 ID 순서·ID·제목만.
// has:nuclei · has:edb · has:ransom · has:foo 는 기존 버그(전부 통과)를 고쳤으므로 아래에서 따로 확인한다.
const FIXED_BUGS = ['has:nuclei', 'has:edb', 'has:ransom', 'has:foo'];
function semantic(out) {
  const o = JSON.parse(JSON.stringify(out));
  o.ui.rows = rowIds(o.ui.rows);
  o.ui.emptyRows = /empty-state/.test(o.ui.emptyRows);
  for (const k of Object.keys(o.detail)) o.detail[k] = { id: o.detail[k].id, title: o.detail[k].title };
  for (const q of FIXED_BUGS) delete o.searches[q];
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

test('대시보드 — KPI 범위 표기 · 상관 카드 · 근거 커버리지 · 데이터 품질', () => {
  const d = dashboard();
  d.run('renderStats(); renderDashboard();');
  const kpis = d.el('dash-kpis').innerHTML;
  const kpi = label => Number((kpis.match(new RegExp(`${label}</div>\\s*<div class="kpi-value"[^>]*>([\\d,]+)<`)) || [])[1]);
  assert.equal(kpi('추적 중 CVE'), 16);
  assert.equal(kpi('CVSS 9.0 이상'), 3);
  assert.equal(kpi('CISA KEV'), 2);
  assert.equal(kpi('EOL 릴리스 영향 CVE'), 4);
  assert.match(kpis, /data-query="has:cisa-kev"/);
  assert.match(kpis, /CVSS 점수 없음 1건은 모름/, '모름을 따로 적는다');
  const corr = d.el('dash-corr').innerHTML;
  assert.equal((corr.match(/class="corr-card/g) || []).length, 10);
  assert.match(corr, /data-query="has:cisa-kev lifecycle:eol"[\s\S]*?corr-n">1</);
  assert.match(corr, /출처가 '있음'으로 표기한 것만/, '랜섬웨어처럼 "없음"이 없는 신호는 비율을 쓰지 않는다');
  const cov = d.el('dash-coverage').innerHTML;
  assert.equal((cov.match(/class="cov-row"/g) || []).length, 10);
  assert.match(cov, /data-query="unknown:high-epss"/);
  assert.match(cov, /data-query="no:patch"/);
  assert.match(d.el('dash-quality').innerHTML, /EPSS 미채점/);
  assert.match(d.el('dash-meta').innerHTML, /수명주기 기준일 <b>2026-09-27<\/b>/);
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

test('목록 — 의미별로 묶은 칸, 출처가 확인한 것만 칩, 모름은 모름으로', () => {
  const d = dashboard();
  filterIds(d, '');
  const html = d.el('cve-table-body').innerHTML;
  const row = id => html.split('<tr ').find(r => r.includes(`showDetail('${id}')`));
  assert.equal(rowIds(html).length, 16);
  assert.match(row(cve(1)), /ev-chip ev-exploit[^>]*>.*CISA KEV · 랜섬웨어/);
  assert.match(row(cve(2)), /ev-chip ev-weapon[^>]*>.*공개 exploit.*EDB/);
  assert.doesNotMatch(row(cve(2)), /ev-exploit/, 'nuclei · EDB 만으로 악용 근거가 되지 않는다');
  assert.match(row(cve(6)), /ev-chip ev-auto/);
  assert.match(row(cve(12)), /class="c-none"/);
  assert.match(row(cve(5)), /점수 없음/, 'CVSS 0 은 모름');
  assert.match(row(cve(16)), /미채점/, 'EPSS 0 은 모름');
  assert.deepEqual(['epssPct(0.99999, 1)', 'epssPct(0.99999, 2)', 'epssPct(1, 1)', 'epssPct(0.1234, 2)'].map(x => d.run(x)),
                   ['99.9', '99.99', '100.0', '12.34'], '1 미만 확률을 100% 로 반올림하지 않는다');
  assert.match(row(cve(8)), /d-row d-yes[^>]*><i>수정<\/i>버전 있음/);
  assert.match(row(cve(3)), /d-row d-no[^>]*><i>수정<\/i>기록 없음/);
  assert.match(row(cve(12)), /d-row d-unknown[^>]*><i>수정<\/i>모름/);
  assert.match(row(cve(14)), /lc-badge lc-ACTIVE[^>]*>ACTIVE<em>/, '수명주기는 릴리스 상태 + 사이클 이름');
  assert.match(row(cve(5)), /class="lc-none"/);
  assert.doesNotMatch(html, /badge-kev|badge-msf/, '예전 위협 배지 스타일을 쓰지 않는다');
  filterIds(d, "activeFilters.search = 'nomatch';");
  assert.match(d.el('cve-table-body').innerHTML, /colspan="6" class="empty-state"/);
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

test('상세 — 한눈에 · 근거 행렬 · 제품 → 수명주기 · 조치 · 탐지 · 출처 · AI 분리', () => {
  const d = dashboard();
  d.run(`allCves.find(c => c.id === 'CVE-2026-0001').analysis = { root_cause: 'AI-ROOT-CAUSE-TEXT', mitigation: ['AI-STEP'] };`);
  d.run("showDetail('CVE-2026-0001')");
  const body = d.el('modal-body').innerHTML;
  const order = ['d-answers', 'd-threat', 'd-product', 'd-lifecycle', 'd-remedy', 'd-detect', 'd-tech', 'd-source', 'd-ai']
    .map(id => body.indexOf(`id="${id}"`));
  assert.ok(order.every(i => i >= 0), `섹션 모두 있음 ${order}`);
  assert.deepEqual(order, [...order].sort((a, b) => a - b), '사실 → 파생 → AI 순서');
  const sec = id => body.slice(body.indexOf(`id="${id}"`), body.indexOf('</section>', body.indexOf(`id="${id}"`)));
  assert.match(sec('d-answers'), /ans ans-yes ans-exploitation/);
  assert.match(sec('d-answers'), /ans ans-unknown ans-remediation/, 'OSV 기록 없음 → 모름');
  assert.match(sec('d-answers'), /ans ans-yes ans-ransomware/);
  assert.match(sec('d-threat'), /ev-row ev-hit[\s\S]*?CISA KEV[\s\S]*?조치기한 2026-10-10/);
  assert.match(sec('d-threat'), /ev-row ev-miss[\s\S]*?VulnCheck KEV/);
  assert.match(sec('d-threat'), /ev-row ev-unknown[\s\S]*?CISA SSVC[\s\S]*?판정 없음/);
  assert.match(sec('d-product'), /Windows 11 version 22H3[\s\S]*?연결 없음/, '22H3 은 연결하지 않는다');
  assert.match(sec('d-product'), /제품명 규칙 · 자동 매칭/);
  assert.match(sec('d-product'), /microsoft:windows_server_2019/, '정규화 키(CPE 형식) — CPE 원문이 아님을 밝힌다');
  assert.match(sec('d-lifecycle'), /Microsoft Windows Server[\s\S]*<b>2019<\/b>/);
  assert.match(sec('d-lifecycle'), /사유: 수명주기 추적 대상 제품이 아님/);
  assert.match(sec('d-detect'), /Sigma/);
  assert.match(sec('d-source'), /EXPLOITATION_CONFIRMED=yes/);
  assert.match(sec('d-source'), /RANSOMWARE=yes/);
  assert.match(sec('d-source'), /KEV_RANSOMWARE/);
  assert.match(sec('d-source'), /endoflife\.date/);
  assert.match(sec('d-source'), /신호별 관측 시각은 저장되지 않습니다/);
  assert.match(sec('d-ai'), /AI-ROOT-CAUSE-TEXT/);
  const beforeAi = body.slice(0, body.indexOf('id="d-ai"'));
  assert.doesNotMatch(beforeAi, /AI-ROOT-CAUSE-TEXT|AI-STEP/, 'AI 분석은 사실·파생 섹션에 섞이지 않는다');
  assert.match(d.el('modal-sev-badge').innerHTML, /Argus 관측된 악용/, '알림 등급은 Argus 파생으로 표기');
});

test('상세 — 모름의 사유 (점수 없음 · 추적 밖 제품 · endoflife.date 미제공)', () => {
  const d = dashboard();
  d.run("showDetail('CVE-2026-0005')");
  assert.match(d.el('modal-scores').innerHTML, /점수 없음 — 0점이 아님/);
  const b5 = d.el('modal-body').innerHTML;
  assert.match(b5, /ans ans-unknown ans-lifecycle[\s\S]*?수명주기 추적 대상이 아닌 제품 포함/);
  assert.doesNotMatch(d.el('modal-signals').innerHTML, /c-none|lc-none/, '머리글에는 확인된 것만');
  d.run("showDetail('CVE-2026-0012')");
  assert.match(d.el('modal-body').innerHTML, /lc-unresolved[\s\S]*OpenSSH[\s\S]*사유: endoflife\.date 에 없는 제품/);
  d.run("showDetail('CVE-2026-0003')");
  assert.match(d.el('modal-body').innerHTML, /ans ans-no ans-remediation[\s\S]*?OSV 에 수정 버전 기록 없음/);
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
