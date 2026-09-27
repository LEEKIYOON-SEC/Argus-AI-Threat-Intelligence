'use strict';
process.env.TZ = 'UTC';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadDashboard, withFixture, readJson, filterIds, RESET } = require('./helpers/dashboard_vm');
const { collect } = require('./helpers/dashboard_scenarios');

const TODAY = '2026-09-27';
const ALIASES = require('../data/lifecycle_aliases.json');
const FULL = [{ file: 'docs/js/lifecycle.js' }, { file: 'docs/js/cve-dashboard.js' }, { file: 'docs/js/lifecycle-view.js' }];

function dashboard({ files = FULL, lifecycle = true } = {}) {
  const d = withFixture(loadDashboard(files));
  if (lifecycle) {
    d.ctx.__lc = [readJson('lifecycle_sample.json'), ALIASES];
    d.run(`setLifecycle(__lc[0], __lc[1]); lcToday = ${JSON.stringify(TODAY)};`);
  }
  return d;
}

// 새 열·새 섹션·빈 표 colspan(8→9)만 걷어내면 수명주기 이전 화면과 글자까지 같아야 한다.
function withoutLifecycle(value) {
  return JSON.parse(JSON.stringify(value, (k, v) => typeof v !== 'string' ? v : v
    .replace(/<td class="lc-cell">[\s\S]*?<\/td>\s*/g, '')
    .replace(/<section class="lc-section">[\s\S]*?<\/section>/g, '')
    .replace(/colspan="9"/g, 'colspan="8"')));
}

const BASELINE = readJson('dashboard_baseline.json').result;
const ids = arr => [...arr].sort();
const search = (d, q) => ids(filterIds(d, `activeFilters.search = ${JSON.stringify(q)};`));

test('회귀: 검색·필터·정렬·페이지·통계·상세·CSV/JSON/STIX 가 변경 전과 같다', () => {
  const now = withoutLifecycle(collect(dashboard()));
  for (const section of Object.keys(BASELINE)) {
    for (const key of Object.keys(BASELINE[section])) {
      assert.deepEqual(now[section][key], BASELINE[section][key], `${section}.${key}`);
    }
  }
});

test('회귀: 수명주기 데이터를 못 받아도 기존 동작이 같다', () => {
  const now = withoutLifecycle(collect(dashboard({ lifecycle: false })));
  assert.deepEqual(now, BASELINE);
});

test('회귀: 수명주기 스크립트가 없어도 대시보드가 동작한다', () => {
  const now = withoutLifecycle(collect(dashboard({ files: [{ file: 'docs/js/cve-dashboard.js' }], lifecycle: false })));
  assert.deepEqual(now, BASELINE);
});

test('회귀: 기존 has:* 문법 결과 (has:nuclei·edb·ransom 은 도입 때부터 전체 통과 — 별도 보고)', () => {
  const d = dashboard();
  const all = ids(BASELINE.searches['']);
  assert.deepEqual(search(d, 'has:kev'), ['CVE-2026-0001', 'CVE-2026-0004', 'CVE-2026-0010']);
  assert.deepEqual(search(d, 'has:msf'), ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0007', 'CVE-2026-0011']);
  assert.deepEqual(search(d, 'has:poc'), ['CVE-2026-0003', 'CVE-2026-0014']);
  assert.deepEqual(search(d, 'has:rules'), ['CVE-2026-0001', 'CVE-2026-0009']);
  assert.deepEqual(search(d, 'has:ai'), ['CVE-2026-0005']);
  assert.deepEqual(search(d, 'has:auto'), ['CVE-2026-0006']);
  assert.deepEqual(search(d, 'has:patched'), ['CVE-2026-0008']);
  for (const q of ['has:nuclei', 'has:edb', 'has:ransom']) assert.deepEqual(search(d, q), all, q);
});

test('lifecycle:<상태> — 영향 릴리스 중 하나라도 그 상태면 걸린다', () => {
  const d = dashboard();
  assert.deepEqual(search(d, 'lifecycle:eol'), ['CVE-2026-0002', 'CVE-2026-0003', 'CVE-2026-0007', 'CVE-2026-0010']);
  assert.deepEqual(search(d, 'lifecycle:extended'), ['CVE-2026-0001', 'CVE-2026-0006', 'CVE-2026-0010', 'CVE-2026-0011']);
  assert.deepEqual(search(d, 'lifecycle:security'), ['CVE-2026-0001', 'CVE-2026-0003', 'CVE-2026-0007', 'CVE-2026-0013', 'CVE-2026-0016']);
  assert.deepEqual(search(d, 'lifecycle:active'), ['CVE-2026-0008', 'CVE-2026-0009', 'CVE-2026-0014', 'CVE-2026-0015']);
  assert.deepEqual(search(d, 'lifecycle:unknown'), ['CVE-2026-0004', 'CVE-2026-0005', 'CVE-2026-0012'],
    '데이터 없음(0005)·사이클 특정 불가(0004)·endoflife.date 미제공(0012)');
  assert.deepEqual(search(d, 'LIFECYCLE:EOL'), search(d, 'lifecycle:eol'));
});

test('eol:<30d / <90d / <180d', () => {
  const d = dashboard();
  assert.deepEqual(search(d, 'eol:<30d'), ['CVE-2026-0014', 'CVE-2026-0015']);
  assert.deepEqual(search(d, 'eol:<90d'), ['CVE-2026-0014', 'CVE-2026-0015']);
  assert.deepEqual(search(d, 'eol:<180d'), ['CVE-2026-0014', 'CVE-2026-0015', 'CVE-2026-0016']);
  assert.deepEqual(search(d, 'eol:<=3d'), ['CVE-2026-0015']);
  assert.deepEqual(search(d, 'eol:<3d'), []);
});

test('기존 문법과 AND 로 결합된다', () => {
  const d = dashboard();
  assert.deepEqual(search(d, 'cvss:>=9 lifecycle:eol'), ['CVE-2026-0007', 'CVE-2026-0010']);
  assert.deepEqual(search(d, 'has:kev lifecycle:eol'), ['CVE-2026-0010']);
  assert.deepEqual(search(d, 'vendor:microsoft eol:<90d'), ['CVE-2026-0014']);
  assert.deepEqual(search(d, 'lifecycle:eol windows'), ['CVE-2026-0010']);
  d.run(RESET);
  d.run("activeFilters.search = 'lifecycle:security'; activeFilters.cvssMin = 7; activeFilters.signals.add('kev'); applyFilters();");
  assert.deepEqual(ids(d.run('filteredCves.map(c => c.id)')), ['CVE-2026-0001']);
});

test('잘못된 값은 조용히 전부 통과시키지 않는다', () => {
  const d = dashboard();
  assert.deepEqual(search(d, 'lifecycle:bogus'), []);
  assert.deepEqual(search(d, 'eol:soon'), []);
  assert.deepEqual(search(d, 'eol:<3m'), []);
});

test('수명주기 데이터가 없으면 전부 UNKNOWN 이고 다른 상태로 걸리지 않는다', () => {
  const d = dashboard({ lifecycle: false });
  assert.deepEqual(search(d, 'lifecycle:eol'), []);
  assert.deepEqual(search(d, 'lifecycle:unknown'), ids(BASELINE.searches['']));
});

test('목록 Lifecycle 칸 — 요약 배지, 데이터 없으면 대시', () => {
  const d = dashboard();
  const cell = id => d.run(`lifecycleCell(allCves.find(c => c.id === ${JSON.stringify(id)}))`);
  assert.match(cell('CVE-2026-0014'), /lc-badge lc-ACTIVE[^>]*>ACTIVE<b>×4<\/b>/);
  const c10 = cell('CVE-2026-0010');
  assert.ok(c10.indexOf('lc-EOL') < c10.indexOf('lc-EXTENDED_SUPPORT'), 'EOL 이 먼저');
  assert.match(cell('CVE-2026-0004'), /lc-badge lc-UNKNOWN[^>]*>UNKNOWN<b>×1<\/b>/);
  assert.match(cell('CVE-2026-0005'), /class="lc-none"/);
  assert.doesNotMatch(cell('CVE-2026-0010'), /badge-kev|badge-msf/, '위협 신호 배지 스타일을 쓰지 않는다');
  filterIds(d, '');
  const rows = d.el('cve-table-body').innerHTML;
  assert.equal((rows.match(/<td class="lc-cell">/g) || []).length, 16);
  filterIds(d, "activeFilters.search = 'nomatch';");
  assert.match(d.el('cve-table-body').innerHTML, /colspan="9"/, '빈 표는 9칸을 덮는다');
});

test('상세 모달 Product Lifecycle 섹션 — 사이클별 날짜, 없는 값은 -, 출처와 수집 시각', () => {
  const d = dashboard();
  d.run("showDetail('CVE-2026-0010')");
  const body = d.el('modal-body').innerHTML;
  const section = body.match(/<section class="lc-section">[\s\S]*?<\/section>/)[0];
  assert.match(section, /Microsoft Windows Server/);
  assert.match(section, /<b>2012-r2<\/b>/);
  assert.match(section, /2026-10-13/, '확장지원 종료');
  assert.match(section, /<b>7-sp1<\/b>/);
  assert.match(section, /href="https:\/\/endoflife\.date\/windows-server"/);
  assert.match(section, /원출처 정책/);
  assert.match(section, /수집 \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC/);
  assert.match(section, /class="lc-na"/);
  assert.match(section, /class="lc-tl"/);
  assert.ok(body.indexOf('lc-section') > body.indexOf('detail-grid'), '기존 상세 항목 뒤에 붙는다');
  d.run("showDetail('CVE-2026-0012')");
  assert.match(d.el('modal-body').innerHTML, /lc-unresolved[\s\S]*OpenSSH[\s\S]*endoflife\.date 에 없는 제품/);
  d.run("showDetail('CVE-2026-0005')");
  assert.match(d.el('modal-body').innerHTML, /수명주기 데이터가 없습니다 \(endoflife\.date 추적 대상 아님 → UNKNOWN\)/);
});

test('상세 모달 — 영향 제품이 여러 개면 제품·사이클별로 따로 보여준다', () => {
  const d = dashboard();
  d.run("showDetail('CVE-2026-0001')");
  const section = d.el('modal-body').innerHTML.match(/<section class="lc-section">[\s\S]*?<\/section>/)[0];
  assert.equal((section.match(/class="lc-group"/g) || []).length, 2);
  assert.match(section, /Microsoft Windows Server[\s\S]*<b>2019<\/b>/);
  assert.match(section, /Microsoft Windows[\s\S]*<b>10-22h2<\/b>/);
  assert.match(section, /그 밖의 영향 제품 항목 1개/, '22H3 은 연결하지 않는다');
});

test('CVE 화면 요약 줄 — 릴리스 수이지 CVE 수가 아님', () => {
  const d = dashboard();
  d.run('renderLifecycleStrip()');
  const html = d.el('lc-strip-stats').innerHTML;
  assert.equal(d.el('lc-strip').hidden, false);
  const count = label => Number((html.match(new RegExp(`${label} <b>(\\d+)</b>`)) || [])[1]);
  assert.equal(count('ACTIVE'), 7);
  assert.equal(count('SECURITY'), 5);
  assert.equal(count('EXTENDED'), 4);
  assert.equal(count('EOL'), 4);
  assert.equal(count('UNKNOWN'), 1);
  assert.equal(count('EOL까지 30일 미만'), 2);
  assert.equal(count('EOL까지 90일 미만'), 2);
  assert.equal(count('EOL까지 180일 미만'), 3);
});

test('Product Lifecycle 탭 — 상태·임박·연결·검색 필터와 통계', () => {
  const d = dashboard();
  const view = code => { d.run(`Object.assign(LC_VIEW, { status: '', window: '', linked: false, search: '', sort: 'default', dir: 1 }); ${code}; renderLifecycleView();`); };
  const rows = () => (d.el('lc-table-body').innerHTML.match(/<tr class="lc-cat-row">/g) || []).length;
  view('');
  assert.equal(rows(), 35);
  const kpi = d.el('lc-kpis').innerHTML;
  const tile = s => Number(kpi.match(new RegExp(`lc-kpi-${s}[\\s\\S]*?kpi-value">(\\d+)<`))[1]);
  assert.deepEqual(['ACTIVE', 'SECURITY_SUPPORT', 'EXTENDED_SUPPORT', 'EOL', 'UNKNOWN'].map(tile), [14, 7, 5, 7, 2]);
  assert.match(d.el('lc-meta').textContent, /CVE 수가 아닙니다/);
  view("LC_VIEW.status = 'EOL'");
  assert.equal(rows(), 7);
  view("LC_VIEW.window = '30'");
  assert.equal(rows(), 2);
  view("LC_VIEW.linked = true");
  assert.equal(rows(), 21);
  view("LC_VIEW.search = 'windows'");
  assert.equal(rows(), 9);
  view("LC_VIEW.search = 'lifecycle:eol windows'");
  assert.equal(rows(), 1);
  // linux 5.15(95일) · oracle-jdk 17(3일) · php 8.2(95일) · windows 11-24h2-w(16일) · windows-server 2016(107일)
  view("LC_VIEW.search = 'eol:<180d'");
  assert.equal(rows(), 5);
  view("LC_VIEW.search = 'vendor:microsoft 2019'");
  assert.equal(rows(), 1);
  // 행마다 "제품|사이클" — 정규식이 행 경계를 넘지 않도록 행 단위로 자른다
  const order = () => d.el('lc-table-body').innerHTML.split('<tr class="lc-cat-row">').slice(1)
    .map(row => row.match(/<b>([^<]*)<\/b>/g).slice(0, 2).map(b => b.replace(/<\/?b>/g, '')).join('|'));
  view("LC_VIEW.sort = 'eol'");
  let got = order();
  assert.equal(got.length, 35);
  assert.equal(got[0], 'Apache HTTP Server|2.2', 'EOL 이 가장 이른 릴리스(2017-07-11)가 맨 위');
  assert.deepEqual(got.slice(-3), ['Apache HTTP Server|2.4', 'nginx|1.31', 'nginx|1.30'], 'EOL 날짜가 없는 릴리스는 맨 뒤');
  view("LC_VIEW.sort = 'eol'; LC_VIEW.dir = -1");
  got = order();
  assert.equal(got[0], 'Microsoft Windows|11-24h2-iot-lts', '내림차순은 가장 늦은 EOL(2034-10-10)부터');
  assert.deepEqual(got.slice(-3), ['Apache HTTP Server|2.4', 'nginx|1.31', 'nginx|1.30'], '내림차순에서도 날짜 없는 릴리스는 맨 뒤');
  assert.match(d.el('lc-unavailable').innerHTML, /OpenSSH/);
});

test('내보내기 스키마는 그대로 — 수명주기 값을 CVE 행에 섞지 않는다', () => {
  const d = dashboard();
  filterIds(d, '');
  d.run("filteredCves.forEach(cveLifecycle)");
  const json = d.run('JSON.stringify(filteredCves)');
  assert.doesNotMatch(json, /lifecycle|"entries"|"unresolved"/);
  assert.equal(d.run('toCsv(filteredCves)').split('\n')[0], BASELINE.exports.csv.split('\n')[0]);
});
