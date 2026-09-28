'use strict';
// 증거 공개일(CI 사전 계산) · 출처 간 불일치 · 출처 단위 집계 · 동시 발생 · 일별 추이 · 최근 공개.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CTX = require('../docs/js/context.js');
const { build, buildEvidence, parseCsv, main } = require('../src/build_context.js');

const FIX = path.join(__dirname, 'fixtures');
const CACHE = path.join(FIX, 'rulesets');
const fx = name => JSON.parse(fs.readFileSync(path.join(FIX, name), 'utf8'));
const NOW = new Date('2026-09-27T12:00:00Z');
const IDS = new Set(fx('dashboard_cves.json').map(c => c.id));

const row = over => Object.assign({
  id: 'CVE-2026-9000', cvss: 7.5, epss: 0.02, epss_percentile: 0.5, is_kev: false, is_vulncheck_kev: false,
  ssvc_exploitation: null, ssvc_automatable: null, has_public_exploit: false, has_metasploit_module: false,
  has_poc: false, has_nuclei_template: false, rule_engines: [], has_official_rules: false, affected: [],
}, over);

test('CSV — 따옴표 · 쉼표 · 줄바꿈 · "" · CRLF', () => {
  const rows = parseCsv('a,b,c\r\n1,"x, ""y""\nz",3\r\n4,,6');
  assert.deepEqual(rows, [['a', 'b', 'c'], ['1', 'x, "y"\nz', '3'], ['4', '', '6']]);
});

test('증거 공개일 — 추적 중인 CVE 만, 파이프라인과 같은 CVE 매칭 · 순서', () => {
  const ev = buildEvidence(CACHE, IDS, NOW);
  assert.equal(ev.schema, 1);
  assert.deepEqual(Object.keys(ev.sources).sort(), ['cisa-kev', 'exploit-db', 'metasploit']);
  assert.equal(ev.sources['cisa-kev'].catalog_version, '2026.09.27');
  assert.ok(ev.sources['exploit-db'].fetched_at, '원 출처 파일 수신 시각을 남긴다');
  // KEV — 소문자 ID 도 잇고, 추적 밖(2019)은 싣지 않는다. 필요 조치 문구는 사전으로.
  assert.deepEqual(Object.keys(ev.kev).sort(), ['CVE-2026-0001', 'CVE-2026-0010']);
  const [added, due, action, notes, name] = ev.kev['CVE-2026-0001'];
  assert.equal(added, '2026-09-19');
  assert.equal(due, '2026-10-10');
  assert.equal(ev.actions.length, 1, '같은 문구는 한 번만');
  assert.match(ev.actions[action], /Apply mitigations/);
  assert.deepEqual(notes, ['https://msrc.example/advisory', 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001']);
  assert.equal(name, 'Fixture SMB Remote Code Execution');
  // Exploit-DB — 파일 순서 그대로(첫 항목 = 파이프라인이 링크로 쓰는 것), file 없는 행은 버린다.
  assert.deepEqual(ev.edb['CVE-2026-0002'].map(e => e[0]), ['1', '2']);
  assert.deepEqual(ev.edb['CVE-2026-0002'][1], ['2', '2026-09-10', '2026-09-11', 1, 'remote', 'linux']);
  assert.deepEqual(Object.keys(ev.edb).sort(), ['CVE-2026-0002', 'CVE-2026-0011'], 'file 없는 CVE-2026-0003 행은 없다');
  // Metasploit — rank 높은 순(파이프라인 metasploit_modules 와 같다)
  assert.deepEqual(ev.msf['CVE-2026-0001'].map(m => m[0]), ['exploit/windows/smb/fixture', 'auxiliary/scanner/smb/fixture_check']);
  assert.deepEqual(ev.msf['CVE-2026-0001'][0], ['exploit/windows/smb/fixture', 600, '2026-09-18', 'exploit', 1]);
  assert.equal(ev.msf['CVE-2019-0001'], undefined);
  // 플래그와 증거가 어긋나지 않는다 (fixture cves.json)
  for (const c of fx('dashboard_cves.json')) {
    assert.equal(!!ev.msf[c.id], !!c.has_metasploit_module, `${c.id} msf`);
    assert.equal(!!ev.edb[c.id], !!c.has_public_exploit, `${c.id} edb`);
    if (c._exploit_db_url && ev.edb[c.id]) assert.ok(c._exploit_db_url.endsWith(`/${ev.edb[c.id][0][0]}`), c.id);
  }
});

test('증거 공개일 — 캐시가 없으면 null, 일부만 있으면 있는 것만', () => {
  assert.equal(buildEvidence(path.join(FIX, 'no-such-cache'), IDS, NOW), null);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-cache-'));
  fs.copyFileSync(path.join(CACHE, 'cisa-kev.json'), path.join(dir, 'cisa-kev.json'));
  const ev = buildEvidence(dir, IDS, NOW);
  assert.deepEqual(Object.keys(ev.sources), ['cisa-kev']);
  assert.deepEqual(ev.edb, {});
});

test('CLI — 캐시가 있으면 cve-evidence.json 을 쓰고, 없으면 이월본을 건드리지 않는다', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-data-'));
  for (const [src, dst] of [['dashboard_cves.json', 'cves.json'], ['dashboard_stats.json', 'stats.json'],
                            ['dashboard_products.json', 'cve-products.json'], ['dashboard_packages.json', 'cve-packages.json'],
                            ['lifecycle_sample.json', 'lifecycle.json']]) {
    fs.copyFileSync(path.join(FIX, src), path.join(dir, dst));
  }
  const log = console.log;
  console.log = () => {};
  try {
    main(['--data-dir', dir, '--cache-dir', CACHE, '--today', '2026-09-27']);
    const ev = JSON.parse(fs.readFileSync(path.join(dir, 'cve-evidence.json'), 'utf8'));
    assert.ok(ev.kev['CVE-2026-0001']);
    fs.writeFileSync(path.join(dir, 'cve-evidence.json'), '{"carried":true}');
    main(['--data-dir', dir, '--cache-dir', path.join(dir, 'missing'), '--today', '2026-09-27']);
    assert.equal(fs.readFileSync(path.join(dir, 'cve-evidence.json'), 'utf8'), '{"carried":true}');
    assert.ok(!fs.readdirSync(dir).some(f => f.endsWith('.tmp')), '임시 파일이 남지 않는다');
  } finally {
    console.log = log;
  }
});

test('출처 간 불일치 — 어느 쪽도 지우지 않고 표시할 대상만 고른다', () => {
  assert.deepEqual(CTX.conflictsOf(row({ is_vulncheck_kev: true, ssvc_exploitation: 'none' })), ['EXPLOITATION_SSVC']);
  assert.deepEqual(CTX.conflictsOf(row({ is_kev: true, ssvc_exploitation: 'poc' })), ['EXPLOITATION_SSVC']);
  assert.deepEqual(CTX.conflictsOf(row({ is_kev: true, ssvc_exploitation: 'active' })), []);
  assert.deepEqual(CTX.conflictsOf(row({ is_kev: true, ssvc_exploitation: null })), [], 'SSVC 판정이 없으면 불일치가 아니라 모름');
  assert.deepEqual(CTX.conflictsOf(row({ ssvc_exploitation: 'none', has_poc: true })), ['EXPLOIT_SSVC']);
  assert.deepEqual(CTX.conflictsOf(row({ ssvc_exploitation: 'poc', has_poc: true })), [], 'SSVC poc 는 PoC 공개와 맞다');
  assert.deepEqual(CTX.conflictsOf(row({ cvss_alt: { '4.0': 6.9, '3.1': 7.3 } })), ['CVSS_VERSIONS']);
  assert.deepEqual(CTX.conflictsOf(row({ cvss_alt: { '4.0': 9.1, '3.1': 9.8 } })), [], '같은 구간이면 불일치 아님');
  assert.deepEqual(CTX.conflictsOf(row({ cvss_alt: { '4.0': 0, '3.1': 9.8 } })), [], '0 은 점수 없음이지 구간이 아니다');
  const all = CTX.conflictsOf(row({ is_vulncheck_kev: true, ssvc_exploitation: 'none', has_public_exploit: true,
                                    cvss_alt: { '4.0': 8.7, '3.1': 9.8 } }));
  assert.equal(CTX.conflictQuery(all, 'any'), true);
  assert.equal(CTX.conflictQuery(all, 'exploit'), true);
  assert.equal(CTX.conflictQuery(all, 'CVSS_VERSIONS'), true);
  assert.equal(CTX.conflictQuery([], 'any'), false);
  assert.equal(CTX.conflictQuery(all, 'bogus'), false);
  for (const c of CTX.CONFLICTS) assert.ok(c.rule && c.label, `${c.code} 에 규칙 문장이 있다`);
});

test('출처 단위 집계 · 동시 발생 · 일별 심각도 · 최근 공개 — CI 결과가 직접 센 값과 같다', () => {
  const inputs = { cves: fx('dashboard_cves.json'), stats: fx('dashboard_stats.json'), products: fx('dashboard_products.json'),
                   packages: fx('dashboard_packages.json'), lifecycle: fx('lifecycle_sample.json'),
                   aliases: require('../data/lifecycle_aliases.json') };
  const out = build(inputs, NOW);
  const cves = inputs.cves;
  const st = out.stats;
  assert.equal(st.sources.weaponized, cves.filter(c => c.has_metasploit_module || c.has_public_exploit).length);
  assert.equal(st.sources.poc, cves.filter(c => c.has_poc).length);
  assert.equal(st.sources.cisa_kev, cves.filter(c => c.is_kev).length);
  assert.equal(st.sources.ai_discovered, cves.filter(c => c.ai_discovered).length);
  // 동시 발생 — 행렬 칸 = 두 신호가 함께 yes 인 건수, 상관 카드와 같은 쌍은 같은 숫자
  assert.equal(st.cooccur['CISA_KEV|EOL_AFFECTED'], st.correlations.KEV_EOL);
  assert.equal(st.cooccur['CISA_KEV|PUBLIC_EXPLOIT'], st.correlations.KEV_PUBLIC_EXPLOIT);
  assert.equal(Object.keys(st.cooccur).length, (CTX.MATRIX.length * (CTX.MATRIX.length - 1)) / 2);
  // 일별 — export 의 daily_trend 와 같은 날짜 창(기준 시각의 UTC 날짜까지 30일), 공개일 × 심각도를 직접 센 값과 같다.
  // (fixture stats.json 의 daily_trend 는 손으로 줄인 값이라 기준으로 쓰지 않는다 — 실데이터 대조는 INVARIANTS §13)
  const days = CTX.trendDays(inputs.stats.generated_at, 30);
  assert.equal(st.daily.length, 30);
  assert.equal(st.daily[29].date, inputs.stats.generated_at.slice(0, 10));
  st.daily.forEach((d, i) => {
    assert.equal(d.date, days[i]);
    for (const s of CTX.SEVERITIES) {
      assert.equal(d[s], cves.filter(c => c.published === d.date && (c.severity || 'None') === s).length, `${d.date} ${s}`);
    }
  });
  assert.ok(st.daily.some(d => d.Critical > 0), 'fixture 에 창 안의 공개일이 있다');
  // 최근 공개 — 공개일 내림차순, 같은 날이면 Argus 시각(시간대가 달라도 시각으로) 순
  assert.equal(out.recent.length, 8);
  for (let i = 1; i < out.recent.length; i++) assert.ok(out.recent[i - 1].published >= out.recent[i].published);
  const mixed = CTX.recentOf([
    { id: 'CVE-A', published: '2026-09-01', date: '2026-09-01T10:00:00+09:00' },
    { id: 'CVE-B', published: '2026-09-01', date: '2026-09-01T02:00:00Z' },
    { id: 'CVE-C', published: '2026-08-31', date: '2026-09-02T00:00:00Z' },
    { id: 'CVE-D', published: '', date: '2026-09-03T00:00:00Z' },
  ], () => null);
  assert.deepEqual(mixed.map(r => r.id), ['CVE-B', 'CVE-A', 'CVE-C'], '01:00Z(=10:00+09:00) 보다 02:00Z 가 나중, 공개일 없는 건은 뺀다');
  assert.deepEqual(CTX.trendDays('2026-09-27T23:30:00+00:00', 3), ['2026-09-25', '2026-09-26', '2026-09-27']);
  assert.deepEqual(CTX.trendDays('bad', 3), []);
});
