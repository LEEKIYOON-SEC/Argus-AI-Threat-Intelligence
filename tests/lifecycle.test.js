'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const LC = require('../docs/js/lifecycle.js');
const { readJson } = require('./helpers/dashboard_vm');

const TODAY = '2026-09-27';
const ALIASES = require('../data/lifecycle_aliases.json');
const SAMPLE = readJson('lifecycle_sample.json');

const cycles = r => (r ? r.cycles.map(c => c.cycle) : null);

function synthetic() {
  const rel = (slug, cycle, extra) => Object.assign({
    product_slug: slug, cycle, release_date: '2020-01-01', support_end: null, support_ended: null,
    security_support_end: null, extended_support_end: null, extended_support_ended: null,
    eol_date: null, eol_reached: false, latest_version: null, lts: false,
  }, extra);
  const meta = (slug, label, cpe, purl, aliases) => ({
    slug, label, aliases: aliases || [], labels: { eoas: null, eol: 'Security Support', eoes: null },
    identifiers: { cpe: cpe || [], purl: purl || [] }, source_url: `https://endoflife.date/${slug}`,
  });
  return {
    products: {
      nginx: meta('nginx', 'nginx', ['cpe:2.3:a:f5:nginx']),
      mysql: meta('mysql', 'MySQL', ['cpe:2.3:a:oracle:mysql']),
      django: meta('django', 'Django', [], ['pkg:pypi/django', 'pkg:deb/debian/python-django']),
      'oracle-jdk': meta('oracle-jdk', 'Oracle JDK', ['cpe:/a:oracle:jdk', 'cpe:2.3:a:oracle:java_se']),
    },
    unavailable: [{ slug: 'openssh', name: 'OpenSSH', identifiers: { cpe: ['cpe:2.3:a:openbsd:openssh'] } }],
    releases: [
      rel('nginx', '1.27'), rel('nginx', '1.26', { eol_date: '2025-04-23', eol_reached: true }),
      rel('nginx', '1.25', { eol_date: '2024-05-29', eol_reached: true }),
      rel('mysql', '8.4'), rel('mysql', '8.0', { eol_date: '2026-04-30', eol_reached: true }),
      rel('mysql', '5.7', { eol_date: '2023-10-31', eol_reached: true }),
      rel('django', '5.1'), rel('django', '5.0', { eol_date: '2025-04-02', eol_reached: true }),
      rel('django', '4.2'),
      rel('oracle-jdk', '17'), rel('oracle-jdk', '8'), rel('oracle-jdk', '7'), rel('oracle-jdk', '1.4'),
    ],
  };
}

test('정상 lifecycle JSON 파싱 — 샘플을 읽어 제품·릴리스·미제공 목록을 만든다', () => {
  const m = LC.createMatcher(SAMPLE, ALIASES);
  assert.equal(Object.keys(m.products).length, 11);
  assert.equal(m.releasesBy.nginx.map(r => r.cycle).join(','), '1.31,1.30,1.26,1.25,1.24');
  assert.ok(m.unavailable.has('openssh'));
  assert.equal(LC.createMatcher(null, null).forCve([{ vendor: 'F5', product: 'nginx', versions: '1.25.0' }]).untracked, 1);
});

test('상태 계산이 src/update_lifecycle.py 와 같은 표를 따른다', () => {
  const table = readJson('lifecycle_status_cases.json');
  for (const c of table.cases) {
    const meta = { labels: table.labels[c.labels] };
    if (c.phase_status) meta.phase_status = c.phase_status;
    assert.equal(LC.statusOf(c.release, meta, table.today), c.expect, c.name);
  }
});

test('null 필드 처리 — 없는 날짜로 타임라인을 그리지 않고 단계명도 지어내지 않는다', () => {
  const meta = { labels: { eoas: 'Active Support', eol: 'Security Support', eoes: null } };
  const open = { release_date: '2026-01-01', support_end: null, support_ended: false, eol_date: null, eol_reached: false };
  assert.deepEqual(LC.timeline(open, meta).map(s => [s.status, s.to, s.open]), [['ACTIVE', null, true]]);
  assert.equal(LC.phaseLabel(open, meta, TODAY), 'Active Support');
  const unknown = { release_date: null, eol_date: null, eol_reached: null };
  assert.deepEqual(LC.timeline(unknown, meta), []);
  assert.equal(LC.phaseLabel(unknown, meta, TODAY), null);
  assert.equal(LC.statusOf(null, meta, TODAY), 'UNKNOWN');
  const esu = { release_date: '2013-11-25', support_end: '2018-10-09', support_ended: true, eol_date: '2023-10-10',
                eol_reached: true, extended_support_end: '2026-10-13', extended_support_ended: false };
  const esuMeta = { labels: { eoas: 'Active Support', eol: 'Security Support', eoes: 'Extended Security Updates' } };
  assert.deepEqual(LC.timeline(esu, esuMeta).map(s => s.status), ['ACTIVE', 'SECURITY_SUPPORT', 'EXTENDED_SUPPORT']);
  assert.equal(LC.phaseLabel(esu, esuMeta, TODAY), 'Extended Security Updates');
});

test('eol:<30d / <90d / <180d — 남은 일수는 오늘 이후 EOL 만 센다', () => {
  const rel = eol => ({ eol_date: eol });
  assert.equal(LC.daysUntil('2026-10-13', TODAY), 16);
  assert.equal(LC.daysUntil('2027-01-12', TODAY), 107);
  assert.ok(LC.eolWithin(rel('2026-10-13'), '<', 30, TODAY));
  assert.ok(!LC.eolWithin(rel('2027-01-12'), '<', 90, TODAY));
  assert.ok(LC.eolWithin(rel('2027-01-12'), '<', 180, TODAY));
  assert.ok(!LC.eolWithin(rel(TODAY), '<', 30, TODAY), 'EOL 당일은 이미 EOL');
  assert.ok(!LC.eolWithin(rel('2025-01-01'), '<', 30, TODAY), '지난 EOL 은 임박이 아니다');
  assert.ok(!LC.eolWithin(rel(null), '<', 30, TODAY), '날짜 없으면 임박으로 세지 않는다');
  assert.ok(LC.eolWithin(rel('2026-09-30'), '<=', 3, TODAY));
  assert.ok(!LC.eolWithin(rel('2026-09-30'), '<', 3, TODAY));
  assert.equal(LC.parseDays('30d'), 30);
  assert.equal(LC.parseDays('90'), 90);
  assert.equal(LC.parseDays('3m'), null);
  assert.equal(LC.parseDays('abc'), null);
});

test('버전 문자열 → 사이클 (parse_affected 형식)', () => {
  const nginx = SAMPLE.releases.filter(r => r.product_slug === 'nginx');
  const pick = (text, rels, opts) => {
    const ranges = LC.parseConstraints(text, opts);
    return ranges ? LC.cyclesFor(rels, ranges).map(r => r.cycle) : null;
  };
  assert.deepEqual(pick('1.25.0 부터 1.25.5 이전', nginx), ['1.25']);
  assert.deepEqual(pick('1.26.0 부터 1.26.3 이전, 1.24.0 부터 1.24.1 이하', nginx), ['1.26', '1.24']);
  assert.deepEqual(pick('1.26.2 이전', nginx), ['1.26', '1.25', '1.24'], '하한이 없으면 그 아래 사이클 전부');
  assert.deepEqual(pick('1.26 이전', nginx), ['1.25', '1.24'], '1.26.0 미만은 1.26 사이클을 포함하지 않는다');
  assert.deepEqual(pick('1.26 이하', nginx), ['1.26', '1.25', '1.24']);
  assert.deepEqual(pick('unspecified 부터 1.30.1 이전', nginx), ['1.30', '1.26', '1.25', '1.24']);
  assert.deepEqual(pick('1.30.0 부터 * 이전', nginx), ['1.31', '1.30']);
  assert.deepEqual(pick('1.25.3 (단일 버전)', nginx), ['1.25']);
  assert.deepEqual(pick('>= 1.24.0, < 1.25.2 (단일 버전)', nginx), ['1.25', '1.24']);
  assert.deepEqual(pick('1.25.5 and prior (단일 버전)', nginx), ['1.25', '1.24']);
  assert.deepEqual(pick('< 1.25.0 (단일 버전)', nginx), ['1.24']);
  assert.deepEqual(pick('1.24.0 to 1.25.1 (단일 버전)', nginx), ['1.25', '1.24']);
  assert.deepEqual(pick('1.24.0, 1.30.2 (단일 버전)', nginx), ['1.30', '1.24']);
  assert.deepEqual(pick('1.30.* 부터 1.30.9 이전', nginx), ['1.30']);
  assert.deepEqual(pick('1.24', nginx), ['1.24'], 'NVD CPE 에서 온 맨 버전');
  assert.deepEqual(pick('nginx 1.25.2 (단일 버전)', nginx, { label: 'nginx' }), ['1.25'], '제품 라벨 접두어는 떼어낸다');
  const php = SAMPLE.releases.filter(r => r.product_slug === 'php');
  assert.deepEqual(pick('8.1.* 부터 8.1.29 이전, 8.3.* 부터 8.3.8 이전', php), ['8.3', '8.1']);
  const debian = SAMPLE.releases.filter(r => r.product_slug === 'debian');
  assert.deepEqual(pick('11', debian), ['11']);
  assert.deepEqual(pick('11.0', debian), ['11']);
  const node = [{ cycle: '20' }, { cycle: '19' }, { cycle: '4' }];
  assert.deepEqual(pick('4.0 부터 4.* 이전, 19.0 부터 19.* 이전', node).sort(), ['19', '4']);
});

test('버전 문자열 — 판단할 수 없으면 null (UNKNOWN), 추정하지 않는다', () => {
  for (const text of ['정보 없음', '모든 버전', '', 'n/a (단일 버전)', 'unspecified (단일 버전)', '0 (단일 버전)',
    '1bc91a5ddf3eaea0e0ea957cccf3abdcfcace00e 부터 3fa58a6fbd1e9e5682d09cdafb08fba004cb12ec 이전, 5.18 (단일 버전)',
    'Fixed in OpenSSL 3.0.6 (Affected 3.0.0-3.0.5) (단일 버전)', '10.0.0 부터 publication 이전',
    'Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27 (단일 버전)', 'server_2003', 'R36 부터 R36 P3 이전']) {
    assert.equal(LC.parseConstraints(text), null, text);
  }
  assert.equal(LC.parseVersion('71b547f'), null, '짧은 git 해시');
  assert.deepEqual(LC.parseVersion('1.0.1n'), { nums: [1, 0, 1], wild: false, pre: false, post: true });
  assert.deepEqual(LC.parseVersion('7.4-rc1'), { nums: [7, 4], wild: false, pre: true, post: false });
  assert.deepEqual(LC.parseVersion('4.*'), { nums: [4], wild: true, pre: false, post: false });
});

test('버전 재작성 규칙 — Java 1.x 표기', () => {
  const m = LC.createMatcher(synthetic(), ALIASES);
  assert.deepEqual(cycles(m.matchItem('oracle', 'jdk', '1.7.0')), ['7']);
  assert.deepEqual(cycles(m.matchItem('oracle', 'jdk', '1.8.0_202')), ['8']);
  assert.deepEqual(cycles(m.matchItem('oracle', 'jdk', '1.4.2')), ['1.4']);
  assert.deepEqual(cycles(m.matchItem('Oracle', 'Java SE', '6u131 (단일 버전), 8u112 (단일 버전)')), ['8']);
  assert.deepEqual(cycles(m.matchItem('Oracle', 'Java SE', '17.0.1 (단일 버전)')), ['17']);
});

test('CVE → 제품 매칭 — CPE vendor:product', () => {
  const m = LC.createMatcher(SAMPLE, ALIASES);
  const r = m.matchItem('debian', 'debian linux', '11');
  assert.equal(r.slug, 'debian');
  assert.equal(r.via, 'cpe');
  assert.equal(r.key, 'debian:debian_linux');
  assert.deepEqual(cycles(r), ['11']);
  assert.deepEqual(cycles(m.matchItem('canonical', 'ubuntu linux', '22.04')), ['22.04']);
  assert.equal(m.matchItem('OpenBSD', 'OpenSSH', '9.8p1 이전').reason, 'unavailable', 'upstream 에 없는 제품은 UNKNOWN');
});

test('CVE → 제품 매칭 — PURL (언어 생태계만, 수정 버전 기준)', () => {
  const m = LC.createMatcher(synthetic(), ALIASES);
  const out = m.matchPackages({ Django: { PyPI: ['4.2.16', '5.1.1'], 'Debian:12': ['3:4.2.16-1'] } });
  assert.equal(out.length, 1, 'Debian 패키지는 백포트가 있어 upstream 사이클에 잇지 않는다');
  assert.equal(out[0].via, 'purl');
  assert.equal(out[0].basis, 'fixed');
  assert.deepEqual(cycles(out[0]).sort(), ['4.2', '5.1']);
  assert.deepEqual(m.matchPackages({ requests: { PyPI: ['2.32.0'] } }), []);
  const empty = LC.createMatcher(SAMPLE, ALIASES);
  assert.deepEqual(empty.matchPackages({ Django: { PyPI: ['4.2.16'] } }), [], '추적 제품에 언어 PURL 이 없으면 건너뛴다');
});

test('CVE → 제품 매칭 — vendor+product (제품명 일치 + 벤더 확인)', () => {
  const m = LC.createMatcher(SAMPLE, ALIASES);
  const r = m.matchItem('Apache Software Foundation', 'Apache HTTP Server', '2.4.0 부터 2.4.60 이전');
  assert.equal(r.slug, 'apache-http-server');
  assert.equal(r.via, 'vendor_product');
  assert.deepEqual(cycles(r), ['2.4']);
  assert.equal(m.matchItem('Linux', 'Linux', '6.1 부터 6.1.90 이전').via, 'vendor_product');
  assert.equal(m.matchItem('Acme', 'Apache HTTP Server', '2.4.1'), null, '벤더가 다르면 이름만으로 잇지 않는다');
  assert.equal(m.matchItem('kubernetes', 'ingress-nginx', '1.11.4 이하'), null);
});

test('별칭 — 벤더 별칭과 수동 override(문자열·객체·null)', () => {
  const m = LC.createMatcher(synthetic(), {
    vendor_aliases: { oracle_corporation: 'oracle' },
    overrides: {
      'oracle:mysql_server': 'mysql',
      'f5:nginx_open_source': 'nginx',
      'f5:nginx_plus': null,
      'acme:legacy_nginx': { product: 'nginx', cycles: ['1.25'] },
      'acme:odd:1.2.3': 'mysql',
    },
  });
  const mysql = m.matchItem('Oracle Corporation', 'MySQL Server', '5.7.39 and prior (단일 버전), 8.0.16 and prior (단일 버전)');
  assert.equal(mysql.via, 'override');
  assert.equal(mysql.key, 'oracle:mysql_server');
  assert.deepEqual(cycles(mysql), ['8.0', '5.7']);
  assert.deepEqual(cycles(m.matchItem('F5', 'NGINX Open Source', '1.25.0 부터 1.25.5 이전')), ['1.25']);
  assert.deepEqual(m.matchItem('F5', 'NGINX Plus', 'R36 부터 R36 P3 이전'), { denied: true, via: 'override', key: 'f5:nginx_plus' });
  assert.deepEqual(cycles(m.matchItem('Acme', 'Legacy NGINX', '정보 없음')), ['1.25']);
  assert.equal(m.matchItem('Acme', 'Odd', '1.2.3').slug, 'mysql', "3단 키 'vendor:product:version'");
  assert.equal(m.matchItem('Acme', 'Odd', '9.9.9'), null);
  assert.equal(LC.normPart('Windows Server 2008  Service Pack 2'), 'windows_server_2008_service_pack_2');
  assert.equal(LC.normPart('Red Hat, Inc.'), 'red_hat_inc');
  assert.equal(LC.normPart('Node.js'), 'node.js');
});

test('CVE → 제품 매칭 — 제품명 규칙 (Windows 에디션·SAC·RHEL)', () => {
  const m = LC.createMatcher(SAMPLE, ALIASES);
  const win = m.matchItem('Microsoft', 'Windows 11 version 24H2', '10.0.26100.0 부터 10.0.26100.9445 이전');
  assert.equal(win.via, 'pattern');
  assert.deepEqual(cycles(win), ['11-24h2-iot-lts', '11-24h2-e-lts', '11-24h2-e', '11-24h2-w']);
  assert.deepEqual(cycles(m.matchItem('Microsoft', 'Windows 10 Version 22H2', 'x')), ['10-22h2']);
  assert.deepEqual(cycles(m.matchItem('Microsoft', 'Windows Server 2019 (Server Core installation)', 'x')), ['2019']);
  assert.deepEqual(cycles(m.matchItem('Microsoft Corporation', 'Windows Server 2012 R2', 'x')), ['2012-r2']);
  assert.deepEqual(cycles(m.matchItem('Microsoft', 'Windows 7 Service Pack 1', 'x')), ['7-sp1']);
  assert.deepEqual(cycles(m.matchItem('Red Hat', 'Red Hat Enterprise Linux 9', '정보 없음')), ['9']);
  assert.equal(m.matchItem('Microsoft', 'Windows 11 version 22H3', 'x'), null, 'upstream 에 없는 이름');
  assert.equal(m.matchItem('Microsoft', 'Windows 7', 'x'), null, 'SP 가 없으면 RTM/SP1 을 가를 수 없다');
  assert.equal(m.matchItem('Red Hat', 'Red Hat Enterprise Linux 8.6 Advanced Mission Critical Update Support', '정보 없음'), null);
  assert.equal(m.matchItem('Microsoft', 'Windows Server 2008', '정보 없음'), null);
  const gone = m.matchItem('Microsoft', 'Windows 10 Version 1507', 'x');
  assert.equal(gone.reason, 'cycle_not_found', '샘플에 없는 사이클은 연결하지 않고 UNKNOWN');
});

test('확인 안 되는 연결은 UNKNOWN — 커널 git 범위, 추적 밖 버전', () => {
  const m = LC.createMatcher(SAMPLE, ALIASES);
  const kernel = m.matchItem('Linux', 'Linux', '1bc91a5ddf3eaea0e0ea957cccf3abdcfcace00e 부터 3fa58a6fbd1e9e5682d09cdafb08fba004cb12ec 이전, 5.18 (단일 버전)');
  assert.equal(kernel.slug, 'linux');
  assert.equal(kernel.reason, 'version_unparsed');
  assert.equal(m.matchItem('linux', 'linux kernel', '2.6.17').reason, 'out_of_range');
});

test('CVE 하나에 여러 제품·사이클 — 중복 제거, 미해결 제품 정리, 상태별 합계', () => {
  const m = LC.createMatcher(SAMPLE, ALIASES);
  const r = m.forCve([
    { vendor: 'Microsoft', product: 'Windows Server 2019', versions: 'x' },
    { vendor: 'Microsoft', product: 'Windows Server 2019 (Server Core installation)', versions: 'x' },
    { vendor: 'Microsoft', product: 'Windows 10 Version 22H2', versions: 'x' },
    { vendor: 'microsoft', product: 'windows', versions: '정보 없음' },
    { vendor: 'OpenBSD', product: 'OpenSSH', versions: '9.8p1 이전' },
    { vendor: 'Acme', product: 'Widget', versions: '1.0' },
  ], null);
  assert.deepEqual(r.entries.map(e => `${e.slug} ${e.rel.cycle}`), ['windows-server 2019', 'windows 10-22h2']);
  assert.deepEqual(r.unresolved.map(u => `${u.slug}:${u.reason}`), ['openssh:unavailable'],
    '같은 CVE 에서 사이클이 잡힌 제품(windows)의 미해결 항목은 따로 세지 않는다');
  assert.equal(r.untracked, 1);
  const s = LC.summarize(r, SAMPLE.products, TODAY);
  assert.deepEqual(s.counts, { ACTIVE: 0, SECURITY_SUPPORT: 1, EXTENDED_SUPPORT: 1, EOL: 0, UNKNOWN: 1 });
  assert.equal(s.known, 2);
  assert.ok(!LC.matchesStatus(s, 'UNKNOWN'));
  assert.ok(LC.matchesStatus(s, 'EXTENDED_SUPPORT'));
  const none = LC.summarize(m.forCve([{ vendor: 'Acme', product: 'Widget', versions: '1.0' }]), SAMPLE.products, TODAY);
  assert.ok(LC.matchesStatus(none, 'UNKNOWN'), '정보가 없으면 UNKNOWN — ACTIVE 로 두지 않는다');
  assert.ok(!LC.matchesStatus(none, 'ACTIVE'));
});

test('검색어 값 해석', () => {
  assert.equal(LC.queryStatus('eol'), 'EOL');
  assert.equal(LC.queryStatus('Security'), 'SECURITY_SUPPORT');
  assert.equal(LC.queryStatus('extended'), 'EXTENDED_SUPPORT');
  assert.equal(LC.queryStatus('active'), 'ACTIVE');
  assert.equal(LC.queryStatus('unknown'), 'UNKNOWN');
  assert.equal(LC.queryStatus('supported'), null);
  assert.equal(LC.queryStatus('toString'), null);
});
