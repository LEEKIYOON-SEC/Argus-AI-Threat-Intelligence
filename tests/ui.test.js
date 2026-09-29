'use strict';
// 화면 뼈대 — cve.html 구조 · 스크립트 순서 · 테마 토큰 · 라이선스 표 위치(INVARIANTS §9-1) · 모듈이 빠졌을 때의 동작.
process.env.TZ = 'UTC';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadDashboard, withFixture, filterIds } = require('./helpers/dashboard_vm');
const { rowIds } = require('./helpers/dashboard_scenarios');

const ROOT = path.resolve(__dirname, '..');
const HTML = fs.readFileSync(path.join(ROOT, 'docs', 'cve.html'), 'utf8');
const CSS = fs.readFileSync(path.join(ROOT, 'docs', 'css', 'style.css'), 'utf8');

test('cve.html — 화면마다 view-* 와 사이드바 항목이 있고, 스크립트는 의존 순서대로', () => {
  for (const v of ['dashboard', 'cves', 'detail', 'lifecycle', 'sources']) {
    assert.match(HTML, new RegExp(`id="view-${v}"`), `view-${v}`);
    assert.match(HTML, new RegExp(`class="view-tab[^"]*"[^>]*data-view="${v}"`), `사이드바 ${v}`);
  }
  const scripts = [...HTML.matchAll(/<script src="js\/([^"]+)"><\/script>/g)].map(m => m[1]);
  assert.deepEqual(scripts, ['lifecycle.js', 'context.js', 'entities.js', 'viewmodel.js', 'cve-dashboard.js', 'cve-detail.js',
                             'dashboard-view.js', 'lifecycle-view.js', 'sources-view.js']);
  for (const s of scripts) assert.ok(fs.existsSync(path.join(ROOT, 'docs', 'js', s)), s);
  assert.doesNotMatch(HTML, /chart\.js/, '예전 추이 차트 스크립트는 없앴다');
  // 기존 id — 회귀 도구 · 외부 링크가 쓰는 것
  for (const id of ['search-input', 'cve-table-body', 'page-info', 'prev-btn', 'next-btn', 'active-chips', 'filter-count', 'severity-dist',
                    'product-dist', 'modal-id', 'modal-title', 'modal-body', 'modal-scores', 'modal-signals', 'modal-sev-badge',
                    'stat-total', 'stat-kev', 'stat-weapon', 'stat-poc', 'stat-ai', 'stat-24h-sub', 'updated-time']) {
    assert.match(HTML, new RegExp(`id="${id}"`), id);
  }
  const ths = HTML.slice(HTML.indexOf('<table class="cve-table">'), HTML.indexOf('</thead>', HTML.indexOf('<table class="cve-table">')));
  assert.equal((ths.match(/<th[ >]/g) || []).length, 6, '목록 6칸 — CVE·알림 · 요약·영향 제품 · CVSS·EPSS · 위협 신호 · 지원 상태 · 탐지·수정');
  // 화면마다 설명 카드는 '설명' 버튼으로 연다 — 버튼이 가리키는 카드가 있어야 한다
  const helps = [...HTML.matchAll(/class="help-btn"[^>]*aria-controls="([^"]+)"[^>]*>([^<]+)</g)];
  assert.deepEqual(helps.map(m => m[2]), ['설명', '설명', '설명', '설명']);
  for (const [, id] of helps) assert.match(HTML, new RegExp(`class="help-card" id="${id}" hidden`), id);
  // 접어 둔 대시보드 칸 — 버튼마다 여는 패널이 있다
  for (const [, id] of HTML.matchAll(/class="fold-btn"[^>]*aria-controls="([^"]+)"/g)) assert.match(HTML, new RegExp(`id="${id}" hidden`), id);
});

test('하단은 늘 보이는 고지만, 출처별 이용 조건은 데이터 출처 화면 한 곳에 (INVARIANTS §9-1)', () => {
  const footer = HTML.slice(HTML.indexOf('<footer'), HTML.indexOf('</footer>'));
  assert.ok(footer.length > 0);
  assert.doesNotMatch(footer, /<details|<table/, '고지는 접지 않고, 조건 표는 하단에 두지 않는다');
  for (const notice of ['This product uses the NVD API but is not endorsed or certified by the NVD.',
                        'This product uses <a href="https://vulncheck.com/kev"', '>VulnCheck KEV</a>.',
                        'Copyright © 1999-2026, The MITRE Corporation.', 'Copyright 2020 endoflife.date contributors', 'FIRST.org']) {
    assert.ok(footer.includes(notice), notice);
  }
  assert.match(footer, /href="\?view=sources" onclick="openSources\(event\)"/, '조건은 데이터 출처 화면으로 보낸다');
  assert.doesNotMatch(footer, /Gemini|Gemma|Google AI Studio|무료 티어|Turso|Slack/, 'AI 도구 · 요금제 · 운영 구성은 싣지 않는다');
  const sources = HTML.slice(HTML.indexOf('id="view-sources"'), HTML.indexOf('</main>'));
  // 약관 원문 — cve.org 이용약관 문구 그대로(CVE™). 사본에 저작권 표기와 이 문구를 함께 실어야 한다.
  assert.ok(sources.includes("distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy."));
  assert.match(sources, /Copyright © 1999-2026, The MITRE Corporation\./);
  assert.match(sources, /Copyright \(c\) 2003-2026, Emerging Threats/, 'ET Open BSD 라이선스 전문');
  for (const gone of ['id="dash-coverage"', 'id="src-conflicts"', 'id="dash-quality"', 'source-license', 'openLicense', 'src-table']) {
    assert.ok(!HTML.includes(gone), `없앤 칸: ${gone}`);
  }
});

function block(css, start) {
  const i = css.indexOf(start);
  assert.ok(i >= 0, start);
  let depth = 0;
  for (let j = css.indexOf('{', i); j < css.length; j++) {
    if (css[j] === '{') depth++;
    else if (css[j] === '}' && --depth === 0) return css.slice(css.indexOf('{', i) + 1, j);
  }
  throw new Error(`닫히지 않은 블록 ${start}`);
}
const decls = body => body.replace(/\/\*[\s\S]*?\*\//g, '').split(';').map(x => x.trim().replace(/\s+/g, ' ')).filter(Boolean).sort();

test('테마 — 라이트 토큰 두 블록(OS 설정 · 테마 버튼)이 같고, 다크 기본값과 같은 이름을 덮는다', () => {
  const media = block(CSS, '@media (prefers-color-scheme: light) {\n  :root:not([data-theme="dark"])');
  const inner = block(media, ':root:not([data-theme="dark"])');
  const attr = block(CSS, ':root[data-theme="light"] {');
  assert.deepEqual(decls(inner), decls(attr));
  const root = decls(block(CSS, ':root {')).map(d => d.split(':')[0]);
  for (const d of decls(attr)) assert.ok(root.includes(d.split(':')[0]), `다크 기본값에도 있음: ${d}`);
  assert.match(block(CSS, ':root {'), /color-scheme: dark/);
  assert.match(attr, /color-scheme: light/);
});

test('뷰 모델 스크립트가 없어도 목록 · 검색 · 상세 머리글은 동작한다', () => {
  const d = withFixture(loadDashboard([{ file: 'docs/js/cve-dashboard.js' }, { file: 'docs/js/cve-detail.js' }, { file: 'docs/js/dashboard-view.js' }]));
  d.run('dataReady = true;');
  const ids = filterIds(d, "activeFilters.search = 'has:kev';");
  assert.deepEqual([...ids].sort(), ['CVE-2026-0001', 'CVE-2026-0004', 'CVE-2026-0010']);
  const html = d.el('cve-table-body').innerHTML;
  assert.deepEqual(rowIds(html), ids);
  assert.match(html, /class="c-none"[^>]*>미확인</, '판단 모듈이 없으면 없음이 아니라 미확인');
  d.run("showDetail('CVE-2026-0001')");
  assert.equal(d.el('modal-id').textContent, 'CVE-2026-0001');
  assert.match(d.el('modal-body').innerHTML, /id="d-product"[\s\S]*id="d-tech"/);
});
