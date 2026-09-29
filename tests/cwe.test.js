'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const CWE = require('../docs/js/cwe.js');
const DATA = require('../docs/js/cwe-data.js');

test('레코드의 CWE — NVD 표기는 빼고 대문자 번호로, 겹치면 한 번만', () => {
  assert.deepEqual(CWE.listOf(['cwe-79', 'NVD-CWE-noinfo', 'CWE-79', ' CWE-89 ', 'NVD-CWE-Other', null, 'CWE-x']),
    ['CWE-79', 'CWE-89']);
  assert.deepEqual(CWE.listOf(undefined), []);
  assert.equal(CWE.typeOf(['NVD-CWE-noinfo']), null);
  assert.equal(CWE.typeOf([]), null);
});

test('여러 개면 더 구체적인 것 — Variant › Base › Compound › Class › Pillar › 분류 · 폐기 · 모르는 번호', () => {
  assert.equal(CWE.pick(['CWE-200', 'CWE-89']), 'CWE-89', 'Class 보다 Base');
  assert.equal(CWE.pick(['CWE-284', 'CWE-200']), 'CWE-200', 'Pillar 보다 Class');
  assert.equal(CWE.pick(['CWE-352', 'CWE-200']), 'CWE-352', 'Class 보다 Compound');
  assert.equal(CWE.pick(['CWE-89', 'CWE-1321']), 'CWE-1321', 'Base 보다 Variant');
  assert.equal(CWE.pick(['CWE-399', 'CWE-284']), 'CWE-284', '분류(Category) 번호는 Pillar 보다도 뒤');
  assert.equal(CWE.pick(['CWE-1187', 'CWE-99999', 'CWE-707']), 'CWE-707', '폐기 · 모르는 번호는 맨 뒤');
  assert.equal(CWE.pick(['CWE-79', 'CWE-89']), 'CWE-79', '같은 수준이면 레코드에 먼저 적힌 것');
  assert.equal(CWE.pick(['CWE-89', 'CWE-79']), 'CWE-89');
  assert.equal(CWE.pick(['CWE-99999', 'CWE-99998']), 'CWE-99999');
});

test('이름 · 풀이 — 표에 있으면 Argus 가 쓴 이름과 한 줄 풀이', () => {
  assert.deepEqual(CWE.typeOf(['CWE-200', 'CWE-89']), {
    id: 'CWE-89', name: 'SQL 인젝션', explain: '입력값이 SQL 문에 섞여 데이터베이스 명령이 바뀌는 결함',
    en: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", category: false,
  });
  assert.equal(CWE.typeOf(['CWE-416']).name, 'Use-After-Free');
  assert.equal(CWE.typeOf(['CWE-79']).name, 'XSS');
  assert.equal(CWE.titleOf(CWE.typeOf(['CWE-89'])),
    "SQL 인젝션 — 입력값이 SQL 문에 섞여 데이터베이스 명령이 바뀌는 결함 (CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'))");
});

test('표에 없는 번호 — 공식 이름의 별칭 → 30자 이하 이름 → 번호, 지어내지 않는다', () => {
  const t = id => CWE.typeOf([id]);
  assert.equal(t('CWE-113').name, 'HTTP Request/Response Splitting', "따옴표 안 별칭 ('…')");
  assert.equal(t('CWE-25').name, 'Path Traversal', "'Path Traversal: …' 형태");
  assert.equal(t('CWE-908').name, 'Use of Uninitialized Resource', '30자 이하면 공식 이름 그대로');
  assert.equal(t('CWE-908').explain, '', '풀이는 지어내지 않는다');
  assert.equal(t('CWE-401').name, 'CWE-401', '길면 번호');
  assert.equal(CWE.titleOf(t('CWE-401')), 'CWE-401 (CWE-401 Missing Release of Memory after Effective Lifetime)');
  assert.equal(CWE.titleOf(t('CWE-908')), 'Use of Uninitialized Resource (CWE-908)', '이름과 같은 공식 이름은 한 번만');
  assert.deepEqual(t('CWE-99999'), { id: 'CWE-99999', name: 'CWE-99999', explain: '', en: '', category: false });
  assert.equal(CWE.titleOf(t('CWE-99999')), 'CWE-99999 (CWE-99999)');
});

test('분류(Category) · 폐기된 번호 — 구체적인 약점이 아님을 알린다', () => {
  const cat = CWE.typeOf(['CWE-399']);
  assert.equal(cat.name, 'Resource Management Errors');
  assert.equal(cat.category, true);
  assert.equal(CWE.titleOf(cat), 'Resource Management Errors — MITRE 분류 번호(구체적인 약점이 아님) (CWE-399)');
  const dep = CWE.typeOf(['CWE-1187']);
  assert.equal(dep.name, 'CWE-1187', "'DEPRECATED: …' 를 이름으로 쓰지 않는다");
  assert.equal(CWE.titleOf(dep), 'CWE-1187 (CWE-1187 DEPRECATED: Use of Uninitialized Resource)');
  assert.equal(CWE.typeOf(['CWE-1']).name, 'CWE-1', '폐기된 분류도 번호');
});

test('한국어 표 — 모든 번호가 현재 MITRE 목록의 살아 있는 약점이고 이름 · 풀이가 비어 있지 않다', () => {
  const ids = Object.keys(CWE.GLOSS);
  assert.ok(ids.length >= 80);
  assert.deepEqual(ids, [...ids].sort((a, b) => Number(a.slice(4)) - Number(b.slice(4))), '번호순');
  for (const id of ids) {
    const [name, explain] = CWE.GLOSS[id];
    const w = DATA.w[id.slice(4)];
    assert.ok(w, `${id} 가 MITRE 목록에 없다`);
    assert.notEqual(w[0], 'D', `${id} 는 폐기됐다`);
    assert.ok(name && name.length <= 30, `${id} 이름`);
    assert.ok(explain && explain.length <= 60, `${id} 풀이`);
    assert.doesNotMatch(explain, /['"]/, `${id} 풀이에 따옴표(title 속성 · 칩에서 깨지지 않게)`);
  }
});

test('MITRE 링크 · 판 번호', () => {
  assert.equal(CWE.link('CWE-89'), 'https://cwe.mitre.org/data/definitions/89.html');
  assert.equal(CWE.version, DATA.version);
  assert.match(CWE.version, /^\d+\.\d+/);
});
