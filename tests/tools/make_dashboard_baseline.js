#!/usr/bin/env node
'use strict';
// 사용: node tests/tools/make_dashboard_baseline.js <git-revision>
// 지정한 리비전의 docs/js/cve-dashboard.js 로 시나리오를 돌려 tests/fixtures/dashboard_baseline.json 을 만든다.
// 기존 동작을 일부러 바꿨을 때만 다시 만든다 — 그 밖에는 이 파일이 회귀 기준이다.
process.env.TZ = 'UTC';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { ROOT, FIXTURES, loadDashboard, withFixture } = require('../helpers/dashboard_vm');
const { collect } = require('../helpers/dashboard_scenarios');

const rev = process.argv[2];
if (!rev) {
  console.error('usage: node tests/tools/make_dashboard_baseline.js <git-revision>');
  process.exit(2);
}
const code = execFileSync('git', ['show', `${rev}:docs/js/cve-dashboard.js`], { cwd: ROOT, encoding: 'utf8' });
const dash = withFixture(loadDashboard([{ name: `${rev}:cve-dashboard.js`, code }]));
const baseline = { revision: execFileSync('git', ['rev-parse', '--short', rev], { cwd: ROOT, encoding: 'utf8' }).trim(),
                   node: process.version, result: collect(dash) };
const out = path.join(FIXTURES, 'dashboard_baseline.json');
fs.writeFileSync(out, JSON.stringify(baseline, null, 1) + '\n');
console.log(`baseline ← ${baseline.revision} → ${path.relative(ROOT, out)}`);
