#!/usr/bin/env node
'use strict';
// CVE 맥락 사전 계산 — docs/data 의 원본 파일로 docs/data/cve-context.json 을 만든다.
// 판정 규칙은 브라우저와 같은 docs/js/context.js · lifecycle.js 를 그대로 쓴다(다시 구현하지 않는다).
// 담는 것: CVE별 수명주기 매핑(비싼 조인) · 기준일 통계 · 입력 지문 · 데이터 품질 점검.
// CVE별 신호는 담지 않는다 — cves.json 필드에서 브라우저가 바로 계산하므로 중복만 늘어난다.
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const LC = require(path.join(ROOT, 'docs', 'js', 'lifecycle.js'));
const CTX = require(path.join(ROOT, 'docs', 'js', 'context.js'));

const SCHEMA = 1;

function readJson(dir, name, required) {
  const file = path.join(dir, name);
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (required) throw new Error(`${name}: 읽을 수 없음 (${e.code || e.message})`);
    console.log(`  ${name}: 없음 또는 읽을 수 없음 → 이 부분 없이 만든다`);
    return null;
  }
}

function readKevCatalog(cacheDir) {
  const file = path.join(cacheDir, 'cisa-kev.json');
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    const ids = new Set();
    for (const item of data.vulnerabilities || []) if (item && item.cveID) ids.add(String(item.cveID).toUpperCase());
    return ids.size ? ids : null;
  } catch (e) {
    return null;
  }
}

function productDecoder(index) {
  if (!index || !index.map) return cve => cve.affected || [];
  const at = (t, i) => (Number.isInteger(i) && i >= 0 && i < t.length ? t[i] : '');
  const v = index.vendors || [], p = index.products || [], s = index.versions || [];
  return cve => {
    const items = index.map[cve.id];
    if (!items) return cve.affected || [];
    return items.map(it => ({ vendor: at(v, it[0]), product: at(p, it[1]), versions: at(s, it[2]) }));
  };
}

function build(inputs, now) {
  const { cves, stats, products, packages, lifecycle, aliases, kevCatalog } = inputs;
  const today = now.toISOString().slice(0, 10);
  const pk = (packages && packages.packages) || {};
  const affectedOf = productDecoder(products);
  const matcher = lifecycle ? LC.createMatcher(lifecycle, aliases || {}) : null;
  const lcProducts = lifecycle ? lifecycle.products : null;

  const mapping = {};
  const items = [];
  for (const cve of cves) {
    const aff = affectedOf(cve);
    let lc = null;
    if (matcher) {
      const match = matcher.matchCve(aff, pk[cve.id]);
      const enc = LC.encodeMatch(match);
      if (enc) mapping[cve.id] = enc;
      lc = LC.reduceMatch(match);
    }
    const s = CTX.signals(cve, { packages: pk[cve.id], lifecycle: lc, products: lcProducts, today,
                                 affectedCount: aff.length });
    items.push({
      id: cve.id, states: s.states, correlations: CTX.correlationsOf(s.states),
      releases: lc ? lc.entries.map(e => `${e.slug}|${e.rel.cycle}`) : [],
      productOnly: !!lc && !lc.entries.length && lc.unresolved.length > 0,
    });
  }

  const quality = CTX.qualityChecks(cves, { packages: pk, lifecycle, kevCatalog });
  const total = stats && stats.cve ? stats.cve.total : null;
  quality.unshift({
    id: 'stats_total_mismatch', label: 'stats.json 총계와 cves.json 행 수 불일치',
    status: total === cves.length ? 'ok' : 'warn', count: total === cves.length ? 0 : 1,
    examples: total === cves.length ? [] : [`stats ${total} ≠ cves ${cves.length}`], note: '',
  });
  if (!kevCatalog) {
    quality.push({ id: 'kev_catalog', label: 'KEV 카탈로그 대조', status: 'skipped', count: 0, examples: [],
                   note: '이 실행에는 파이프라인 KEV 캐시(.cache/rulesets/cisa-kev.json)가 없어 건너뜀' });
  }

  return {
    schema: SCHEMA,
    generator: 'src/build_context.js',
    generated_at: now.toISOString(),
    as_of: today,
    inputs: CTX.fingerprint({ cves, stats, products, packages, lifecycle, aliases }),
    lifecycle: matcher ? mapping : null,
    stats: CTX.aggregate(items),
    quality,
  };
}

function parseArgs(argv) {
  const out = { dataDir: path.join(ROOT, 'docs', 'data'), out: null, today: null,
                cacheDir: process.env.ARGUS_CACHE_DIR || path.join(ROOT, '.cache', 'rulesets') };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--data-dir') out.dataDir = path.resolve(argv[++i]);
    else if (a === '--out') out.out = path.resolve(argv[++i]);
    else if (a === '--today') out.today = argv[++i];
    else if (a === '--cache-dir') out.cacheDir = path.resolve(argv[++i]);
    else throw new Error(`알 수 없는 인자: ${a}`);
  }
  out.out = out.out || path.join(out.dataDir, 'cve-context.json');
  return out;
}

function main(argv) {
  const args = parseArgs(argv);
  console.log('=== CVE 맥락 사전 계산 ===');
  const inputs = {
    cves: readJson(args.dataDir, 'cves.json', true),
    stats: readJson(args.dataDir, 'stats.json', true),
    products: readJson(args.dataDir, 'cve-products.json', false),
    packages: readJson(args.dataDir, 'cve-packages.json', false),
    lifecycle: readJson(args.dataDir, 'lifecycle.json', false),
    aliases: readJson(args.dataDir, 'lifecycle_aliases.json', false),
    kevCatalog: readKevCatalog(args.cacheDir),
  };
  if (!Array.isArray(inputs.cves) || !inputs.cves.length) throw new Error('cves.json 이 비었다');
  const now = args.today ? new Date(`${args.today}T12:00:00Z`) : new Date();
  if (isNaN(now)) throw new Error(`--today 형식 오류: ${args.today}`);

  const started = Date.now();
  const result = build(inputs, now);
  // docs/ 전체가 배포되므로 쓰다 실패한 임시 파일이 남으면 그대로 공개된다 — 지우고 실패로 끝낸다.
  const tmp = `${args.out}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(result));
    fs.renameSync(tmp, args.out);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) { /* 이미 없음 */ }
    throw e;
  }

  const st = result.stats;
  console.log(`  CVE ${st.total.toLocaleString()}건 · 수명주기 연결 ${st.lifecycle.mapped.toLocaleString()}건`
              + ` (사이클 ${st.lifecycle.cycle_level} · 제품만 ${st.lifecycle.product_only}) · 기준일 ${result.as_of}`);
  console.log('  상관: ' + Object.entries(st.correlations).map(([k, v]) => `${k} ${v}`).join(' · '));
  for (const q of result.quality) {
    if (q.status !== 'ok') console.log(`  품질 [${q.status}] ${q.label}: ${q.count}${q.note ? ` — ${q.note}` : ''}`);
  }
  const size = fs.statSync(args.out).size;
  console.log(`  → ${path.relative(ROOT, args.out)} (${(size / 1024).toFixed(0)} KB, ${Date.now() - started} ms)`);
  return 0;
}

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    console.error(`[!] 사전 계산 실패: ${e.message} — cve-context.json 을 쓰지 않는다 (브라우저가 직접 계산)`);
    process.exitCode = 1;
  }
}

module.exports = { build, productDecoder, readKevCatalog, parseArgs, main };
