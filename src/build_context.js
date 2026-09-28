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

/* ---------- 증거 공개일 (파이프라인이 받아 둔 원 출처 파일에서) ---------- */

// 파이프라인(src/fields.py CVE_RE)과 같은 규칙으로 CVE 를 찾는다 — 플래그와 증거 행이 어긋나지 않게.
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const cveIds = text => [...new Set((String(text || '').match(CVE_RE) || []).map(s => s.toUpperCase()))];

// RFC 4180 — 따옴표 안의 쉼표·줄바꿈·"" 이스케이프를 처리한다.
function parseCsv(text) {
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += ch;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

function cacheFile(cacheDir, name) {
  const file = path.join(cacheDir, name);
  try {
    return { text: fs.readFileSync(file, 'utf8'), fetched_at: fs.statSync(file).mtime.toISOString() };
  } catch (e) {
    return null;
  }
}

const EVIDENCE_SCHEMA = 1;
const EDB_MAX = 5;
const MSF_MAX = 5;

// ids: 추적 중인 CVE — 배포 파일은 대시보드에 있는 CVE 만 담는다.
function buildEvidence(cacheDir, ids, now) {
  // actions: KEV 필요 조치 문구 사전 — 1,728건이 46가지 문구를 되풀이한다(실측), kev 항목은 번호로 가리킨다.
  const out = { schema: EVIDENCE_SCHEMA, generator: 'src/build_context.js', generated_at: now.toISOString(),
                sources: {}, actions: [], kev: {}, edb: {}, msf: {} };
  const actionIndex = new Map();
  const kev = cacheFile(cacheDir, 'cisa-kev.json');
  if (kev) {
    try {
      const data = JSON.parse(kev.text);
      for (const v of data.vulnerabilities || []) {
        const id = String((v && v.cveID) || '').toUpperCase();
        if (!ids.has(id)) continue;
        const notes = (String(v.notes || '').match(/https?:\/\/[^\s;]+/g) || []).slice(0, 5);
        const action = String(v.requiredAction || '');
        if (!actionIndex.has(action)) { actionIndex.set(action, out.actions.length); out.actions.push(action); }
        out.kev[id] = [v.dateAdded || '', v.dueDate || '', actionIndex.get(action), notes, v.vulnerabilityName || ''];
      }
      out.sources['cisa-kev'] = { fetched_at: kev.fetched_at, catalog_version: data.catalogVersion || '',
                                  released: data.dateReleased || '', entries: (data.vulnerabilities || []).length };
    } catch (e) {
      console.log(`  cisa-kev.json 을 읽지 못함 (${e.message}) → KEV 공개일 없이 만든다`);
    }
  }
  const edb = cacheFile(cacheDir, 'exploitdb-files.csv');
  if (edb) {
    const rows = parseCsv(edb.text);
    const head = rows.shift() || [];
    const col = name => head.indexOf(name);
    const c = { id: col('id'), file: col('file'), pub: col('date_published'), added: col('date_added'),
                verified: col('verified'), type: col('type'), platform: col('platform'), codes: col('codes') };
    if (c.codes >= 0 && c.id >= 0) {
      let entries = 0;
      for (const r of rows) {
        if (!r[c.file]) continue;
        for (const id of cveIds(r[c.codes])) {
          if (!ids.has(id)) continue;
          const list = out.edb[id] || (out.edb[id] = []);
          if (list.length < EDB_MAX) {
            list.push([r[c.id] || '', r[c.pub] || '', r[c.added] || '', r[c.verified] === '1' ? 1 : 0,
                       r[c.type] || '', r[c.platform] || '']);
          }
        }
        entries++;
      }
      out.sources['exploit-db'] = { fetched_at: edb.fetched_at, entries };
    } else {
      console.log('  exploitdb-files.csv 의 열 이름이 예상과 다름 → Exploit-DB 공개일 없이 만든다');
    }
  }
  const msf = cacheFile(cacheDir, 'metasploit-modules.json');
  if (msf) {
    try {
      const data = JSON.parse(msf.text);
      let modules = 0;
      for (const meta of Object.values(data)) {
        const refs = (meta && meta.references) || [];
        const found = new Set();
        for (const ref of refs) if (typeof ref === 'string') for (const id of cveIds(ref.replace(/,/g, '-'))) found.add(id);
        if (!found.size) continue;
        modules++;
        for (const id of found) {
          if (!ids.has(id)) continue;
          (out.msf[id] || (out.msf[id] = [])).push([meta.fullname || meta.name || '', Number(meta.rank) || 0,
                                                     meta.disclosure_date || '', meta.type || '', meta.check ? 1 : 0]);
        }
      }
      // 파이프라인(metasploit_modules)처럼 rank 높은 순 — 자른 뒤가 아니라 정렬한 뒤 자른다.
      for (const [id, list] of Object.entries(out.msf)) out.msf[id] = list.sort((a, b) => b[1] - a[1]).slice(0, MSF_MAX);
      out.sources.metasploit = { fetched_at: msf.fetched_at, modules };
    } catch (e) {
      console.log(`  metasploit-modules.json 을 읽지 못함 (${e.message}) → Metasploit 공개일 없이 만든다`);
    }
  }
  return Object.keys(out.sources).length ? out : null;
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
  const { cves, stats, products, packages, lifecycle, aliases, kevCatalog, evidence } = inputs;
  const today = now.toISOString().slice(0, 10);
  const pk = (packages && packages.packages) || {};
  const affectedOf = productDecoder(products);
  const matcher = lifecycle ? LC.createMatcher(lifecycle, aliases || {}) : null;
  const lcProducts = lifecycle ? lifecycle.products : null;

  const mapping = {};
  const items = [];
  const contexts = new Map();
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
    const ctx = { states: s.states, correlations: CTX.correlationsOf(s.states) };
    contexts.set(cve.id, ctx);
    items.push(CTX.aggregateItem(cve, ctx, lc));
  }

  const quality = CTX.qualityChecks(cves, { packages: pk, lifecycle, kevCatalog, evidence });
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
    stats: CTX.aggregate(items, { days: CTX.trendDays(stats && stats.generated_at, 30) }),
    recent: CTX.recentOf(cves, cve => contexts.get(cve.id)),
    quality,
  };
}

function parseArgs(argv) {
  const out = { dataDir: path.join(ROOT, 'docs', 'data'), out: null, evidenceOut: null, today: null,
                cacheDir: process.env.ARGUS_CACHE_DIR || path.join(ROOT, '.cache', 'rulesets') };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--data-dir') out.dataDir = path.resolve(argv[++i]);
    else if (a === '--out') out.out = path.resolve(argv[++i]);
    else if (a === '--evidence-out') out.evidenceOut = path.resolve(argv[++i]);
    else if (a === '--today') out.today = argv[++i];
    else if (a === '--cache-dir') out.cacheDir = path.resolve(argv[++i]);
    else throw new Error(`알 수 없는 인자: ${a}`);
  }
  out.out = out.out || path.join(out.dataDir, 'cve-context.json');
  out.evidenceOut = out.evidenceOut || path.join(out.dataDir, 'cve-evidence.json');
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
  // 증거 공개일은 원 출처 캐시가 있는 실행(Bulk Lane)에서만 만든다. 없으면 이월본을 건드리지 않고 품질 대조에만 쓴다.
  const evidence = buildEvidence(args.cacheDir, new Set(inputs.cves.map(c => String(c.id || '').toUpperCase())), now);
  inputs.evidence = evidence || readJson(path.dirname(args.evidenceOut), path.basename(args.evidenceOut), false);
  const result = build(inputs, now);
  writeAtomic(args.out, JSON.stringify(result));

  const st = result.stats;
  console.log(`  CVE ${st.total.toLocaleString()}건 · 수명주기 연결 ${st.lifecycle.mapped.toLocaleString()}건`
              + ` (사이클 ${st.lifecycle.cycle_level} · 제품만 ${st.lifecycle.product_only}) · 기준일 ${result.as_of}`);
  console.log('  상관: ' + Object.entries(st.correlations).map(([k, v]) => `${k} ${v}`).join(' · '));
  for (const q of result.quality) {
    if (q.status !== 'ok') console.log(`  품질 [${q.status}] ${q.label}: ${q.count}${q.note ? ` — ${q.note}` : ''}`);
  }
  const size = fs.statSync(args.out).size;
  console.log(`  → ${path.relative(ROOT, args.out)} (${(size / 1024).toFixed(0)} KB, ${Date.now() - started} ms)`);

  if (evidence) {
    writeAtomic(args.evidenceOut, JSON.stringify(evidence));
    const n = k => Object.keys(evidence[k]).length;
    console.log(`  증거 공개일: KEV ${n('kev')} · Exploit-DB ${n('edb')} · Metasploit ${n('msf')}건 (${Object.keys(evidence.sources).join(', ')})`
                + ` → ${path.relative(ROOT, args.evidenceOut)} (${(fs.statSync(args.evidenceOut).size / 1024).toFixed(0)} KB)`);
  } else {
    console.log(`  원 출처 캐시(${path.relative(ROOT, args.cacheDir) || args.cacheDir})가 없음 → cve-evidence.json 은 이월본을 그대로 둔다`);
  }
  return 0;
}

function writeAtomic(file, text) {
  // docs/ 전체가 배포되므로 쓰다 실패한 임시 파일이 남으면 그대로 공개된다 — 지우고 실패로 끝낸다.
  const tmp = `${file}.tmp`;
  try {
    fs.writeFileSync(tmp, text);
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) { /* 이미 없음 */ }
    throw e;
  }
}

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    console.error(`[!] 사전 계산 실패: ${e.message} — cve-context.json 을 쓰지 않는다 (브라우저가 직접 계산)`);
    process.exitCode = 1;
  }
}

module.exports = { build, buildEvidence, parseCsv, productDecoder, readKevCatalog, parseArgs, main };
