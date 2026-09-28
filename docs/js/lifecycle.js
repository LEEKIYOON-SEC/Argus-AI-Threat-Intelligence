(function (root) {
  'use strict';

  const STATUSES = ['ACTIVE', 'SECURITY_SUPPORT', 'EXTENDED_SUPPORT', 'EOL', 'UNKNOWN'];
  const SHORT = {
    ACTIVE: 'ACTIVE', SECURITY_SUPPORT: 'SECURITY', EXTENDED_SUPPORT: 'EXTENDED',
    EOL: 'EOL', UNKNOWN: 'UNKNOWN',
  };
  const QUERY = {
    active: 'ACTIVE', security: 'SECURITY_SUPPORT', security_support: 'SECURITY_SUPPORT',
    'security-support': 'SECURITY_SUPPORT',
    extended: 'EXTENDED_SUPPORT', extended_support: 'EXTENDED_SUPPORT', 'extended-support': 'EXTENDED_SUPPORT',
    eol: 'EOL', unknown: 'UNKNOWN',
  };
  const DISPLAY_ORDER = ['EOL', 'EXTENDED_SUPPORT', 'SECURITY_SUPPORT', 'ACTIVE', 'UNKNOWN'];
  const REASONS = {
    unavailable: 'endoflife.date에 없는 제품',
    no_data: '수명주기 데이터를 받지 못한 제품',
    version_unparsed: '영향 버전이 어느 릴리스인지 정할 수 없음',
    out_of_range: '영향 버전이 추적 중인 릴리스 범위 밖',
    cycle_not_found: '제품명이 가리키는 릴리스가 제조사 일정에 없음',
  };
  const VIA = {
    override: '수동 지정', cpe: 'CPE', purl: 'PURL', vendor_product: '벤더+제품명', pattern: '제품명 규칙',
  };
  const LANG_PURL = {
    pypi: 'pypi', npm: 'npm', maven: 'maven', go: 'golang', nuget: 'nuget', rubygems: 'gem',
    packagist: 'composer', 'crates.io': 'cargo', hex: 'hex', pub: 'pub',
  };
  const PURL_TYPES = new Set(Object.values(LANG_PURL));

  const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

  function normPart(value) {
    return String(value == null ? '' : value).toLowerCase()
      .replace(/\\(.)/g, '$1')
      .replace(/[^a-z0-9.+]+/g, '_')
      .replace(/^[_.]+|[_.]+$/g, '');
  }

  function splitCpe(text) {
    const parts = [];
    let cur = '';
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch === '\\' && i + 1 < text.length) { cur += text[i + 1]; i++; continue; }
      if (ch === ':') { parts.push(cur); cur = ''; continue; }
      cur += ch;
    }
    parts.push(cur);
    return parts;
  }

  function parseCpe(id) {
    const s = String(id || '').trim();
    let vendor, product;
    if (/^cpe:2\.3:/i.test(s)) {
      const p = splitCpe(s);
      vendor = p[3]; product = p[4];
    } else if (/^cpe:\//i.test(s)) {
      const p = splitCpe(s.slice(5));
      vendor = p[1]; product = p[2];
    } else {
      return null;
    }
    vendor = normPart(vendor);
    product = normPart(product);
    if (!vendor || !product || vendor === '*' || product === '*') return null;
    return { vendor, product };
  }

  function purlKey(id) {
    const s = String(id || '').trim();
    const m = /^pkg:([a-z0-9.+-]+)\/([^@?#]+)/i.exec(s);
    if (!m) return null;
    let path;
    try { path = decodeURIComponent(m[2]); } catch (e) { path = m[2]; }
    const type = m[1].toLowerCase();
    return { type, key: `${type}/${path.replace(/^\/+|\/+$/g, '').toLowerCase()}` };
  }

  function packageKey(name, ecosystem) {
    const type = LANG_PURL[String(ecosystem || '').split(':')[0].trim().toLowerCase()];
    if (!type || !name) return null;
    let n = String(name).trim().toLowerCase();
    if (type === 'maven') n = n.replace(':', '/');
    if (type === 'pypi') n = n.replace(/[-_.]+/g, '-');
    return `${type}/${n}`;
  }

  /* ---------- 상태 (src/update_lifecycle.py compute_status 와 같은 규칙) ---------- */

  function reached(date, flag, today) {
    if (date) return date <= today;
    if (typeof flag === 'boolean') return flag;
    return null;
  }

  function phaseStatus(label, override) {
    if (STATUSES.includes(override)) return override;
    const text = String(label || '').toLowerCase();
    if (text.includes('security')) return 'SECURITY_SUPPORT';
    if (text.includes('extended')) return 'EXTENDED_SUPPORT';
    return 'UNKNOWN';
  }

  const labelsOf = meta => (meta && meta.labels) || {};
  const overrideOf = meta => ((meta && meta.phase_status) || {}).eol;

  function statusOf(rel, meta, today) {
    if (!rel) return 'UNKNOWN';
    const labels = labelsOf(meta);
    const eol = reached(rel.eol_date, rel.eol_reached, today);
    if (eol === null) return 'UNKNOWN';
    if (eol) {
      const ext = rel.extended_support_ended;
      if (labels.eoes && typeof ext === 'boolean'
          && reached(rel.extended_support_end, ext, today) === false) return 'EXTENDED_SUPPORT';
      return 'EOL';
    }
    if (labels.eoas) {
      const eoas = reached(rel.support_end, rel.support_ended, today);
      if (eoas === null) return 'UNKNOWN';
      if (!eoas) return 'ACTIVE';
      return phaseStatus(labels.eol, overrideOf(meta));
    }
    return 'ACTIVE';
  }

  function phaseLabel(rel, meta, today) {
    const labels = labelsOf(meta);
    const eol = reached(rel.eol_date, rel.eol_reached, today);
    if (eol === null) return null;
    if (eol) return statusOf(rel, meta, today) === 'EXTENDED_SUPPORT' ? labels.eoes : null;
    if (labels.eoas && reached(rel.support_end, rel.support_ended, today) === false) return labels.eoas;
    return labels.eol || null;
  }

  function timeline(rel, meta) {
    const labels = labelsOf(meta);
    const out = [];
    const firstEnd = labels.eoas ? rel.support_end : rel.eol_date;
    if (rel.release_date) {
      out.push({ from: rel.release_date, to: firstEnd || null, status: 'ACTIVE',
                 label: labels.eoas || labels.eol || null,
                 open: !firstEnd && !(labels.eoas ? rel.support_ended : rel.eol_reached) });
    }
    if (labels.eoas && rel.support_end && (rel.eol_date || rel.eol_reached === false)) {
      out.push({ from: rel.support_end, to: rel.eol_date || null,
                 status: phaseStatus(labels.eol, overrideOf(meta)), label: labels.eol || null,
                 open: !rel.eol_date });
    }
    if (labels.eoes && rel.eol_date && typeof rel.extended_support_ended === 'boolean'
        && (rel.extended_support_end || rel.extended_support_ended === false)) {
      out.push({ from: rel.eol_date, to: rel.extended_support_end || null,
                 status: 'EXTENDED_SUPPORT', label: labels.eoes, open: !rel.extended_support_end });
    }
    return out.filter(seg => !seg.to || seg.to >= seg.from);
  }

  function daysUntil(date, today) {
    if (!date || !today) return null;
    const a = Date.parse(`${date}T00:00:00Z`);
    const b = Date.parse(`${today}T00:00:00Z`);
    if (isNaN(a) || isNaN(b)) return null;
    return Math.round((a - b) / 86400000);
  }

  function localToday(now) {
    const d = now || new Date();
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  }

  /* ---------- 버전 문자열 → 사이클 ---------- */

  const OPEN_LOW = new Set(['unspecified', '*', '?', '0', '0.0', '0.0.0', '-']);
  const PRE = /(alpha|beta|rc|pre|dev|preview|snapshot|(^|[-._~])m\d)/;

  function parseVersion(text, rewrites) {
    let s = String(text || '').trim().toLowerCase();
    for (const rw of rewrites || []) s = s.replace(rw.re, rw.to);
    s = s.replace(/^v(?=\d)/, '');
    if (!s || /\s/.test(s)) return null;
    if (/^[0-9a-f]{7,40}$/.test(s) && /[a-f]/.test(s)) return null;
    const m = /^((?:\d+|[*x])(?:\.(?:\d+|[*x]))*)(.*)$/.exec(s);
    if (!m) return null;
    let suffix = m[2];
    if (suffix.length > 16 || !/^[a-z0-9._+~*-]*$/.test(suffix)) return null;
    const nums = [];
    let wild = false;
    for (const part of m[1].split('.')) {
      if (part === '*' || part === 'x') { wild = true; break; }
      nums.push(parseInt(part, 10));
    }
    if (suffix === '*' || suffix === '.*') { wild = true; suffix = ''; }
    else if (suffix.includes('*')) return null;
    if (!nums.length) return null;
    return { nums, wild, pre: !!suffix && PRE.test(suffix), post: !!suffix && !PRE.test(suffix) };
  }

  function splitEntries(text) {
    const s = String(text || '').trim();
    if (!s || s === '정보 없음' || s === '모든 버전') return null;
    if (!/ (이전|이하|\(단일 버전\))(, |$)/.test(s)) return [{ body: s, kind: 'bare' }];
    const re = /(.+?) (이전|이하|\(단일 버전\))(?:, |$)/y;
    const out = [];
    let m;
    while (re.lastIndex < s.length && (m = re.exec(s))) out.push({ body: m[1].trim(), kind: m[2] });
    return re.lastIndex === s.length && out.length ? out : null;
  }

  function single(v) {
    if (!v || (!v.wild && v.nums.every(n => n === 0))) return null;
    return { lo: v, loInc: true, hi: v, hiInc: true };
  }

  const V = '([0-9][0-9a-z._+~*-]*)';
  const upTo = inc => (m, ver) => {
    const hi = ver(m[1]);
    return hi && { lo: null, hi, hiInc: inc };
  };
  const FREE = [
    [new RegExp(`^(?:<|before|prior to|earlier than) ?${V}$`), upTo(false)],
    [new RegExp(`^(?:<=|up to|through) ?${V}$`), upTo(true)],
    [new RegExp(`^${V} (?:and|or) (?:prior|earlier|below|lower|before)$`), upTo(true)],
    [new RegExp(`^>= ?${V} ?, ?(<=?) ?${V}$`), (m, ver) => {
      const lo = ver(m[1]), hi = ver(m[3]);
      return lo && hi && { lo, loInc: true, hi, hiInc: m[2] === '<=' };
    }],
    [new RegExp(`^${V} (?:to|through|-) ${V}$`), (m, ver) => {
      const lo = ver(m[1]), hi = ver(m[2]);
      return lo && hi && { lo, loInc: true, hi, hiInc: true };
    }],
  ];
  const PLAIN = new RegExp(`^=? ?${V}$`);

  function freeText(body, rw) {
    const t = body.toLowerCase().replace(/\s+/g, ' ').trim();
    const ver = s => parseVersion(s, rw);
    for (const [re, build] of FREE) {
      const m = re.exec(t);
      if (!m) continue;
      const r = build(m, ver);
      return r ? [r] : null;
    }
    const parts = t.split(/ ?, ?/);
    const out = [];
    for (const part of parts) {
      const m = PLAIN.exec(part);
      const r = m && single(ver(m[1]));
      if (!r) return null;
      out.push(r);
    }
    return out.length ? out : null;
  }

  function parseEntry(entry, rw) {
    if (entry.kind === 'bare') {
      const r = single(parseVersion(entry.body, rw));
      return r ? [r] : null;
    }
    if (entry.kind === '(단일 버전)') return freeText(entry.body, rw);
    const parts = entry.body.split(' 부터 ');
    if (parts.length > 2) return null;
    const hiText = parts[parts.length - 1].trim();
    const hi = hiText === '*' ? null : parseVersion(hiText, rw);
    if (!hi && hiText !== '*') return null;
    let lo = null;
    if (parts.length === 2) {
      const loText = parts[0].trim().toLowerCase();
      if (!OPEN_LOW.has(loText)) {
        lo = parseVersion(loText, rw);
        if (!lo) return null;
      }
    }
    return [{ lo, loInc: true, hi, hiInc: entry.kind === '이하' }];
  }

  const escapeRe = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  function parseConstraints(versions, opts) {
    const o = Array.isArray(opts) ? { rewrites: opts } : (opts || {});
    let text = String(versions || '');
    if (o.label) text = text.replace(new RegExp(`(^|, )${escapeRe(o.label)}[ -](?=\\d)`, 'gi'), '$1');
    const entries = splitEntries(text);
    if (!entries) return null;
    const out = [];
    for (const e of entries) {
      const r = parseEntry(e, o.rewrites);
      if (!r) return null;
      out.push(...r);
    }
    return out;
  }

  function cmpPrefix(a, b, k) {
    for (let i = 0; i < k; i++) {
      const x = a[i] || 0, y = b[i] || 0;
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  }

  function cycleNums(cycle) {
    return /^\d+(\.\d+)*$/.test(String(cycle || '')) ? String(cycle).split('.').map(Number) : null;
  }

  function cycleInRange(c, r) {
    const k = c.length;
    if (r.lo && cmpPrefix(r.lo.nums, c, k) > 0) return false;
    const hi = r.hi;
    if (!hi) return true;
    if (hi.wild) {
      const n = Math.min(k, hi.nums.length);
      return cmpPrefix(c, hi.nums, n) <= 0;
    }
    const d = cmpPrefix(c, hi.nums, k);
    if (d !== 0) return d < 0;
    if (hi.nums.slice(k).some(x => x > 0)) return true;
    if (hi.pre) return false;
    if (hi.post) return true;
    return !!r.hiInc;
  }

  function cyclesFor(releases, ranges) {
    const out = [];
    for (const rel of releases || []) {
      const c = cycleNums(rel.cycle);
      if (c && ranges.some(r => cycleInRange(c, r))) out.push(rel);
    }
    return out;
  }

  /* ---------- 매칭 ---------- */

  function safeRegex(src, flags) {
    try { return new RegExp(src, flags || ''); } catch (e) { return null; }
  }

  function expand(template, m) {
    return String(template).replace(/\$(\d)/g, (_, i) => m[Number(i)] || '');
  }

  function createMatcher(data, aliases) {
    const products = (data && data.products) || {};
    const A = aliases || {};
    const vendorAliases = A.vendor_aliases || {};
    const overrides = A.overrides || {};
    const releasesBy = {};
    for (const r of (data && data.releases) || []) {
      (releasesBy[r.product_slug] = releasesBy[r.product_slug] || []).push(r);
    }
    const unavailable = new Map(((data && data.unavailable) || []).map(u => [u.slug, u]));

    const cpeIndex = new Map();
    const purlIndex = new Map();
    const nameIndex = new Map();
    const vendorSets = {};
    const claim = (map, key, slug) => {
      if (!key) return;
      if (map.has(key) && map.get(key) !== slug) map.set(key, null);
      else if (!map.has(key)) map.set(key, slug);
    };
    for (const slug of Object.keys(products).sort()) {
      const meta = products[slug];
      const ids = meta.identifiers || {};
      vendorSets[slug] = new Set();
      for (const id of ids.cpe || []) {
        const c = parseCpe(id);
        if (c) { claim(cpeIndex, `${c.vendor}:${c.product}`, slug); vendorSets[slug].add(c.vendor); }
      }
      for (const id of ids.purl || []) {
        const p = purlKey(id);
        if (p && PURL_TYPES.has(p.type)) claim(purlIndex, p.key, slug);
      }
      for (const n of [slug, meta.label].concat(meta.aliases || [])) {
        const k = normPart(n);
        if (!k) continue;
        if (!nameIndex.has(k)) nameIndex.set(k, new Set());
        nameIndex.get(k).add(slug);
      }
      for (const v of (A.product_vendors || {})[slug] || []) vendorSets[slug].add(normPart(v));
    }
    for (const [slug, u] of unavailable) {
      for (const id of (u.identifiers || {}).cpe || []) {
        const c = parseCpe(id);
        if (c && !cpeIndex.has(`${c.vendor}:${c.product}`)) cpeIndex.set(`${c.vendor}:${c.product}`, slug);
      }
    }
    const patterns = (A.patterns || []).map(p => Object.assign({}, p, {
      re: safeRegex(p.product), vendorKey: normPart(p.vendor),
    })).filter(p => p.re && p.lifecycle && p.cycle);
    const rewrites = {};
    for (const [slug, rules] of Object.entries(A.version_rewrites || {})) {
      rewrites[slug] = (rules || []).map(r => ({ re: safeRegex(r.from), to: r.to || '' })).filter(r => r.re);
    }

    function resolve(slug, fixed, family, versions, via, key) {
      const base = { slug, via, key };
      if (unavailable.has(slug)) return Object.assign(base, { cycles: [], reason: 'unavailable' });
      const rels = releasesBy[slug];
      if (!rels || !products[slug]) return Object.assign(base, { cycles: [], reason: 'no_data' });
      if (fixed) {
        const cycles = rels.filter(r => fixed.some(c =>
          r.cycle === c || (family && String(r.cycle).startsWith(`${c}-`))));
        return Object.assign(base, { cycles, reason: cycles.length ? null : 'cycle_not_found' });
      }
      const ranges = parseConstraints(versions, { rewrites: rewrites[slug], label: products[slug].label });
      if (!ranges) return Object.assign(base, { cycles: [], reason: 'version_unparsed' });
      const cycles = cyclesFor(rels, ranges);
      return Object.assign(base, { cycles, reason: cycles.length ? null : 'out_of_range' });
    }

    function matchItem(vendor, product, versions) {
      const vk = normPart(vendor);
      const pk = normPart(product);
      if (!pk) return null;
      const cvk = own(vendorAliases, vk) ? normPart(vendorAliases[vk]) : vk;
      const keys = [...new Set([`${vk}:${pk}`, `${cvk}:${pk}`])];
      const vs = normPart(versions);
      for (const k of keys) {
        for (const kk of vs ? [`${k}:${vs}`, k] : [k]) {
          if (!own(overrides, kk)) continue;
          const o = overrides[kk];
          if (o === null) return { denied: true, via: 'override', key: kk };
          const spec = typeof o === 'string' ? { product: o } : (o || {});
          return resolve(spec.product, Array.isArray(spec.cycles) && spec.cycles.length ? spec.cycles : null,
                         !!spec.family, versions, 'override', kk);
        }
      }
      for (const k of keys) {
        const slug = cpeIndex.get(k);
        if (slug) return resolve(slug, null, false, versions, 'cpe', k);
      }
      const cands = nameIndex.get(pk);
      if (cands) {
        const hits = [...cands].filter(s => vendorSets[s] && (vendorSets[s].has(cvk) || vendorSets[s].has(vk)));
        if (hits.length === 1) return resolve(hits[0], null, false, versions, 'vendor_product', `${cvk}:${pk}`);
      }
      for (const p of patterns) {
        if (p.vendorKey !== cvk && p.vendorKey !== vk) continue;
        const m = p.re.exec(pk);
        if (m) return resolve(p.lifecycle, [expand(p.cycle, m)], !!p.family, versions, 'pattern', `${cvk}:${pk}`);
      }
      return null;
    }

    const keyMemo = new Map();
    function memoKey(name, eco) {
      const k = `${name}\u0001${eco}`;
      if (!keyMemo.has(k)) keyMemo.set(k, packageKey(name, eco));
      return keyMemo.get(k);
    }

    function matchPackages(pkgMap) {
      const out = [];
      if (!purlIndex.size) return out;
      for (const [name, ecoMap] of Object.entries(pkgMap || {})) {
        for (const [eco, fixes] of Object.entries(ecoMap || {})) {
          const key = memoKey(name, eco);
          const slug = key && purlIndex.get(key);
          if (!slug) continue;
          const found = (fixes || []).filter(Boolean);
          const ranges = found.map(f => single(parseVersion(f, rewrites[slug]))).filter(Boolean);
          const res = resolve(slug, null, false, null, 'purl', `pkg:${key}`);
          if (res.reason === 'unavailable' || res.reason === 'no_data') { out.push(res); continue; }
          const cycles = ranges.length ? cyclesFor(releasesBy[slug], ranges) : [];
          out.push(Object.assign(res, { cycles, reason: cycles.length ? null : 'version_unparsed',
                                        basis: 'fixed' }));
        }
      }
      return out;
    }

    const memo = new Map();
    function memoItem(vendor, product, versions) {
      const k = `${vendor}\u0001${product}\u0001${versions}`;
      if (!memo.has(k)) memo.set(k, matchItem(vendor, product, versions));
      return memo.get(k);
    }

    // 영향 제품 항목마다의 결과(어느 항목이 어느 제품·사이클로, 어떤 방법으로 이어졌나)를 그대로 남긴다.
    function matchCve(affected, pkgMap) {
      return {
        items: (affected || []).map(a => memoItem(a.vendor, a.product, a.versions)),
        packages: matchPackages(pkgMap),
      };
    }

    function forCve(affected, pkgMap) {
      return reduceMatch(matchCve(affected, pkgMap));
    }

    const releaseIndex = new Map();
    for (const rels of Object.values(releasesBy)) {
      for (const r of rels) releaseIndex.set(`${r.product_slug}|${r.cycle}`, r);
    }

    return {
      products, releasesBy, unavailable, releaseIndex,
      matchItem, matchPackages, matchCve, forCve,
      meta: slug => products[slug] || null,
    };
  }

  // 항목별 결과 → CVE 요약. 같은 릴리스는 한 번만(처음 연결한 방법 유지), 사이클이 하나라도
  // 이어진 제품은 '사이클 특정 불가' 목록에서 뺀다 — 다만 빠진 항목은 partial 에 남긴다.
  // 같은 제품의 다른 항목이 어느 사이클인지 모르므로 'EOL 아님'을 단정하는 근거가 되지 않는다.
  function reduceMatch(match) {
    const entries = new Map();
    const unresolved = new Map();
    let untracked = 0;
    const take = r => {
      if (!r || r.denied) { untracked++; return; }
      if (r.cycles.length) {
        for (const rel of r.cycles) {
          const k = `${rel.product_slug}|${rel.cycle}`;
          if (!entries.has(k)) entries.set(k, { slug: r.slug, rel, via: r.via, key: r.key, basis: r.basis || null });
        }
      } else if (!unresolved.has(r.slug)) {
        unresolved.set(r.slug, { slug: r.slug, via: r.via, key: r.key, reason: r.reason });
      }
    };
    for (const r of (match && match.items) || []) take(r);
    for (const r of (match && match.packages) || []) take(r);
    const partial = [];
    for (const e of entries.values()) {
      if (unresolved.has(e.slug)) {
        partial.push(unresolved.get(e.slug));
        unresolved.delete(e.slug);
      }
    }
    return { entries: [...entries.values()], unresolved: [...unresolved.values()], untracked, partial };
  }

  /* ---------- 사전 계산(CI) ↔ 브라우저 직렬화 ---------- */

  // 결과 하나를 짧은 배열로: 연결 없음 0 · 연결 금지 [1, key] · 그 밖 [slug, via, key, [사이클...], 사유, 근거]
  function encodeResult(r) {
    if (!r) return 0;
    if (r.denied) return [1, r.key];
    return [r.slug, r.via, r.key, r.cycles.map(c => c.cycle), r.reason || 0, r.basis || 0];
  }

  // 사이클이 현재 lifecycle.json 에 없으면 undefined — 호출부가 브라우저 계산으로 되돌아간다.
  function decodeResult(x, releaseIndex) {
    if (!x) return null;
    if (x[0] === 1) return { denied: true, via: 'override', key: x[1] };
    const cycles = [];
    for (const c of x[3] || []) {
      const rel = releaseIndex.get(`${x[0]}|${c}`);
      if (!rel) return undefined;
      cycles.push(rel);
    }
    return { slug: x[0], via: x[1], key: x[2], cycles, reason: x[4] || null, basis: x[5] || null };
  }

  function encodeMatch(match) {
    const items = ((match && match.items) || []).map(encodeResult);
    const pkgs = ((match && match.packages) || []).map(encodeResult);
    if (!pkgs.length && items.every(x => x === 0)) return null;
    return pkgs.length ? { i: items, p: pkgs } : { i: items };
  }

  function decodeMatch(compact, affectedCount, releaseIndex) {
    if (!compact) return { items: new Array(affectedCount).fill(null), packages: [] };
    const raw = compact.i || [];
    if (raw.length !== affectedCount) return null;
    const items = [];
    for (const x of raw) {
      const r = decodeResult(x, releaseIndex);
      if (r === undefined) return null;
      items.push(r);
    }
    const packages = [];
    for (const x of compact.p || []) {
      const r = decodeResult(x, releaseIndex);
      if (!r) return null;
      packages.push(r);
    }
    return { items, packages };
  }

  /* ---------- CVE 요약 · 검색 ---------- */

  function summarize(result, products, today) {
    const counts = {};
    for (const s of STATUSES) counts[s] = 0;
    for (const e of (result && result.entries) || []) counts[statusOf(e.rel, (products || {})[e.slug], today)]++;
    counts.UNKNOWN += ((result && result.unresolved) || []).length;
    const known = counts.ACTIVE + counts.SECURITY_SUPPORT + counts.EXTENDED_SUPPORT + counts.EOL;
    return { counts, known };
  }

  function queryStatus(value) {
    return own(QUERY, String(value || '').toLowerCase()) ? QUERY[String(value).toLowerCase()] : null;
  }

  function parseDays(value) {
    const m = /^(\d{1,5})d?$/.exec(String(value || '').trim().toLowerCase());
    return m ? Number(m[1]) : null;
  }

  const CMP = {
    '>=': (a, b) => a >= b, '<=': (a, b) => a <= b,
    '>': (a, b) => a > b, '<': (a, b) => a < b, '=': (a, b) => a === b,
  };

  function eolWithin(rel, op, days, today) {
    const d = daysUntil(rel && rel.eol_date, today);
    return d !== null && d > 0 && !!CMP[op] && CMP[op](d, days);
  }

  function matchesStatus(summary, status) {
    if (status === 'UNKNOWN') return summary.known === 0;
    return summary.counts[status] > 0;
  }

  function matchesEol(result, op, days, today) {
    return ((result && result.entries) || []).some(e => eolWithin(e.rel, op, days, today));
  }

  const api = {
    STATUSES, SHORT, DISPLAY_ORDER, REASONS, VIA,
    normPart, parseCpe, purlKey, packageKey,
    reached, phaseStatus, statusOf, phaseLabel, timeline, daysUntil, localToday,
    parseVersion, splitEntries, parseConstraints, cyclesFor, cycleInRange,
    createMatcher, reduceMatch, encodeMatch, decodeMatch,
    summarize, queryStatus, parseDays, eolWithin, matchesStatus, matchesEol,
  };
  root.ArgusLifecycle = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
