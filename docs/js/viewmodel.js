(function (root, factory) {
  'use strict';
  const node = typeof module !== 'undefined' && module.exports;
  const api = factory(node ? require('./context.js') : root.ArgusContext,
                      node ? require('./lifecycle.js') : root.ArgusLifecycle);
  root.ArgusViewModel = api;
  if (node) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis, function (CTX, LC) {
  'use strict';

  /*
   * View Model — 화면은 여기서 만든 값만 그린다. 원본 필드 이름(is_kev · has_metasploit_module …)은 이 파일과
   * 엔티티 계층(entities.js)만 안다. HTML 은 만들지 않는다(문자열 조립은 화면 파일의 일).
   * 파생 모듈(context.js)이 없으면 신호 칸을 비워 둔다 — 목록 · 검색 · 내보내기는 그래도 동작한다.
   */

  const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'None'];
  const band = s => (CTX ? CTX.sevBand(s) : (s >= 9 ? 'Critical' : s >= 7 ? 'High' : s >= 4 ? 'Medium' : s > 0 ? 'Low' : 'None'));

  // 확률을 % 로. 0.99999 를 반올림하면 100% 가 되어 확실한 것처럼 읽힌다 — 1 미만은 100 으로 올리지 않는다.
  function epssPct(p, digits) {
    const v = Number(p) || 0;
    const s = (v * 100).toFixed(digits);
    return v < 1 && Number(s) >= 100 ? (100 - 10 ** -digits).toFixed(digits) : s;
  }

  function scores(cve) {
    const cvss = Number(cve.cvss) || 0;
    const epss = Number(cve.epss) || 0;
    const pctl = Number(cve.epss_percentile) || 0;
    const alt = Object.entries(cve.cvss_alt || {}).filter(([, v]) => Number(v) > 0)
      .sort((a, b) => (a[0] < b[0] ? 1 : -1)).map(([version, v]) => ({ version, value: Number(v), band: band(Number(v)) }));
    return {
      cvss: cvss > 0 ? { value: cvss, text: cvss.toFixed(1), version: cve.cvss_version || '', band: cve.severity || band(cvss), alt,
                         mixed: new Set(alt.map(a => a.band)).size > 1 } : null,
      epss: epss > 0 || pctl > 0 ? { value: epss, text: `${epssPct(epss, 1)}%`, text2: `${epssPct(epss, 2)}%`,
                                     percentile: pctl || null,
                                     top: pctl ? `상위 ${Math.max(0.1, (1 - pctl) * 100).toFixed(1)}%` : '' } : null,
    };
  }

  /* ---------- 목록 한 행 ---------- */

  const ENGINE_FAMILY = { snort2: 'Snort', snort3: 'Snort', suricata5: 'Suricata', suricata7: 'Suricata',
                          sigma: 'Sigma', splunk: 'Splunk', yara: 'YARA', nuclei: 'nuclei' };
  const clean = v => { const s = String(v || '').trim(); return ['', 'unknown', 'n/a', '-'].includes(s.toLowerCase()) ? '' : s; };

  // env: { ctx (cveContext), lc (cveLifecycle 요약 · 없으면 null), lcProducts, today, affected, shown, packages }
  function listRow(cve, env) {
    const e = env || {};
    const s = (e.ctx && e.ctx.states) || {};
    const sc = scores(cve);
    const threat = [];
    if (s.EXPLOITATION_CONFIRMED === 'yes') {
      const src = [cve.is_kev && 'CISA KEV', cve.is_vulncheck_kev && 'VulnCheck KEV',
                   cve.ssvc_exploitation === 'active' && 'SSVC active'].filter(Boolean);
      threat.push({ kind: 'exploit', label: src[0] + (cve.is_kev_ransomware ? ' · 랜섬웨어' : ''),
                    extra: src.length > 1 ? `+${src.length - 1}` : '',
                    title: `악용 근거 — ${src.join(' · ')}${cve.is_kev_ransomware ? ' · CISA KEV 랜섬웨어 캠페인 사용 Known' : ''}` });
    }
    if (s.PUBLIC_EXPLOIT === 'yes') {
      const src = [cve.has_metasploit_module && 'MSF', cve.has_public_exploit && 'EDB', cve.has_poc && 'PoC'].filter(Boolean);
      threat.push({ kind: 'weapon', label: '공개 exploit', extra: src.join('·'),
                    title: `공개 exploit — ${src.join(' · ')} (공개돼 있다는 사실이며 실제 공격 발생이 아님)` });
    }
    if (s.AUTOMATABLE === 'yes') {
      threat.push({ kind: 'auto', label: '자동화', extra: '', title: 'CISA SSVC Automatable=yes — 정찰부터 익스플로잇까지 자동화 가능' });
    }
    const aff = e.affected || [];
    const shown = e.shown || aff[0] || {};
    const vendor = clean(shown.vendor), product = clean(shown.product);
    let lifecycle = null;
    if (e.lc && LC) {
      const present = LC.DISPLAY_ORDER.filter(st => e.lc.counts[st] > 0);
      if (present.length) {
        const top = present[0];
        const first = e.lc.entries.find(x => LC.statusOf(x.rel, (e.lcProducts || {})[x.slug], e.today) === top);
        const relName = first ? `${((e.lcProducts || {})[first.slug] || {}).label || first.slug} ${first.rel.cycle}` : '';
        const others = e.lc.entries.length + e.lc.unresolved.length - (first ? 1 : 0);
        lifecycle = { status: top, short: LC.SHORT[top], cycle: first ? first.rel.cycle : '', product: relName, others,
                      title: `${relName ? relName + ' — ' : ''}영향 제품 릴리스의 지원 상태: ${present.map(st => `${LC.SHORT[st]} ×${e.lc.counts[st]}`).join(' · ')}${
                        top === 'UNKNOWN' && e.lc.unresolved.length ? ' · 제품은 찾았지만 사이클을 특정하지 못함' : ''}. CVE 가 아니라 제품 릴리스의 상태 (× 뒤는 릴리스 수)` };
      }
    }
    const engines = CTX ? CTX.detectionEngines(cve) : (cve.rule_engines || []);
    return {
      id: cve.id, severity: cve.severity || 'None', tier: cve.tier || '', title: cve.title || 'N/A',
      ai: cve.ai_discovered ? { program: cve.ai_program || '' } : null,
      cvss: sc.cvss, epss: sc.epss, threat,
      product: { name: product ? (vendor ? `${vendor} / ${product}` : product) : (vendor || '-'),
                 more: aff.length > 1 ? aff.length - 1 : 0, versions: clean(shown.versions), packages: e.packages || [] },
      lifecycle,
      detection: s.PUBLIC_DETECTION === 'yes'
        ? { state: 'yes', text: [...new Set(engines.map(x => ENGINE_FAMILY[x] || x))].join(' · ') || '공식 룰', engines }
        : CTX ? { state: 'no', text: '룰 없음', engines: [] } : { state: 'unknown', text: '모름', engines: [] },
      fix: s.PATCH_AVAILABLE === 'yes' ? { state: 'yes', text: '버전 있음' }
        : s.PATCH_AVAILABLE === 'no' ? { state: 'no', text: '기록 없음' } : { state: 'unknown', text: '모름' },
      conflicts: (e.ctx && e.ctx.conflicts) || [],
      date: cve.date || '',
    };
  }

  /* ---------- 대시보드 ---------- */

  // src.stats: context.aggregate 결과 · stats: stats.json
  function kpis(agg, stats) {
    const s = (stats && stats.cve) || {};
    const src = (agg && agg.sources) || null;
    const v = k => (src ? src[k] : null);
    return [
      { id: 'stat-total', key: 'total', label: '추적 중 CVE', value: s.total || (agg && agg.total) || 0, query: '',
        sub: '최근 90일 · 악용·고위험 신호가 있는 것만 저장', title: '악용 신호가 관측됐거나 고위험이 될 가능성이 있는 건만 올라온다. 누르면 전체 목록' },
      { id: 'stat-24h', key: 'recent', label: '24시간 알림·갱신', value: s.recent_24h || 0, query: 'recent:24h',
        sub: '새로 올라오거나 상태가 바뀐 CVE — 신규 공개만이 아님',
        title: 'export 시각 기준 24시간 안에 Argus 가 알림을 보냈거나 상태를 바꾼 CVE (cves.json date)' },
      { id: 'stat-kev', key: 'kev', label: 'CISA KEV', value: v('cisa_kev'), query: 'has:cisa-kev', group: 'exploit',
        sub: agg ? `악용 근거 전체(VulnCheck · SSVC 포함)는 ${agg.signals.EXPLOITATION_CONFIRMED.yes.toLocaleString()}건` : '',
        title: 'CISA Known Exploited Vulnerabilities 카탈로그 등재 — 실제 악용 확인' },
      { id: 'stat-weapon', key: 'weaponized', label: '무기화', value: v('weaponized'), query: 'has:weaponized', group: 'weapon',
        sub: src ? `Metasploit ${src.metasploit.toLocaleString()} · Exploit-DB ${src.exploit_db.toLocaleString()}` : '',
        title: '무기화된 exploit 코드 — Metasploit 모듈 또는 Exploit-DB 항목. PoC 저장소 · nuclei 점검 템플릿은 넣지 않는다' },
      { id: 'stat-poc', key: 'poc', label: '공개 PoC', value: v('poc'), query: 'has:poc', group: 'weapon',
        sub: 'PoC-in-GitHub 공개 저장소 — 실제 공격 발생이 아님', title: '공개 PoC 저장소 링크가 있는 CVE' },
      { id: 'stat-ai', key: 'ai', label: 'AI 발견', value: v('ai_discovered'), query: 'has:ai', group: 'src',
        sub: 'AI 가 찾아 책임공개된 취약점 (발견 출처 정보)', title: 'Anthropic CVD 원장 · CVE 크레딧 기준 — AI 분석과 다르다' },
    ];
  }

  function correlations(agg) {
    if (!CTX || !agg) return [];
    return CTX.CORRELATIONS.map(c => {
      const n = agg.correlations[c.code] || 0;
      const scope = (agg.correlation_scope || {})[c.code];
      const first = CTX.SIGNAL[c.parts[0]];
      const secondCode = c.parts[1].replace('!', '');
      const second = CTX.SIGNAL[secondCode];
      const canBeNo = agg.signals[secondCode].no > 0;
      return {
        code: c.code, label: c.label, short: c.short, query: c.query, n, parts: c.parts.map(p => ({
          code: p.replace('!', ''), negated: p[0] === '!' })),
        scope: scope == null ? null : scope,
        share: scope && canBeNo ? n / scope : null,
        scopeText: scope == null ? ''
          : canBeNo ? `${first.short} ${agg.signals[c.parts[0]].yes.toLocaleString()}건 중 ${second.short} 확인 ${scope.toLocaleString()}건 기준`
          : `${first.short} ${agg.signals[c.parts[0]].yes.toLocaleString()}건 중 출처가 '있음'으로 표기한 것만 — 나머지는 모름`,
      };
    }).sort((a, b) => b.n - a.n);
  }

  // 동시 발생 행렬 — 칸 = 두 신호가 함께 yes 인 CVE 수. 대각선은 그 신호의 yes 수.
  function matrix(agg) {
    if (!CTX || !agg) return null;
    const axes = CTX.MATRIX.map(code => ({ code, short: CTX.SIGNAL[code].short, total: agg.signals[code].yes,
                                           query: CTX.yesQuery(code) }));
    const cells = {};
    let max = 0;
    for (let i = 0; i < axes.length; i++) {
      for (let j = i + 1; j < axes.length; j++) {
        const n = agg.cooccur[`${axes[i].code}|${axes[j].code}`] || 0;
        cells[`${i}|${j}`] = { n, query: `${axes[i].query} ${axes[j].query}` };
        if (n > max) max = n;
      }
    }
    return { axes, cells, max };
  }

  function overview(agg) {
    const days = (agg && agg.daily) || [];
    const series = ['Critical', 'High', 'Medium', 'Low', 'None'];
    const totals = days.map(d => series.reduce((a, s) => a + (d[s] || 0), 0));
    return { days, series, totals, max: Math.max(1, ...totals), sum: totals.reduce((a, b) => a + b, 0) };
  }

  function recent(list, refIso) {
    const ref = Date.parse(refIso || '');
    const refDay = isNaN(ref) ? null : new Date(ref).toISOString().slice(0, 10);
    return (list || []).map(r => {
      let ago = '';
      if (refDay && r.published) {
        const days = Math.round((Date.parse(`${refDay}T00:00:00Z`) - Date.parse(`${r.published}T00:00:00Z`)) / 864e5);
        ago = days <= 0 ? '오늘 공개' : days === 1 ? '어제 공개' : `${days}일 전 공개`;
      }
      return Object.assign({}, r, { ago,
        corrLabels: (r.correlations || []).map(code => (CTX && CTX.CORRELATION[code] ? CTX.CORRELATION[code].short : code)),
        signalLabels: (r.signals || []).filter(k => k !== 'EXPLOITATION_CONFIRMED' || !r.signals.includes('CISA_KEV'))
          .map(k => (CTX ? CTX.SIGNAL[k].short : k)) });
    });
  }

  /* ---------- Data Sources — 출처 엔티티별 범위 · 시각 (조건 · 라이선스는 하단 표 한 곳) ---------- */

  // coverage: 이 출처가 '있음'이라고 한 CVE 수 (aggregate.sources / signals 에서)
  function sources(EN, agg, files) {
    if (!EN) return [];
    const src = (agg && agg.sources) || {};
    const sig = (agg && agg.signals) || {};
    const f = files || {};
    const cov = {
      'cve-record': agg ? { n: agg.total, text: `추적 CVE 전부 · CVSS 있음 ${(src.cvss_scored || 0).toLocaleString()}` } : null,
      'cisa-adp': agg ? { n: src.ssvc_assessed, text: `SSVC 판정 ${(src.ssvc_assessed || 0).toLocaleString()} · 모름 ${(sig.AUTOMATABLE ? sig.AUTOMATABLE.unknown : 0).toLocaleString()}` } : null,
      'first-epss': agg ? { n: src.epss_scored, text: `채점 ${(src.epss_scored || 0).toLocaleString()} · 미채점 ${(agg.total - (src.epss_scored || 0)).toLocaleString()}` } : null,
      'cisa-kev': agg ? { n: src.cisa_kev, text: `등재 ${(src.cisa_kev || 0).toLocaleString()} · 랜섬웨어 Known ${(sig.RANSOMWARE ? sig.RANSOMWARE.yes : 0).toLocaleString()}` } : null,
      'vulncheck-kev': agg ? { n: src.vulncheck_kev, text: `등재 ${(src.vulncheck_kev || 0).toLocaleString()}` } : null,
      'exploit-db': agg ? { n: src.exploit_db, text: `항목 있음 ${(src.exploit_db || 0).toLocaleString()}` } : null,
      metasploit: agg ? { n: src.metasploit, text: `모듈 있음 ${(src.metasploit || 0).toLocaleString()}` } : null,
      'poc-in-github': agg ? { n: src.poc, text: `저장소 있음 ${(src.poc || 0).toLocaleString()}` } : null,
      nuclei: agg ? { n: src.nuclei, text: `템플릿 있음 ${(src.nuclei || 0).toLocaleString()}` } : null,
      'rule-index': agg ? { n: src.rules, text: `룰 있음 ${(src.rules || 0).toLocaleString()} (nuclei 제외)` } : null,
      osv: agg && sig.PATCH_AVAILABLE ? { n: sig.PATCH_AVAILABLE.yes + sig.PATCH_AVAILABLE.no,
                                          text: `기록 ${(sig.PATCH_AVAILABLE.yes + sig.PATCH_AVAILABLE.no).toLocaleString()} · 수정 버전 ${sig.PATCH_AVAILABLE.yes.toLocaleString()}` } : null,
      endoflife: agg && agg.lifecycle ? { n: agg.lifecycle.mapped, text: `CVE 연결 ${agg.lifecycle.mapped.toLocaleString()} (사이클까지 ${agg.lifecycle.cycle_level.toLocaleString()})` } : null,
      'ai-discovery': agg ? { n: src.ai_discovered, text: `AI 발견 ${(src.ai_discovered || 0).toLocaleString()}` } : null,
    };
    const fileTime = name => ({ 'cves.json': f.cves, 'cve-products.json': f.products, 'cve-facts.json': f.facts,
                                'cve-evidence.json': f.evidence, 'cve-packages.json': f.packages, 'lifecycle.json': f.lifecycle,
                                'cve-context.json': f.context })[name];
    return EN.SOURCE_ORDER.map(id => {
      const s = EN.SOURCES[id];
      const types = (s.provides || []).map(k => ({ key: k, label: (EN.PROVIDES_LABEL || {})[k] || k }));
      return { id, name: s.name, provider: s.provider, url: s.url, kind: s.kind, role: s.role, cadence: s.cadence,
               files: (s.files || []).map(name => ({ name, at: fileTime(name) || null })), coverage: cov[id] || null, types };
    });
  }

  function conflicts(agg) {
    if (!CTX || !agg) return [];
    return CTX.CONFLICTS.map(c => ({ code: c.code, key: c.key, subject: c.subject, label: c.label, rule: c.rule,
                                    n: (agg.conflicts || {})[c.code] || 0, query: `conflict:${c.key}` }));
  }

  return { SEVERITIES, epssPct, scores, listRow, kpis, correlations, matrix, overview, recent, sources, conflicts, ENGINE_FAMILY };
});
