(function (root, factory) {
  'use strict';
  const node = typeof module !== 'undefined' && module.exports;
  const api = factory(node ? require('./lifecycle.js') : root.ArgusLifecycle);
  root.ArgusContext = api;
  if (node) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis, function (LC) {
  'use strict';

  /*
   * 파생 계층 — 원본 필드(cves.json · cve-products · cve-packages · lifecycle)를 CVE 중심 맥락으로 묶는다.
   * 규칙은 모두 결정적이다. 점수를 합산하지 않고, AI 분석(analysis)은 읽지도 않는다.
   * 모든 판정은 yes / no / unknown 셋 중 하나다 — 근거가 없으면 no 가 아니라 unknown.
   * 브라우저와 CI(src/build_context.js)가 이 파일 하나를 함께 쓴다.
   */

  // src/risk.py 의 epss_high 트리거와 같은 기준(백분위 95, 백분위가 없으면 확률 9.3%).
  const EPSS_P_HIGH = 0.95;
  const EPSS_SCORE_HIGH = 0.093;
  const CVSS_CRITICAL = 9.0;

  const URL = {
    cveRecord: id => `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`,
    nvd: id => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
    epss: id => `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(id)}`,
    osv: id => `https://osv.dev/list?q=${encodeURIComponent(id)}`,
    kev: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    vulncheck: 'https://vulncheck.com/kev',
    metasploit: 'https://github.com/rapid7/metasploit-framework',
    poc: 'https://github.com/nomi-sec/PoC-in-GitHub',
    exploitdb: 'https://www.exploit-db.com/',
    endoflife: 'https://endoflife.date/',
  };

  // 룰 엔진 — detect: 공격·악성 행위 탐지 룰, check: 대상에 요청을 보내 취약 여부를 확인하는 점검 템플릿.
  const ENGINES = {
    sigma: { label: 'Sigma', kind: 'detect', source: 'SigmaHQ' },
    splunk: { label: 'Splunk ESCU', kind: 'detect', source: 'Splunk security_content' },
    yara: { label: 'YARA', kind: 'detect', source: 'YARA Forge' },
    snort2: { label: 'Snort 2', kind: 'detect', source: 'ET Open · Snort Community' },
    snort3: { label: 'Snort 3', kind: 'detect', source: 'ET Open · Snort Community' },
    suricata5: { label: 'Suricata 5', kind: 'detect', source: 'ET Open' },
    suricata7: { label: 'Suricata 7', kind: 'detect', source: 'ET Open' },
    nuclei: { label: 'nuclei', kind: 'check', source: 'nuclei-templates' },
  };
  const ENGINE_ORDER = ['sigma', 'suricata7', 'suricata5', 'snort3', 'snort2', 'splunk', 'yara', 'nuclei'];
  const NETWORK = new Set(['snort2', 'snort3', 'suricata5', 'suricata7']);
  const engineInfo = e => ENGINES[e] || { label: e, kind: 'detect', source: e };

  /* ---------- 신호 정의 (코드 · 질문 · 정의 · 검색어) ---------- */

  const SIGNALS = [
    { code: 'EXPLOITATION_CONFIRMED', group: 'exploitation', short: '악용 근거', key: 'kev',
      question: '실제 악용 근거가 있는가',
      def: 'CISA KEV · VulnCheck KEV 등재, 또는 CISA SSVC Exploitation=active — 세 출처 모두 실제 악용 보고를 등재 기준으로 삼는다' },
    { code: 'CISA_KEV', group: 'exploitation', short: 'CISA KEV', key: 'cisa-kev',
      question: 'CISA KEV 에 등재됐는가', def: 'CISA Known Exploited Vulnerabilities 카탈로그 등재 여부' },
    { code: 'PUBLIC_EXPLOIT', group: 'weaponization', short: '공개 exploit', key: 'exploit',
      question: '공개 exploit 이 있는가',
      def: 'Exploit-DB 항목 · Metasploit 모듈 · 공개 PoC 저장소 중 하나 이상 — 공개돼 있다는 사실이며 실제 공격 발생을 뜻하지 않는다' },
    { code: 'AUTOMATABLE', group: 'automation', short: '자동화 가능', key: 'auto',
      question: '자동화된 대량 공격이 가능한가', def: 'CISA SSVC Automatable=yes (no 는 명시적 판정, 판정이 없으면 unknown)' },
    { code: 'RANSOMWARE', group: 'ransomware', short: '랜섬웨어', key: 'ransom',
      question: '랜섬웨어 캠페인에 쓰였는가',
      def: 'CISA KEV knownRansomwareCampaignUse=Known. KEV 의 Unknown · 미등재는 "아님"이 아니라 unknown' },
    { code: 'EOL_AFFECTED', group: 'lifecycle', short: 'EOL 릴리스', key: 'eol',
      question: '영향받는 제품 릴리스가 EOL 인가',
      def: '영향 제품 릴리스 중 하나 이상이 오늘 기준 EOL(endoflife.date). 취약점 심각도가 아니라 지원 상태다' },
    { code: 'PATCH_AVAILABLE', group: 'remediation', short: '수정 버전', key: 'patch',
      question: '수정 버전이 있는가',
      def: 'OSV 가 이 CVE 의 수정 버전을 하나 이상 기록. OSV 기록은 있는데 수정 버전이 없으면 no, OSV 기록이 없으면 unknown. 심각도가 아니다' },
    { code: 'PUBLIC_DETECTION', group: 'detection', short: '공개 탐지', key: 'detection',
      question: '공개 탐지 룰·점검 템플릿이 있는가',
      def: 'Sigma · Snort · Suricata · Splunk · YARA 룰 또는 nuclei 점검 템플릿 — Argus 가 색인하는 공개 소스 기준' },
    { code: 'HIGH_EPSS', group: 'scores', short: 'EPSS 상위 5%', key: 'high-epss',
      question: '악용 확률 예측이 높은가',
      def: 'EPSS 백분위 95 이상(백분위가 없으면 확률 9.3% 이상, src/risk.py 와 같은 기준). 예측이며 악용 확인이 아니다' },
    { code: 'CRITICAL_CVSS', group: 'scores', short: 'CVSS 9+', key: 'critical',
      question: '기본 심각도가 Critical 인가', def: 'CVSS 기본 점수 9.0 이상. 점수가 없으면 unknown' },
  ];
  const SIGNAL = Object.fromEntries(SIGNALS.map(s => [s.code, s]));
  const SIGNAL_BY_KEY = Object.fromEntries(SIGNALS.map(s => [s.key, s.code]));
  Object.assign(SIGNAL_BY_KEY, { patched: 'PATCH_AVAILABLE', rules: 'PUBLIC_DETECTION', exploited: 'EXPLOITATION_CONFIRMED' });

  // 상관 — 두 사실이 모두 yes 일 때만 만든다. '!' 는 명시적 no (unknown 은 해당 없음).
  const CORRELATIONS = [
    { code: 'KEV_EOL', parts: ['CISA_KEV', 'EOL_AFFECTED'], short: 'KEV × EOL',
      label: 'CISA KEV 이면서 영향 릴리스가 EOL', query: 'has:cisa-kev lifecycle:eol' },
    { code: 'KEV_PUBLIC_EXPLOIT', parts: ['CISA_KEV', 'PUBLIC_EXPLOIT'], short: 'KEV × 공개 exploit',
      label: 'CISA KEV 이면서 공개 exploit 존재', query: 'has:cisa-kev has:exploit' },
    { code: 'KEV_AUTOMATABLE', parts: ['CISA_KEV', 'AUTOMATABLE'], short: 'KEV × 자동화',
      label: 'CISA KEV 이면서 SSVC 자동화 가능', query: 'has:cisa-kev has:auto' },
    { code: 'KEV_RANSOMWARE', parts: ['CISA_KEV', 'RANSOMWARE'], short: 'KEV × 랜섬웨어',
      label: 'CISA KEV 에서 랜섬웨어 캠페인 사용 Known', query: 'has:cisa-kev has:ransom' },
    { code: 'HIGH_EPSS_KEV', parts: ['HIGH_EPSS', 'CISA_KEV'], short: 'EPSS 상위 5% × KEV',
      label: '악용 확률 예측이 높고 CISA KEV 등재', query: 'has:high-epss has:cisa-kev' },
    { code: 'CRITICAL_PUBLIC_EXPLOIT', parts: ['CRITICAL_CVSS', 'PUBLIC_EXPLOIT'], short: 'CVSS 9+ × 공개 exploit',
      label: 'CVSS 9.0 이상이면서 공개 exploit 존재', query: 'cvss:>=9 has:exploit' },
    { code: 'CRITICAL_EOL', parts: ['CRITICAL_CVSS', 'EOL_AFFECTED'], short: 'CVSS 9+ × EOL',
      label: 'CVSS 9.0 이상이면서 영향 릴리스가 EOL', query: 'cvss:>=9 lifecycle:eol' },
    { code: 'PATCH_EXPLOITED', parts: ['PATCH_AVAILABLE', 'EXPLOITATION_CONFIRMED'], short: '수정 버전 × 악용 근거',
      label: '수정 버전이 있는데 악용 근거도 있음 — 올릴 목표가 있는 악용 건', query: 'has:patch has:kev' },
    { code: 'EXPLOIT_NO_FIX', parts: ['PUBLIC_EXPLOIT', '!PATCH_AVAILABLE'], short: '공개 exploit × 수정 기록 없음',
      label: '공개 exploit 이 있는데 OSV 에 수정 버전 기록이 없음', query: 'has:exploit no:patch' },
    { code: 'EOL_NO_FIX', parts: ['EOL_AFFECTED', '!PATCH_AVAILABLE'], short: 'EOL × 수정 기록 없음',
      label: '영향 릴리스가 EOL 이고 OSV 에 수정 버전 기록이 없음', query: 'lifecycle:eol no:patch' },
  ];
  const CORRELATION = Object.fromEntries(CORRELATIONS.map(c => [c.code, c]));

  const REASON = {
    cvss_unscored: 'CVSS 점수 없음',
    epss_unscored: 'EPSS 미채점 (신규 CVE 는 채점 전일 수 있음)',
    ssvc_missing: 'CISA SSVC 판정 없음',
    kev_unknown: 'KEV 원문이 랜섬웨어 사용을 Unknown 으로 표기',
    not_in_kev: 'KEV 미등재 — 랜섬웨어 사용을 판단할 근거 없음',
    no_osv_record: 'OSV 기록 없음 (OSV 가 다루지 않는 제품이거나 아직 수집 전)',
    no_affected: '영향 제품 정보 없음',
    untracked: '수명주기 추적 대상이 아닌 제품 포함 (endoflife.date 매핑 없음)',
    unresolved: '제품은 찾았지만 영향 버전을 사이클로 특정하지 못함',
    status_unknown: 'upstream 단계가 보안·확장 지원을 명시하지 않아 상태 미상',
    lifecycle_unloaded: '수명주기 데이터를 불러오지 못함',
  };

  /* ---------- 기본 판정 (목록·검색·통계가 쓰는 빠른 경로) ---------- */

  const t = b => (b ? 'yes' : 'no');

  function scoreFacts(cve) {
    const cvss = Number(cve.cvss) || 0;
    const epss = Number(cve.epss) || 0;
    const pct = Number(cve.epss_percentile) || 0;
    return {
      cvss: cvss > 0 ? cvss : null,
      epss: epss > 0 || pct > 0 ? epss : null,
      percentile: pct > 0 ? pct : null,
    };
  }

  function epssHigh(cve) {
    const f = scoreFacts(cve);
    if (f.epss === null) return 'unknown';
    return t(f.percentile !== null ? f.percentile >= EPSS_P_HIGH : f.epss >= EPSS_SCORE_HIGH);
  }

  function hasFix(pkgMap) {
    return Object.values(pkgMap || {}).some(ecoMap =>
      Object.values(ecoMap || {}).some(fixes => (fixes || []).some(Boolean)));
  }

  function patchState(pkgMap) {
    if (!pkgMap || !Object.keys(pkgMap).length) return 'unknown';
    return t(hasFix(pkgMap));
  }

  function detectionEngines(cve) {
    const engines = [...(cve.rule_engines || [])];
    if (cve.has_nuclei_template && !engines.includes('nuclei')) engines.push('nuclei');
    return engines;
  }

  // lifecycle: { entries, unresolved, untracked } (lifecycle.js reduceMatch 결과) · products · today
  function lifecycleFacts(lc, products, today, affectedCount) {
    const counts = { ACTIVE: 0, SECURITY_SUPPORT: 0, EXTENDED_SUPPORT: 0, EOL: 0, UNKNOWN: 0 };
    const reasons = [];
    if (!lc) {
      if (!affectedCount) reasons.push('no_affected');
      else reasons.push('lifecycle_unloaded');
      return { state: 'unknown', counts, reasons, releases: 0 };
    }
    for (const e of lc.entries || []) counts[LC.statusOf(e.rel, (products || {})[e.slug], today)]++;
    counts.UNKNOWN += (lc.unresolved || []).length;
    const releases = (lc.entries || []).length;
    if (!affectedCount) reasons.push('no_affected');
    if (lc.untracked) reasons.push('untracked');
    if ((lc.unresolved || []).length) reasons.push('unresolved');
    if ((lc.entries || []).some(e => LC.statusOf(e.rel, (products || {})[e.slug], today) === 'UNKNOWN')) {
      reasons.push('status_unknown');
    }
    let state;
    if (counts.EOL > 0) state = 'yes';
    else if (releases > 0 && !reasons.length) state = 'no';
    else state = 'unknown';
    return { state, counts, reasons: state === 'yes' ? [] : reasons, releases };
  }

  // 목록·검색·통계용 판정. deps: { packages, lifecycle, products, today, affectedCount }
  function signals(cve, deps) {
    const d = deps || {};
    const f = scoreFacts(cve);
    const ssvcExp = cve.ssvc_exploitation || null;
    const auto = cve.ssvc_automatable || null;
    const lcf = lifecycleFacts(d.lifecycle, d.products, d.today,
                               d.affectedCount != null ? d.affectedCount : (cve.affected || []).length);
    const s = {
      EXPLOITATION_CONFIRMED: t(cve.is_kev || cve.is_vulncheck_kev || ssvcExp === 'active'),
      CISA_KEV: t(cve.is_kev),
      PUBLIC_EXPLOIT: t(cve.has_public_exploit || cve.has_metasploit_module || cve.has_poc),
      AUTOMATABLE: auto === 'yes' ? 'yes' : auto === 'no' ? 'no' : 'unknown',
      RANSOMWARE: cve.is_kev_ransomware ? 'yes' : 'unknown',
      EOL_AFFECTED: lcf.state,
      PATCH_AVAILABLE: patchState(d.packages),
      PUBLIC_DETECTION: t(detectionEngines(cve).length > 0 || cve.has_official_rules),
      HIGH_EPSS: epssHigh(cve),
      CRITICAL_CVSS: f.cvss === null ? 'unknown' : t(f.cvss >= CVSS_CRITICAL),
    };
    return { states: s, lifecycle: lcf };
  }

  function correlationsOf(states) {
    return CORRELATIONS.filter(c => c.parts.every(p =>
      p[0] === '!' ? states[p.slice(1)] === 'no' : states[p] === 'yes')).map(c => c.code);
  }

  function reasonsOf(cve, states, lcf) {
    const r = {};
    if (states.CRITICAL_CVSS === 'unknown') r.CRITICAL_CVSS = ['cvss_unscored'];
    if (states.HIGH_EPSS === 'unknown') r.HIGH_EPSS = ['epss_unscored'];
    if (states.AUTOMATABLE === 'unknown') r.AUTOMATABLE = ['ssvc_missing'];
    if (states.RANSOMWARE === 'unknown') r.RANSOMWARE = [cve.is_kev ? 'kev_unknown' : 'not_in_kev'];
    if (states.PATCH_AVAILABLE === 'unknown') r.PATCH_AVAILABLE = ['no_osv_record'];
    if (states.EOL_AFFECTED === 'unknown') r.EOL_AFFECTED = lcf.reasons.slice();
    return r;
  }

  /* ---------- 상세용 근거 행렬 (출처마다 hit · miss · unknown · info) ---------- */

  const row = (source, status, value, extra) => Object.assign({ source, status, value }, extra || {});

  function exploitationRows(cve) {
    const id = cve.id;
    const ssvc = cve.ssvc_exploitation || null;
    return [
      cve.is_kev
        ? row('CISA KEV', 'hit', '등재', { kind: 'listing', url: URL.kev, basis: 'CVE ID',
                                           detail: cve.kev_due_date ? `연방기관 조치기한 ${cve.kev_due_date}` : '' })
        : row('CISA KEV', 'miss', '미등재', { kind: 'listing', url: URL.kev, basis: 'CVE ID' }),
      cve.is_vulncheck_kev
        ? row('VulnCheck KEV', 'hit', '등재', { kind: 'listing', url: URL.vulncheck, basis: 'CVE ID' })
        : row('VulnCheck KEV', 'miss', '미등재', { kind: 'listing', url: URL.vulncheck, basis: 'CVE ID' }),
      ssvc === 'active'
        ? row('CISA SSVC', 'hit', 'Exploitation: active', { kind: 'assessment', url: URL.cveRecord(id), basis: 'CVE ID' })
        : ssvc
          ? row('CISA SSVC', 'miss', `Exploitation: ${ssvc}`, { kind: 'assessment', url: URL.cveRecord(id), basis: 'CVE ID' })
          : row('CISA SSVC', 'unknown', '판정 없음', { kind: 'assessment', basis: 'CVE ID' }),
    ];
  }

  function weaponizationRows(cve) {
    const rows = [];
    rows.push(cve.has_public_exploit
      ? row('Exploit-DB', 'hit', '공개 exploit 항목', { kind: 'artifact', url: cve._exploit_db_url || URL.exploitdb,
                                                          basis: 'CVE ID', detail: '원문은 싣지 않고 링크만' })
      : row('Exploit-DB', 'miss', '항목 없음', { kind: 'artifact', basis: 'CVE ID' }));
    const mods = (cve.metasploit_modules || []).filter(Boolean);
    rows.push(cve.has_metasploit_module
      ? row('Metasploit', 'hit', mods.length ? `모듈 ${mods.length}개` : '모듈 있음',
            { kind: 'artifact', url: URL.metasploit, basis: 'CVE ID', items: mods })
      : row('Metasploit', 'miss', '모듈 없음', { kind: 'artifact', basis: 'CVE ID' }));
    const pocs = [...new Set((cve.poc_urls || []).filter(Boolean))];
    rows.push(cve.has_poc
      ? row('PoC-in-GitHub', 'hit', pocs.length ? `공개 저장소 ${pocs.length}개` : '공개 PoC 있음',
            { kind: 'artifact', url: URL.poc, basis: 'CVE ID', links: pocs, detail: 'PoC 공개는 실제 공격 발생을 뜻하지 않는다' })
      : row('PoC-in-GitHub', 'miss', '없음', { kind: 'artifact', basis: 'CVE ID' }));
    if (cve.ssvc_exploitation === 'poc') {
      rows.push(row('CISA SSVC', 'info', 'Exploitation: poc', { kind: 'assessment', url: URL.cveRecord(cve.id),
        basis: 'CVE ID', detail: 'CISA 판정 — 공개 PoC 또는 잘 알려진 공격 방법이 있음(개별 exploit 링크는 아님)' }));
    }
    return rows;
  }

  function automationRows(cve) {
    const a = cve.ssvc_automatable || null;
    const rows = [a === 'yes'
      ? row('CISA SSVC', 'hit', 'Automatable: yes', { kind: 'assessment', url: URL.cveRecord(cve.id), basis: 'CVE ID',
                                                       detail: '정찰부터 익스플로잇까지 자동화 가능 — 대량 스캔·공격 대상' })
      : a
        ? row('CISA SSVC', 'miss', `Automatable: ${a}`, { kind: 'assessment', url: URL.cveRecord(cve.id), basis: 'CVE ID' })
        : row('CISA SSVC', 'unknown', '판정 없음', { kind: 'assessment', basis: 'CVE ID' })];
    if (cve.ssvc_technical_impact) {
      rows.push(row('CISA SSVC', 'info', `Technical Impact: ${cve.ssvc_technical_impact}`, {
        kind: 'assessment', url: URL.cveRecord(cve.id), basis: 'CVE ID',
        detail: cve.ssvc_technical_impact === 'total' ? '성공 시 대상 시스템을 완전히 장악' : '영향이 일부에 그침' }));
    }
    return rows;
  }

  function ransomwareRows(cve) {
    if (cve.is_kev_ransomware) {
      return [row('CISA KEV', 'hit', 'knownRansomwareCampaignUse: Known', { kind: 'listing', url: URL.kev, basis: 'CVE ID' })];
    }
    return [row('CISA KEV', 'unknown', cve.is_kev ? 'knownRansomwareCampaignUse: Unknown' : 'KEV 미등재',
                { kind: 'listing', url: URL.kev, basis: 'CVE ID' })];
  }

  function ruleInfo(cve, engine) {
    const rules = cve.rules || {};
    if (NETWORK.has(engine)) return (rules.network || []).filter(r => (r.engine || 'network') === engine);
    return rules[engine] ? [rules[engine]] : [];
  }

  function detectionRows(cve) {
    const engines = detectionEngines(cve);
    const ordered = engines.slice().sort((a, b) =>
      (ENGINE_ORDER.indexOf(a) + 1 || 99) - (ENGINE_ORDER.indexOf(b) + 1 || 99));
    const rows = ordered.map(engine => {
      const info = engineInfo(engine);
      const found = ruleInfo(cve, engine);
      const first = found[0] || {};
      const url = engine === 'nuclei' ? (cve._nuclei_url || first.url || '') : (first.url || '');
      return row(info.label, 'hit', info.kind === 'check' ? '점검 템플릿' : found.length > 1 ? `룰 ${found.length}개` : '룰',
                 { kind: info.kind, engine, url, basis: 'CVE ID', source_name: first.source || info.source,
                   license: first.license || '', author: first.author || '', count: found.length || 1,
                   detail: info.kind === 'check'
                     ? '대상에 요청을 보내 취약 여부를 확인하는 템플릿 — 공격 탐지 룰이 아니며 공격에도 쓰일 수 있다'
                     : '' });
    });
    if (!rows.length) {
      rows.push(row('공개 룰 색인', cve.has_official_rules ? 'hit' : 'miss',
                    cve.has_official_rules ? '공식 룰 있음' : '색인된 공개 룰 없음',
                    { kind: 'detect', basis: 'CVE ID', detail: 'Sigma · ET/Snort · Suricata · Splunk · YARA · nuclei 기준' }));
    }
    return rows;
  }

  function fixedVersions(pkgMap) {
    const out = [];
    for (const [pkg, ecoMap] of Object.entries(pkgMap || {})) {
      for (const [eco, fixes] of Object.entries(ecoMap || {})) {
        const f = (fixes || []).filter(Boolean);
        if (f.length) out.push({ package: pkg, ecosystem: eco, versions: f });
      }
    }
    return out;
  }

  function remediationRows(cve, pkgMap) {
    const rows = [];
    const state = patchState(pkgMap);
    const fixed = fixedVersions(pkgMap);
    if (state === 'yes') {
      rows.push(row('OSV', 'hit', `수정 버전 ${fixed.length}건`, { kind: 'record', url: URL.osv(cve.id), basis: 'CVE ID·별칭',
        fixed, packages: Object.keys(pkgMap || {}) }));
    } else if (state === 'no') {
      rows.push(row('OSV', 'miss', '수정 버전 기록 없음', { kind: 'record', url: URL.osv(cve.id), basis: 'CVE ID·별칭',
        packages: Object.keys(pkgMap || {}), detail: 'OSV 에 영향 패키지는 있으나 수정 버전(fixed 이벤트)이 기록되지 않음' }));
    } else {
      rows.push(row('OSV', 'unknown', 'OSV 기록 없음', { kind: 'record', basis: 'CVE ID·별칭',
        detail: REASON.no_osv_record }));
    }
    if (cve.is_kev && cve.kev_due_date) {
      rows.push(row('CISA KEV', 'info', `조치기한 ${cve.kev_due_date}`, { kind: 'listing', url: URL.kev, basis: 'CVE ID',
        detail: 'CISA 가 미국 연방기관에 정한 패치·완화 기한' }));
    }
    return rows;
  }

  function lifecycleRows(lc, products, today) {
    const rows = [];
    for (const e of (lc && lc.entries) || []) {
      const meta = (products || {})[e.slug] || {};
      const status = LC.statusOf(e.rel, meta, today);
      rows.push(row(meta.label || e.slug, status === 'EOL' ? 'hit' : status === 'UNKNOWN' ? 'unknown' : 'miss', status, {
        kind: 'mapping', slug: e.slug, cycle: e.rel.cycle, rel: e.rel, vendor: meta.vendor || '',
        eol_date: e.rel.eol_date || null, via: e.via, key: e.key, basis: e.basis || null,
        url: meta.source_url || URL.endoflife, original_url: meta.original_source_url || '',
        fetched_at: e.rel.fetched_at || meta.fetched_at || null,
        match: e.via === 'override' ? 'explicit' : 'automatic' }));
    }
    return rows;
  }

  // 상세 화면의 전체 맥락. deps: signals() 와 같음 + match(항목별 매칭) + affected(전체 영향 제품)
  function derive(cve, deps) {
    const d = deps || {};
    const affected = d.affected || cve.affected || [];
    const base = signals(cve, Object.assign({}, d, { affectedCount: affected.length }));
    const s = base.states;
    const f = scoreFacts(cve);
    const group = (code, rows, extra) => Object.assign({ state: s[code], rows }, extra || {});
    return {
      id: cve.id,
      states: s,
      correlations: correlationsOf(s),
      reasons: reasonsOf(cve, s, base.lifecycle),
      scores: {
        cvss: { value: f.cvss, version: cve.cvss_version || null, severity: cve.severity || 'None',
                vector: cve.cvss_vector && cve.cvss_vector !== 'N/A' ? cve.cvss_vector : null,
                alt: cve.cvss_alt || {}, sources: [{ name: 'CVE 레코드', url: URL.cveRecord(cve.id) },
                                                    { name: 'NVD', url: URL.nvd(cve.id) }] },
        epss: { value: f.epss, percentile: f.percentile, high: s.HIGH_EPSS, source: { name: 'FIRST EPSS', url: URL.epss(cve.id) } },
      },
      exploitation: group('EXPLOITATION_CONFIRMED', exploitationRows(cve), { kev: s.CISA_KEV }),
      weaponization: group('PUBLIC_EXPLOIT', weaponizationRows(cve)),
      automation: group('AUTOMATABLE', automationRows(cve)),
      ransomware: group('RANSOMWARE', ransomwareRows(cve)),
      detection: group('PUBLIC_DETECTION', detectionRows(cve)),
      remediation: group('PATCH_AVAILABLE', remediationRows(cve, d.packages), { fixed: fixedVersions(d.packages) }),
      lifecycle: group('EOL_AFFECTED', lifecycleRows(d.lifecycle, d.products, d.today), {
        counts: base.lifecycle.counts, unresolved: (d.lifecycle && d.lifecycle.unresolved) || [],
        untracked: d.lifecycle ? d.lifecycle.untracked : affected.length }),
      discovery: cve.ai_discovered
        ? { program: cve.ai_program || '', detail: cve.ai_detail || '', url: cve.ai_url || '' } : null,
      record: { published: cve.published || '', updated: cve.updated || '', date: cve.date || '' },
    };
  }

  /* ---------- 검색어 (has: · no: · unknown: · corr: · release:) ---------- */

  function stateQuery(states, value, want) {
    const code = SIGNAL_BY_KEY[String(value || '').toLowerCase()];
    return !!code && states[code] === want;
  }

  function correlationQuery(correlations, value) {
    const code = String(value || '').toUpperCase().replace(/-/g, '_');
    return !!CORRELATION[code] && correlations.includes(code);
  }

  function parseRelease(value) {
    const m = /^([a-z0-9][a-z0-9.+-]*)\/(.+)$/.exec(String(value || '').toLowerCase());
    return m ? { slug: m[1], cycle: m[2] } : null;
  }

  /* ---------- 집계 (대시보드 · 수명주기 화면) ---------- */

  function emptyCounts() {
    const out = {};
    for (const sgl of SIGNALS) out[sgl.code] = { yes: 0, no: 0, unknown: 0 };
    return out;
  }

  // items: [{ id, states, correlations, releases: ['slug|cycle', ...], exploited }]
  function aggregate(items) {
    const signalsOut = emptyCounts();
    const corr = Object.fromEntries(CORRELATIONS.map(c => [c.code, 0]));
    const releases = {};
    const lifecycle = { mapped: 0, cycle_level: 0, product_only: 0 };
    for (const it of items) {
      for (const [code, st] of Object.entries(it.states)) signalsOut[code][st]++;
      for (const c of it.correlations) corr[c]++;
      if (it.releases && it.releases.length) lifecycle.cycle_level++;
      else if (it.productOnly) lifecycle.product_only++;
      for (const key of it.releases || []) {
        const r = releases[key] || (releases[key] = { cves: 0, kev: 0, exploited: 0, exploit: 0, detection: 0,
                                                      patch: 0, critical: 0 });
        r.cves++;
        if (it.states.CISA_KEV === 'yes') r.kev++;
        if (it.states.EXPLOITATION_CONFIRMED === 'yes') r.exploited++;
        if (it.states.PUBLIC_EXPLOIT === 'yes') r.exploit++;
        if (it.states.PUBLIC_DETECTION === 'yes') r.detection++;
        if (it.states.PATCH_AVAILABLE === 'yes') r.patch++;
        if (it.states.CRITICAL_CVSS === 'yes') r.critical++;
      }
    }
    lifecycle.mapped = lifecycle.cycle_level + lifecycle.product_only;
    return { total: items.length, signals: signalsOut, correlations: corr, releases, lifecycle };
  }

  /* ---------- 데이터 품질 점검 ---------- */

  const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
  const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

  // cves: cves.json 행 · packages: cve-packages 의 packages · lifecycle: lifecycle.json
  function qualityChecks(cves, deps) {
    const d = deps || {};
    const checks = [];
    // warn: 데이터끼리 어긋남(고칠 대상) · info: 원래 비어 있는 값(unknown 으로 표시하면 되는 것)
    const add = (id, label, bad, note, level) => checks.push({
      id, label, status: bad.length ? (level || 'warn') : 'ok', count: bad.length, examples: bad.slice(0, 5),
      note: note || '' });
    const ids = cves.map(c => c && c.id);
    add('cve_id_invalid', 'CVE ID 형식 오류', ids.filter(i => !CVE_ID.test(String(i || ''))));
    const seen = new Set(), dup = new Set();
    for (const i of ids) { if (seen.has(i)) dup.add(i); seen.add(i); }
    add('cve_duplicate', '중복 CVE', [...dup]);
    add('cvss_missing', 'CVSS 점수 없음 (unknown 으로 표시)', cves.filter(c => !(Number(c.cvss) > 0)).map(c => c.id),
        '0 점이 아니라 점수 없음으로 다룬다', 'info');
    add('epss_missing', 'EPSS 미채점 (unknown 으로 표시)',
        cves.filter(c => !(Number(c.epss) > 0) && !(Number(c.epss_percentile) > 0)).map(c => c.id),
        '0% 가 아니라 채점 전으로 다룬다', 'info');
    add('ssvc_missing', 'CISA SSVC 판정 없음 (unknown 으로 표시)',
        cves.filter(c => !c.ssvc_exploitation && !c.ssvc_automatable).map(c => c.id), '', 'info');
    add('kev_ransom_without_kev', 'KEV 미등재인데 랜섬웨어 표시', cves.filter(c => c.is_kev_ransomware && !c.is_kev).map(c => c.id));
    add('kev_due_without_kev', 'KEV 미등재인데 조치기한 있음', cves.filter(c => c.kev_due_date && !c.is_kev).map(c => c.id));
    add('kev_without_due', 'KEV 등재인데 조치기한 없음', cves.filter(c => c.is_kev && !c.kev_due_date).map(c => c.id));
    add('edb_flag_without_url', 'Exploit-DB 표시가 있는데 링크 없음',
        cves.filter(c => c.has_public_exploit && !c._exploit_db_url).map(c => c.id));
    add('poc_flag_without_url', 'PoC 표시가 있는데 링크 없음', cves.filter(c => c.has_poc && !(c.poc_urls || []).length).map(c => c.id));
    add('poc_duplicate_url', 'PoC 링크 중복', cves.filter(c => {
      const u = (c.poc_urls || []).filter(Boolean);
      return new Set(u.map(x => x.toLowerCase().replace(/\/+$/, ''))).size !== u.length;
    }).map(c => c.id));
    add('msf_flag_without_module', 'Metasploit 표시가 있는데 모듈명 없음',
        cves.filter(c => c.has_metasploit_module && !(c.metasploit_modules || []).length).map(c => c.id));
    add('reference_duplicate', '참고 링크 중복', cves.filter(c => {
      const u = (c.references || []).filter(Boolean);
      return new Set(u).size !== u.length;
    }).map(c => c.id));
    const lc = d.lifecycle;
    if (lc && Array.isArray(lc.releases)) {
      const dateFields = ['release_date', 'support_end', 'security_support_end', 'extended_support_end', 'eol_date',
                          'latest_release_date'];
      add('lifecycle_bad_date', '수명주기 날짜 형식 오류', lc.releases.filter(r =>
        dateFields.some(k => r[k] != null && !(ISO_DATE.test(String(r[k])) && !isNaN(Date.parse(`${r[k]}T00:00:00Z`)))))
        .map(r => `${r.product_slug}|${r.cycle}`));
      add('lifecycle_bad_cycle', '수명주기 사이클 이름 오류', lc.releases.filter(r =>
        !r.cycle || !/^[a-z0-9][a-z0-9.+-]*$/i.test(String(r.cycle))).map(r => `${r.product_slug}|${r.cycle}`));
      const known = new Set(LC.STATUSES);
      add('lifecycle_bad_status', '수명주기 상태값 오류', lc.releases.filter(r => !known.has(r.lifecycle_status))
        .map(r => `${r.product_slug}|${r.cycle}`));
      const keys = new Set(), dupRel = new Set();
      for (const r of lc.releases) {
        const k = `${r.product_slug}|${r.cycle}`;
        if (keys.has(k)) dupRel.add(k);
        keys.add(k);
      }
      add('lifecycle_duplicate_release', '수명주기 릴리스 중복', [...dupRel]);
      add('lifecycle_unavailable', 'endoflife.date 에 없는 추적 제품 (UNKNOWN 처리)',
          (lc.unavailable || []).map(u => u.slug), '데이터를 만들지 않는다 — 오류가 아니라 범위 표시', 'info');
    }
    if (d.kevCatalog) {
      const tracked = new Map(cves.map(c => [c.id, c]));
      add('kev_catalog_not_flagged', 'KEV 카탈로그에 있는데 추적 데이터는 KEV 아님',
          [...d.kevCatalog].filter(id => tracked.has(id) && !tracked.get(id).is_kev));
      add('kev_flag_not_in_catalog', '추적 데이터는 KEV 인데 카탈로그에 없음',
          cves.filter(c => c.is_kev && !d.kevCatalog.has(c.id)).map(c => c.id));
    }
    return checks;
  }

  /* ---------- 입력 지문 (사전 계산 결과가 지금 받은 파일과 같은 판에서 나왔는지) ---------- */

  function hashString(text) {
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }

  function fingerprint(files) {
    const f = files || {};
    const pk = (f.packages && f.packages.packages) || null;
    let pkgEntries = 0;
    if (pk) for (const m of Object.values(pk)) pkgEntries += Object.keys(m || {}).length;
    // cves 는 stats.json 만으로 확인할 수 있게 한다(export 가 total = len(cves) 로 쓴다) — 큰 파일보다 먼저 판단.
    return {
      cves: f.stats ? `${f.stats.generated_at || ''}|${(f.stats.cve && f.stats.cve.total) || 0}` : null,
      products: f.products ? String(f.products.generated_at || '') : null,
      packages: pk ? `${Object.keys(pk).length}|${pkgEntries}` : null,
      lifecycle: f.lifecycle ? `${f.lifecycle.generated_at || ''}|${(f.lifecycle.releases || []).length}` : null,
      aliases: f.aliases ? hashString(JSON.stringify(f.aliases)) : null,
    };
  }

  function sameFingerprint(a, b) {
    if (!a || !b) return false;
    return ['cves', 'products', 'packages', 'lifecycle', 'aliases'].every(k => (a[k] || null) === (b[k] || null));
  }

  return {
    EPSS_P_HIGH, EPSS_SCORE_HIGH, CVSS_CRITICAL, URL, ENGINES, ENGINE_ORDER, engineInfo,
    SIGNALS, SIGNAL, SIGNAL_BY_KEY, CORRELATIONS, CORRELATION, REASON,
    scoreFacts, epssHigh, patchState, hasFix, fixedVersions, detectionEngines, lifecycleFacts,
    signals, correlationsOf, reasonsOf, derive,
    stateQuery, correlationQuery, parseRelease,
    aggregate, qualityChecks, hashString, fingerprint, sameFingerprint,
  };
});
