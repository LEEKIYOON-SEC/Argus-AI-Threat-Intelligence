(function (root, factory) {
  'use strict';
  const node = typeof module !== 'undefined' && module.exports;
  const api = factory(node ? require('./cwe-data.js') : root.ArgusCWEData);
  root.ArgusCWE = api;
  if (node) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis, function (DATA) {
  'use strict';

  /*
   * 취약점 유형(CWE) — 목록 칩 · 상세 제목 옆 · 상세 '취약점 유형' 칸이 쓰는 이름과 한 줄 풀이.
   *
   * 이름: 그 CWE 가 붙은 CVE 의 제목 · 요약(이 사이트의 글)에서 약점을 가리킬 때 가장 많이 쓰인 말.
   *   '원격 코드 실행' · '권한 상승'처럼 결과를 뜻하는 말은 쓰지 않는다. 그래서 영어가 더 많이 쓰이면 영어
   *   (Use-After-Free · Path Traversal), 약자면 약자(XSS · SSRF), 한국어가 많으면 한국어(SQL 인젝션 · 인증 우회).
   *   실측(2026-09-28, CVE 10,976건): CWE-416 요약의 79%가 'use-after-free', '해제 후 사용' 0% · CWE-89 는 'SQL 인젝션' 88%.
   * 풀이: 무엇이 잘못된 결함인지 한 줄 — MITRE CWE 설명을 바탕으로 Argus 가 쓴 글. 원인을 넓게 묶은 CWE 는 '(넓은 분류)'.
   * 표에 없는 번호는 MITRE 공식 영문 이름(cwe-data.js)의 따옴표 안 별칭 → 30자 이하면 이름 그대로 → 번호.
   * 폐기된 번호('DEPRECATED: …')는 늘 번호.
   *
   * CWE 가 여러 개면 더 구체적인 것 하나를 고른다 — 추상화 수준 Variant › Base › Compound › Class › Pillar,
   * 폐기 · 분류(Category) 번호 · 모르는 번호는 맨 뒤. 같은 수준이면 레코드에 적힌 순서(CNA 가 먼저 적은 것).
   * 예: CWE-200(정보 노출, Class) + CWE-89(Base) → SQL 인젝션.
   */

  const GLOSS = {
    'CWE-20': ['입력값 검증 미흡', '입력값이 올바른지 확인하지 않거나 잘못 확인하는 결함(넓은 분류)'],
    'CWE-22': ['Path Traversal', '경로에 ../ 등을 넣어 허용된 폴더 밖 파일에 접근하는 결함'],
    'CWE-23': ['Path Traversal', '상대 경로(../)로 허용된 폴더 밖 파일에 접근하는 결함'],
    'CWE-24': ['Path Traversal', '../ 경로로 허용된 폴더 밖 파일에 접근하는 결함'],
    'CWE-29': ['Path Traversal', '..\\ 같은 경로로 허용된 폴더 밖 파일에 접근하는 결함'],
    'CWE-35': ['Path Traversal', '.../...// 같은 경로로 허용된 폴더 밖 파일에 접근하는 결함'],
    'CWE-36': ['Path Traversal', '절대 경로(/로 시작하는 경로)로 허용된 폴더 밖 파일에 접근하는 결함'],
    'CWE-59': ['심볼릭 링크 악용', '파일이 링크인지 확인하지 않아 다른 파일을 읽거나 덮어쓰는 결함'],
    'CWE-73': ['파일 경로 조작', '입력값으로 파일 이름 · 경로를 정할 수 있는 결함'],
    'CWE-74': ['인젝션', '입력값이 명령 · 쿼리 등에 섞여 해석이 바뀌는 결함(넓은 분류)'],
    'CWE-77': ['Command Injection', '입력값이 명령에 섞여 명령이 바뀌거나 추가되는 결함'],
    'CWE-78': ['OS Command Injection', '입력값이 운영체제 명령에 섞여 임의 명령이 실행되는 결함'],
    'CWE-79': ['XSS', '입력값이 웹 페이지에 그대로 실려 방문자 브라우저에서 스크립트가 실행되는 결함'],
    'CWE-80': ['XSS', '입력값의 HTML 태그를 걸러내지 않아 방문자 브라우저에서 스크립트가 실행되는 결함'],
    'CWE-88': ['Argument Injection', '입력값이 명령의 인자(옵션)로 해석되는 결함'],
    'CWE-89': ['SQL 인젝션', '입력값이 SQL 문에 섞여 데이터베이스 명령이 바뀌는 결함'],
    'CWE-94': ['코드 인젝션', '입력값이 실행되는 코드에 섞여 공격자 코드가 실행되는 결함'],
    'CWE-95': ['Eval Injection', '입력값이 eval 같은 동적 실행 함수에 들어가 코드로 실행되는 결함'],
    'CWE-98': ['File Inclusion', 'PHP include에 넣는 파일 이름을 제한하지 않아 다른 파일을 불러오는 결함'],
    'CWE-116': ['출력 인코딩 누락', '다른 구성 요소로 보내는 데이터를 알맞게 인코딩 · 이스케이프하지 않는 결함'],
    'CWE-119': ['버퍼 오버플로', '메모리 버퍼 범위를 벗어나 읽거나 쓰는 결함(넓은 분류)'],
    'CWE-120': ['버퍼 오버플로', '입력 크기를 확인하지 않고 버퍼에 복사하는 결함'],
    'CWE-121': ['스택 버퍼 오버플로', '스택(함수 안 변수) 버퍼 범위를 넘어 쓰는 결함'],
    'CWE-122': ['힙 버퍼 오버플로', '힙(동적 할당) 버퍼 범위를 넘어 쓰는 결함'],
    'CWE-125': ['Out-of-bounds Read', '할당된 메모리 범위 밖을 읽는 결함'],
    'CWE-190': ['정수 오버플로', '계산 결과가 정수 범위를 넘어 엉뚱한 값이 되는 결함'],
    'CWE-200': ['정보 노출', '권한 없는 사람에게 민감한 정보가 보이는 결함'],
    'CWE-201': ['응답에 민감 정보', '보내는 데이터에 보여 주면 안 되는 정보가 섞인 결함'],
    'CWE-203': ['사이드 채널', '응답 시간 · 결과 차이로 내부 정보를 알아낼 수 있는 결함'],
    'CWE-259': ['하드코딩된 비밀번호', '비밀번호가 제품 안에 고정돼 있는 결함'],
    'CWE-266': ['잘못된 권한 부여', '사용자 · 프로세스에 필요 이상의 권한을 주는 결함'],
    'CWE-269': ['권한 관리 오류', '권한을 잘못 주거나 확인해 더 높은 권한을 얻게 되는 결함'],
    'CWE-284': ['접근 제어 결함', '권한 없는 접근을 막지 못하는 결함(넓은 분류)'],
    'CWE-285': ['권한 확인 오류', '권한 확인을 하지 않거나 잘못 하는 결함'],
    'CWE-287': ['인증 우회', '신원 확인이 부실해 인증을 통과할 수 있는 결함'],
    'CWE-288': ['인증 우회', '인증을 거치지 않는 다른 경로가 있는 결함'],
    'CWE-290': ['스푸핑 인증 우회', '위조할 수 있는 값(IP · 헤더 등)으로 신원을 판단하는 결함'],
    'CWE-294': ['재전송 인증 우회', '가로챈 인증 메시지를 다시 보내 인증을 통과할 수 있는 결함'],
    'CWE-295': ['인증서 검증 오류', 'TLS 인증서를 확인하지 않거나 잘못 확인하는 결함'],
    'CWE-305': ['인증 우회', '인증 방식은 맞지만 구현의 다른 결함으로 건너뛸 수 있는 결함'],
    'CWE-306': ['인증 누락', '로그인 없이도 중요한 기능을 쓸 수 있는 결함'],
    'CWE-312': ['민감 정보 평문 저장', '민감한 정보를 암호화하지 않고 저장하는 결함'],
    'CWE-321': ['하드코딩된 암호 키', '암호화 키가 제품 안에 고정돼 있는 결함'],
    'CWE-345': ['출처 확인 누락', '데이터가 진짜 출처에서 왔는지 확인하지 않는 결함'],
    'CWE-346': ['출처 검증 오류', '요청의 출처(Origin 등)를 제대로 확인하지 않는 결함'],
    'CWE-347': ['서명 검증 오류', '전자서명을 확인하지 않거나 잘못 확인하는 결함'],
    'CWE-352': ['CSRF', '로그인한 사용자가 모르게 요청을 보내게 만드는 결함'],
    'CWE-359': ['개인정보 노출', '개인정보가 권한 없는 사람에게 보이는 결함'],
    'CWE-362': ['Race Condition', '동시에 실행되는 작업 사이의 순서 틈을 노릴 수 있는 결함'],
    'CWE-367': ['TOCTOU', '확인한 뒤 사용하기 전 사이에 자원이 바뀔 수 있는 결함'],
    'CWE-400': ['자원 고갈(DoS)', '메모리 · CPU 사용을 제한하지 않아 서비스가 멈출 수 있는 결함'],
    'CWE-404': ['자원 해제 오류', '쓴 자원을 해제하지 않거나 잘못 해제하는 결함'],
    'CWE-415': ['Double Free', '같은 메모리를 두 번 해제하는 결함'],
    'CWE-416': ['Use-After-Free', '이미 해제한 메모리를 다시 사용하는 결함'],
    'CWE-426': ['검색 경로 조작', '외부가 정한 검색 경로로 중요한 파일을 찾아 공격자 파일을 불러올 수 있는 결함'],
    'CWE-427': ['검색 경로 조작', '라이브러리 · 실행 파일을 찾는 경로에 공격자 파일이 끼어들 수 있는 결함(DLL 하이재킹 등)'],
    'CWE-434': ['위험한 파일 업로드', '웹셸처럼 실행될 수 있는 파일을 올릴 수 있는 결함'],
    'CWE-444': ['HTTP 요청 스머글링', '프록시와 서버가 HTTP 요청의 경계를 다르게 해석하는 결함'],
    'CWE-451': ['화면 표시 위장', '주소 · 발신자 같은 중요한 정보를 화면에 잘못 보여 줘 속일 수 있는 결함'],
    'CWE-470': ['Unsafe Reflection', '입력값으로 불러올 클래스 · 코드를 고를 수 있는 결함'],
    'CWE-476': ['NULL 포인터 역참조', 'NULL인 포인터를 사용해 대개 프로그램이 비정상 종료되는 결함'],
    'CWE-502': ['안전하지 않은 역직렬화', '외부에서 받은 데이터를 검증 없이 객체로 되살리는 결함'],
    'CWE-506': ['악성 코드 포함', '제품 안에 악성 코드가 들어 있음(공급망 공격 등)'],
    'CWE-522': ['자격 증명 보호 미흡', '비밀번호 · 토큰을 안전하지 않게 저장 · 전송하는 결함'],
    'CWE-532': ['로그에 민감 정보', '비밀번호 · 토큰 같은 정보를 로그에 남기는 결함'],
    'CWE-552': ['외부 접근 가능한 파일', '외부에서 보면 안 되는 파일 · 폴더에 접근할 수 있는 결함'],
    'CWE-601': ['Open Redirect', '사용자가 넣은 외부 주소로 그대로 이동시키는 결함'],
    'CWE-611': ['XXE', 'XML 외부 엔티티를 허용해 서버 파일 · 내부 주소에 접근되는 결함'],
    'CWE-613': ['세션 만료 미흡', '만료됐어야 할 세션 · 토큰을 다시 쓸 수 있는 결함'],
    'CWE-639': ['IDOR', '요청의 ID 값만 바꿔 다른 사용자 데이터에 접근하는 결함'],
    'CWE-693': ['보안 기능 우회', '보안 기능이 없거나 잘못 동작하는 결함(넓은 분류)'],
    'CWE-732': ['파일 권한 설정 오류', '중요 파일 · 폴더의 접근 권한을 너무 넓게 준 결함'],
    'CWE-754': ['예외 상황 확인 누락', '드물거나 예외적인 상황을 확인하지 않거나 잘못 확인하는 결함'],
    'CWE-770': ['자원 고갈(DoS)', '자원 할당에 한도가 없어 서비스가 멈출 수 있는 결함'],
    'CWE-787': ['Out-of-bounds Write', '할당된 메모리 범위 밖에 데이터를 쓰는 결함'],
    'CWE-798': ['하드코딩된 자격 증명', '비밀번호 · 키가 제품 안에 고정돼 있는 결함'],
    'CWE-822': ['Untrusted Pointer Dereference', '외부에서 받은 값을 포인터로 바꿔 그대로 사용하는 결함'],
    'CWE-843': ['Type Confusion', '메모리의 데이터를 원래와 다른 자료형으로 다루는 결함'],
    'CWE-862': ['권한 확인 누락', '그 작업을 해도 되는 사용자인지 확인하지 않는 결함'],
    'CWE-863': ['권한 우회', '권한 확인을 잘못해 허용되지 않은 작업을 할 수 있는 결함'],
    'CWE-917': ['Expression Language Injection', '입력값이 표현 언어(EL) 식에 섞여 서버에서 실행되는 결함'],
    'CWE-918': ['SSRF', '서버가 공격자가 준 주소로 대신 요청을 보내는 결함'],
    'CWE-1188': ['안전하지 않은 기본 설정', '바꿔 써야 할 기본값(기본 비밀번호 등)이 안전하지 않은 결함'],
    'CWE-1321': ['Prototype Pollution', '입력값으로 JavaScript 객체의 프로토타입을 바꿀 수 있는 결함'],
    'CWE-1336': ['템플릿 인젝션', '입력값이 템플릿 문법으로 해석돼 서버에서 실행되는 결함'],
  };

  const RANK = { V: 0, B: 1, M: 2, C: 3, P: 4 };
  const WORST = 5;

  // 레코드의 CWE — 'NVD-CWE-noinfo' 같은 NVD 표기와 형식이 다른 값은 뺀다. 대문자 'CWE-번호'로, 겹치면 한 번만.
  function listOf(cwes) {
    const out = [];
    for (const x of Array.isArray(cwes) ? cwes : []) {
      const m = /^CWE-(\d+)$/i.exec(String(x || '').trim());
      if (m && !out.includes(`CWE-${m[1]}`)) out.push(`CWE-${m[1]}`);
    }
    return out;
  }

  const entry = id => (DATA && DATA.w ? DATA.w[id.slice(4)] : undefined);
  function rankOf(id) {
    const w = entry(id);
    return w && w[0] in RANK ? RANK[w[0]] : WORST;
  }

  function pick(cwes) {
    let best = null, bestRank = Infinity;
    for (const id of listOf(cwes)) {
      const r = rankOf(id);
      if (r < bestRank) { best = id; bestRank = r; }
    }
    return best;
  }

  // 공식 영문 이름 — 약점이면 이름, 분류(Category) 번호면 분류 이름, 모르면 ''.
  function officialName(id) {
    const w = entry(id);
    if (w) return w.slice(2);
    return (DATA && DATA.c && DATA.c[id.slice(4)]) || '';
  }

  // { id, name, explain, en, category } — CWE 가 없으면 null. category: MITRE 분류 번호(구체적인 약점이 아님).
  function typeOf(cwes) {
    const id = pick(cwes);
    if (!id) return null;
    const en = officialName(id);
    const g = GLOSS[id];
    if (g) return { id, name: g[0], explain: g[1], en, category: false };
    const category = !entry(id) && !!en;
    // 폐기된 번호('DEPRECATED: …')는 이름 대신 번호 — 공식 이름은 마우스를 올리면 보인다.
    if (/^DEPRECATED:/i.test(en)) return { id, name: id, explain: '', en, category };
    const alias = (/\('([^']+)'\)\s*$/.exec(en) || [])[1] || (/^Path Traversal:/.test(en) ? 'Path Traversal' : '');
    return { id, name: alias || (en && en.length <= 30 ? en : id), explain: '', en, category };
  }

  // 칩 · 칸에 마우스를 올렸을 때 — '이름 — 풀이 (번호 공식 이름)'
  function titleOf(t) {
    if (!t) return '';
    const note = t.explain || (t.category ? 'MITRE 분류 번호(구체적인 약점이 아님)' : '');
    return `${t.name}${note ? ` — ${note}` : ''} (${t.id}${t.en && t.en !== t.name ? ` ${t.en}` : ''})`;
  }

  const link = id => `https://cwe.mitre.org/data/definitions/${String(id).replace(/^CWE-/i, '')}.html`;

  return { GLOSS, RANK, listOf, rankOf, pick, officialName, typeOf, titleOf, link,
           version: (DATA && DATA.version) || '', date: (DATA && DATA.date) || '' };
});
