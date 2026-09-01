<div align="center">

# Argus

**고위험 취약점만 빠르게 알려주는 CVE 위협 인텔리전스 파이프라인**

하루에 공개되는 CVE 2,000여 건 중, 실제로 지금 봐야 하는 **15건**만 골라 Slack으로 보냅니다.

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![GitHub Actions](https://img.shields.io/badge/Runtime-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)](.github/workflows/argus-fast.yml)
[![Dashboard](https://img.shields.io/badge/Dashboard-GitHub%20Pages-222?logo=github&logoColor=white)](https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/cve.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-3fb950)](LICENSE)
[![Infra Cost](https://img.shields.io/badge/Infra-Free%20Tier-3fb950)](#운영-비용)

### 🔗 [**라이브 대시보드**](https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/cve.html)

</div>

---

## 무엇을 해결하나

공개된 취약점은 하루만 지나도 N-day가 됩니다. 공격 코드가 돌기 시작하면 그다음은 시간 문제입니다.
CISA KEV는 등재 기준 자체가 "조치 방법이 이미 있는 취약점"이라, 이 목록에 오른 건은
**패치가 나와 있는데도 실제로 악용됐다**는 뜻입니다.

국내에서도 같은 일이 반복됩니다.

| 시점 | 무슨 일이 있었나 | 결과 |
| :--- | :--- | :--- |
| 2017-10 | 오라클이 WebLogic 원격코드실행(`CVE-2017-10271`) 패치 배포 | 이후 CISA KEV 등재 · 랜섬웨어 악용 확인 |
| 2024-11 | 국내 대학 2곳, 같은 패치를 **6년 이상** 미적용 상태로 침해 | 과징금 1억 9,300만원 · 4,280만원 |
| 2025-08 | 국내 카드사, 결제 서버 **48대 중 1대**에 같은 패치 누락 | 고객 297만 명 정보 유출 |

<sub>공개 8년이 지난 취약점 하나가 국내에서 계속 반복됐습니다. 출처: 개인정보보호위원회 처분(2024-11-14),
금융당국 합동조사 결과 및 관련 보도(2025), CISA KEV 카탈로그. 피해 기관은 업종으로만 적었습니다.</sub>

선을 하나 그어두면, **제로데이는 이 파이프라인의 범위가 아닙니다.** 패치도 정보도 없는 시점의
공격은 행위 기반 탐지 장비가 맡을 영역이고, Argus는 **공개된 다음부터 조치 전까지의 구간**을 맡습니다.

---

## 어려운 건 판단이 아니라 양입니다

하루 2,000여 건이 쏟아지는데 그중 지금 손대야 하는 건 손에 꼽습니다. 그래서 **무엇을 알리지
않을지**가 이 도구의 핵심입니다.

가장 흔한 실패는 "CVSS가 높으면 알린다"입니다. 실제로 재보면 이렇습니다.

**2026-08-27~28 · CVE 3,951건 전수 판정**

| 알림 조건 | 하루 알림 |
| :--- | ---: |
| 악용 신호만 (KEV · VulnCheck KEV · Metasploit · SSVC active · nuclei · Exploit-DB · EPSS 상위 1%) | **15건** ← 채택 |
| \+ CVSS ≥ 9 & 원격·인증불필요 | 162건 |
| \+ CVSS ≥ 9 & 원격·인증불필요·사용자관여없음·저복잡도 | 128건 |
| \+ 위 조건 + 두 번째 근거 요구 | 57건 |

점수만 높은 건이 하루 100건 넘게 나오는 이유는 단순합니다 — CNA와 CISA ADP가 9.8을 일괄
부여하고, 그중 압도적 다수는 악용 근거가 없습니다. **그래서 Argus에서 CVSS는 단독으로
어떤 알림도 만들지 못합니다.** 점수 기반 '될 가능성'은 알림 대신 대시보드에서 봅니다.

---

## 위험 티어

대시보드에는 `T0`/`T1` 같은 코드명이 아니라 **뜻**이 그대로 나옵니다 — 악용 중 · 무기화 임박 ·
관찰 · 신호 없음. 목록을 훑는 사람에게 'T0'은 아무것도 알려주지 않기 때문입니다.

| 티어 | 화면 표기 | 조건 | 처리 | 하루 |
| :--- | :--- | :--- | :--- | ---: |
| **T0** 관측된 악용 | 🚨 악용 중 | CISA KEV · VulnCheck KEV · SSVC Exploitation=active · Metasploit 모듈 | **Slack 즉시** + 리포트 | ~10건 |
| **T1** 무기화 임박 | ⚠️ 무기화 | nuclei 템플릿 · Exploit-DB · EPSS 상위 1%(p99) · **AI 발견 공개** | **Slack 즉시** + 리포트 | ~5건 |
| **T2** 될 가능성 | 📋 관찰 | CVSS 9+ 사전인증 원격 **AND 두 번째 근거** · 무기화 쉬운 CWE + 원격 · SSVC Automatable/Total · EPSS 상위 5% · 주요 벤더 무점수 신규 | 대시보드 추적 + 시간별 요약 | ~144건 |
| **T3** | · 신호 없음 | 그 외 | **저장하지 않음** | ~1,816건 |

화면이 표시하는 등급은 **저장된 판정값과 그 행이 실제로 들고 있는 신호 중 더 위험한 쪽**입니다.
없는 값을 특정 등급으로 단정하지 않습니다 — 예전에는 판정값이 없으면 T2로 뒀는데, `tier` 필드가
2-lane 개편에서 새로 생긴 값이라 그 이전 행에는 전부 없었고, 그래서 **CISA KEV에 올라 있는 CVE가
'관찰'로 표시됐습니다.** 판정(`risk.evaluate`)은 상태 dict의 순수 함수라 export가 그대로 부릅니다.

T3을 저장하지 않아도 놓치지 않습니다. 나중에 그 CVE에 신호가 붙으면 **소스 쪽에서** 잡아옵니다
(아래 참조). 우리 DB에 있었는지와 무관합니다.

**EPSS는 절대 점수 대신 percentile을 씁니다.** 점수 0.1은 임의값이고 모델이 갱신되면 같은 값의
의미가 달라집니다. 실측(366,357건): p99 ≈ 0.571 (상위 1%), p95 ≈ 0.093 (상위 5%).

---

## AI가 찾은 취약점

AI 에이전트가 찾아 책임공개되는 취약점이 빠르게 늘고 있습니다. 이건 **악용 신호가 아니라
출처(provenance) 신호**입니다 — 공개 시점에 이미 패치돼 있는 경우가 많지만(Anthropic 레저
실측 fix_rate 95.3%), 공개와 동시에 상세가 함께 공개되므로 N-day 위험은 실재합니다.
물량이 하루 1~2건이라 알림에 얹어도 묻히지 않습니다.

두 갈래로 잡습니다.

**① Anthropic Disclosure Ledger** — `red.anthropic.com/2026/cvd/data/payload.json`
CVE ID ↔ ANT ID를 직접 이어 주는 구조화 데이터입니다(실측 CVE 69건, 레저 전체 2,736건).
새 공개는 스냅샷 대조로 잡히므로 우리 DB에 그 CVE가 있었는지와 무관합니다.

> 주의: 페이지 URL(`/ledger/payload.json`)은 사이트 셸 HTML을 200으로 돌려줍니다.
> 실제 경로는 `/data/` 아래입니다 — 여기서 틀리면 조용히 HTML을 파싱하게 됩니다.

**② CVE 레코드의 `credits` 필드** — 소스를 새로 붙일 필요가 없습니다. 우리가 이미 받는
레코드 안에 있습니다(실측 15% 보유).

```
"Red Hat would like to thank Google Big Sleep for reporting this issue."
"Nicholas Carlini using Claude, Anthropic"
"Thai Duong (Calif.io in collaboration with Claude and Anthropic Research)"
"Red Hat would like to thank John Walker (ZeroPath) ..."
```

패턴은 **프로그램 고유명만** 씁니다(Big Sleep · Claude/Anthropic · ZeroPath · XBOW ·
CodeMender · AIxCC). `AI`·`LLM`·`OpenAI` 같은 일반어를 넣으면
`Kostya Kortchinsky | OpenAI`처럼 **소속을 발견 주체로 오인**합니다 — OpenAI 소속 사람
연구원이지 AI가 찾은 게 아닙니다. 매칭된 크레딧 원문을 그대로 들고 다녀, 오탐이 나면
알림과 대시보드에서 눈에 보이게 했습니다.

대시보드에서 `🧠 AI 발견` 필터로 따로 볼 수 있습니다.

---

## 동작 방식

```
┌─ fast-lane (5분) ───────────────────────── 탐지 → Slack 목표 10분 이내
│  ① cvelistV5 delta 피드로 바뀐 CVE 수집        (1 요청)
│  ② 메모리 신호로 티어 판정 → T0/T1이면 Slack 즉시
│  ③ CISA KEV · VulnCheck KEV 스냅샷 대조
│  ※ AI 번역·분석·룰 검색을 하지 않는다 — 알림이 그 뒤에 줄 서지 않게
└─
┌─ bulk-lane (시간별) ─────────────────────
│  무거운 스냅샷 대조(nuclei·Metasploit·Exploit-DB·EPSS) · AI 심층 분석 리포트
│  · 한국어 번역 · 공개 탐지 룰 · 대시보드 배포
└─
┌─ maintenance (주 1회) ───────────────────
│  OSV 패키지 역인덱스 · CVE↔탐지룰 역인덱스
└─
```

### 수집 — 커밋 순회에서 delta 피드로

예전에는 GitHub 커밋 API를 순회했습니다. 커밋 목록을 최대 300페이지 넘기고, 커밋마다 상세를
다시 불러 파일명에서 CVE를 긁고, 그 CVE마다 원문을 받아 해시를 비교했습니다. **변경분을
'발견'하는 데만 수백 번의 API 호출**이 들었고 그 시간이 알림 지연으로 넘어갔습니다.

지금은 `cves/deltaLog.json`을 Range 요청으로 앞부분만 받습니다(1 요청). 긴 공백은 일별
delta ZIP으로 메웁니다 — 레코드 원문이 통째로 들어 있어 CVE마다 따로 받을 필요가 없습니다.

실측으로 확인한 함정 두 가지를 코드와 테스트에 못박아 뒀습니다.

- **워터마크는 배치 `fetchTime` 기준이어야 합니다.** 항목의 `dateUpdated`로 거르면 30일
  79,897건 중 **6.4%**(최대 6.7시간 지연)가 조용히 사라집니다.
- **delta ZIP은 시간별이 아니라 자정부터의 누적입니다.** 19Z ⊂ 23Z이고 00Z에 리셋됩니다.

### 에스컬레이션 — DB 조회가 아니라 소스측 대조

저위험이던 CVE가 나중에 고위험이 되는 걸 잡는 게 이 도구의 존재 이유 중 하나입니다.

예전에는 DB에서 후보를 골라 재평가했는데, 그 조회 조건(`최근 30일 · 300건 · is_kev=false`)이
**그대로 사각지대**였습니다. 2년 전 저위험 CVE에 오늘 Metasploit 모듈이 올라오면 못 잡았습니다.

지금은 방향을 뒤집어 **신호 소스를 전량 받아 지난 회차와 비교**합니다. KEV(1,685) ·
VulnCheck KEV · nuclei(4,363) · Metasploit(3,198) · Exploit-DB(25,058) · EPSS(366,357) —
전부 통째로 받을 수 있습니다. 새로 들어온 것이 곧 에스컬레이션이고, 전 기간이 덮입니다.

비용은 **digest 게이팅**으로 눌렀습니다. 먼저 해시만 비교하고(수십 바이트), 다를 때만 집합을
읽습니다. 업스트림이 실제로 바뀌는 건 하루 한두 번이라 대부분의 실행은 해시 비교에서 끝납니다.

안전 규칙 두 가지가 있습니다. **수신 실패를 빈 집합으로 취급하지 않고**(다음 실행에서 전량이
'신규'가 되어 알림 폭풍이 납니다), **저장은 합집합**입니다(신호가 빠졌다 돌아와도 재알림하지 않습니다).

---

## 알림

```
🚨 즉시 대응: CVE-2026-XXXXX

원격 코드 실행 취약점

무엇이 바뀌었나 · CISA KEV 등재 — 랜섬웨어 캠페인에 사용 확인
영향            · Fortinet FortiOS (7.4.0 부터 7.4.5 이전)
패치 목표       · `fortios` Debian:12 → 7.4.5
공격 조건       · 네트워크 · 인증 불필요 · 사용자 관여 없음 · 조건 단순
지표            · CVSS 9.8 · EPSS 62.0% (상위 0.6%) · Metasploit 모듈 · nuclei 템플릿
CISA 조치 기한  · 2026-09-15
[상세 리포트]  [CVE 원문]  [벤더 권고]
```

판단에 필요한 것을 메시지 안에서 끝냅니다. 예전 알림은 제목과 배지뿐이라 결국 이슈를 열어봐야 했습니다.

**같은 CVE로 반복 발화하지 않습니다.** 발화한 트리거를 저장해 '새로 켜진 것'만 알리므로,
EPSS가 0.11 → 0.17 → 0.23으로 올라도 알림은 한 번입니다.

---

## 데이터 출처 & 라이선스

**무료이면서 법적 문제가 없는 것만** 씁니다. 새 소스를 붙일 때는 LICENSE 원문을 직접 확인하고
이 표에 한 줄을 추가하는 것이 규칙입니다.

| 소스 | 용도 | 라이선스 | 의무 |
|---|---|---|---|
| CVE Program (cvelistV5) | 레코드 원본 · delta 피드 | CC0 1.0 | — |
| CISA KEV | 관측된 악용 | U.S. Government Work | — |
| CISA vulnrichment (SSVC) | 악용 상태·CVSS·CWE 보강 | CC0 1.0 | — |
| NVD (NIST) | CVSS·CWE·CPE 보충 | U.S. Government Work | — |
| EPSS (FIRST.org) | 악용 확률 | 무료 공개 | 출처 표기 |
| OSV.dev | CVE↔패키지·패치 버전 | CC-BY 4.0 | 출처 표기 |
| **VulnCheck KEV** | 관측된 악용 (더 넓고 이름) | 무료 | **"prominent attribution to VulnCheck" 필수** |
| **nuclei-templates** | 무기화 신호 + 탐지 룰 | **MIT** | 저작권 고지 보존 |
| Metasploit metadata | 무기화 신호 | BSD-3-Clause | 출처(Rapid7) 표기 |
| Exploit-DB / PoC-in-GitHub / trickest | 익스플로잇 존재 | PoC 저작권=제출자 | **원문 미게시·링크만** |
| SigmaHQ | 탐지 룰 | DRL 1.1 | author 표기 보존 |
| ET Open / Snort Community | 네트워크 룰 | MIT / GPLv2 | 헤더 고지 보존 |
| **Splunk security_content (ESCU)** | 탐지 룰 | **Apache-2.0** | NOTICE 보존 |
| **YARA Forge** | YARA 룰 | 룰별 상이 | 룰 메타(author·license_url) 보존 |
| **Anthropic Disclosure Ledger** | AI 발견 취약점(ANT ID) | 명시 문구 없음 | **사실 데이터만 사용 + 출처 표기** |

> **Anthropic 레저 취급**: 페이지에 명시적 라이선스 문구가 없습니다. 그래서 사실 데이터
> (CVE ID·ANT ID·프로젝트·버그 클래스·날짜)만 쓰고 출처를 명시하며, 데이터셋 자체를 우리
> 것처럼 재배포하지 않습니다. EPSS·KEV와 같은 취급입니다.

> **채택하지 않은 것 — Elastic detection-rules**: Elastic License 2.0은 source-available이라
> 서비스 제공에 제한 조항이 있습니다. 공개 대시보드에 싣기에는 법적 검토 부담이 커서 제외했습니다.

<details>
<summary><b>Grype의 vulnDB는 왜 안 쓰나</b></summary>

Grype · grype-db · Vunnel **코드는 전부 Apache-2.0**이고 DB도 무료로 배포됩니다. 그런데
grype-db가 담는 것은 **패키지↔버전 범위 매칭 데이터**이지 악용/위협 신호가 아닙니다
(Vunnel 원천: Alpine, Amazon, Azure, Debian, Echo, GHSA, NVD, Oracle, RedHat, SLES, Ubuntu, Wolfi).
**1차 목표인 '고위험 신속 통지'에 기여하는 바가 사실상 없습니다.**

그리고 Anchore가 취합 데이터를 재라이선스해 주지는 않습니다. 원천별 조건(GHSA는 CC-BY-4.0,
RedHat/SUSE/Oracle OVAL은 각 벤더 조건)이 그대로 따라오므로, 공개 대시보드에 그 내용을
재배포하면 원천별 검토가 필요해집니다.

그래서 **2차 목표(자산 영향도)에서 사내 SBOM을 로컬 스캔하는 도구로만** 쓰는 것이 깨끗합니다.
그 전에 더 싼 길이 있었습니다 — OSV는 40종 이상을 제공하는데 Argus는 7종만 쓰고 있었습니다.
**22종으로 넓혀** Red Hat·Rocky·AlmaLinux·SUSE·NuGet·RubyGems·crates.io 등을 채웠습니다.
CC-BY 4.0 하나로 끝납니다.

</details>

---

## 운영 비용

전부 무료 티어 안에서 돕니다. 실행은 GitHub Actions, 대시보드는 GitHub Pages, DB는 Supabase,
AI는 Google AI Studio입니다.

| 한도 | 어떻게 지키나 |
| :--- | :--- |
| **GitHub Actions** | 이 저장소는 public이라 **분 제한이 없습니다.** 그래서 5분 주기가 가능합니다 |
| **Supabase** egress 5GB/월 | 증분 export · digest 게이팅 · 티어별 보존(T2는 90일, T0/T1은 180일) |
| **GitHub Pages** | 데이터 파일을 커밋하지 않고 아티팩트로 배포 — 저장소가 커지지 않습니다 |
| **Google AI Studio** | 역할별 RPM·TPM·RPD를 실행 간에 이어붙여 추적. 한도에 닿으면 다음 모델, 그다음 정형 폴백 |

번역과 분석 대상이 하루 수천 건에서 **수십~수백 건**으로 줄어, 대시보드에 실리는 CVE를
전부 한글화하는 것이 예산 안에 들어옵니다.

---

## 직접 써보기

<details>
<summary><b>설정 펼치기</b></summary>

### 1. GitHub Secrets

| Secret | 발급처 | 필수 |
|---|---|:--:|
| `GEMINI_API_KEY` | [aistudio.google.com](https://aistudio.google.com) | ✅ |
| `SUPABASE_URL` · `SUPABASE_KEY` | [supabase.com](https://supabase.com) | ✅ |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook | ✅ |
| `GH_TOKEN` | GitHub PAT (issues:write) | ✅ |
| `NVD_API_KEY` | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | 선택 |
| `VULNCHECK_API_KEY` | [vulncheck.com](https://vulncheck.com) | 선택 (있으면 T0 커버리지↑) |

### 2. DB 테이블

Supabase SQL Editor에서:

```sql
-- CVE 추적
create table if not exists cves (
  id                text primary key,
  cvss_score        double precision,
  epss_score        double precision,
  is_kev            boolean,
  last_alert_state  jsonb,
  rules_snapshot    jsonb,
  report_url        text,
  has_official_rules boolean,
  last_rule_check_at timestamptz,
  last_alert_at     timestamptz,
  updated_at        timestamptz
);

-- 파이프라인 진행 상태 (워터마크·실패추적·일일 요청 수)
create table if not exists pipeline_state (
  id         int primary key,
  state      jsonb       not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
insert into pipeline_state (id, state) values (1, '{}'::jsonb)
  on conflict (id) do nothing;

-- 신호 스냅샷 — 소스측 에스컬레이션 대조의 '지난번 집합'
create table if not exists signal_snapshots (
  source     text primary key,
  digest     text        not null,
  cve_ids    jsonb       not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);
```

`signal_snapshots`가 없어도 파이프라인은 죽지 않지만 **소스측 에스컬레이션 대조가 동작하지
않습니다.** 반드시 만들어 주세요.

### 3. 실행

- **Actions** 탭에서 워크플로를 활성화합니다 (`argus-fast.yml` 5분 · `argus.yml` 시간별).
- **Settings → Pages → Source** 를 **`GitHub Actions`** 로 설정합니다.
- 처음 한 번은 **Argus Maintenance**에서 `package-index`와 `rule-index`를 수동 실행합니다.
  이게 있어야 패치 목표 버전과 공개 탐지 룰이 리포트에 실립니다.

첫 회차의 스냅샷 대조는 **전량을 기록만 하고 알림을 보내지 않습니다.** 그러지 않으면 배포
직후 KEV 1,685건이 통째로 알림으로 나갑니다.

### 4. 이미 쌓인 이슈 정리

```bash
python3 tools/close_stale_issues.py            # 미리보기
python3 tools/close_stale_issues.py --apply    # 실제 종료
```

</details>

---

## 검증

판정이 틀리면 놓치거나 헛것을 쫓게 되므로, 규칙을 손댈 때마다 **배포 중인 실데이터로** 확인합니다.

```bash
python -m compileall -q src tools tests
for t in tests/test_*.py; do python "$t"; done
```

| 무엇을 | 어떻게 |
| :--- | :--- |
| **판정 경계** | `tests/test_risk.py` — 티어 21종 · 반복 발화 억제 · 전환 시 알림 폭풍 방지 |
| **누락 0** | `tests/test_feed.py` — 배치 시각 기준 수집(dateUpdated로 거르면 6.4% 유실) · 잘린 JSON 파싱 |
| **스냅샷 의미론** | `tests/test_signal_snapshot.py` — 수신 실패를 빈 집합으로 저장하지 않음 · 합집합 저장 · 부분 성공 재시도 |
| **화면** | 실제 데이터를 브라우저에 띄워 렌더·필터·모달·콘솔 오류 |

오답의 방향도 규칙으로 정해 뒀습니다. 취약한 것을 안전하다고 말하는 쪽이 반대보다 훨씬
나쁘므로, 확신이 없으면 `버전 미확인`으로 남기고 `수정판`이라고 단정하지 않습니다.

---

## 앞으로

2차 목표는 **자산 영향도**입니다. 지금은 "이 CVE가 위험한가"까지만 답하고, "우리에게 위험한가"는
`tools/sbom_match.py`로 로컬에서 대조합니다(자산 목록은 어디로도 전송되지 않습니다).
판정 결과에 자산 가중치를 곱할 자리를 `src/risk.py`에 남겨 뒀습니다.

---

> ⚠️ 이 도구가 생성·표시하는 AI 분석 결과와 위험도 분류는 **참고용**입니다.
> 실제 대응·패치 결정은 각 조직의 환경과 공식 벤더 권고를 함께 검토해 판단하시기 바랍니다.

## License

Code is licensed under the **[MIT License](LICENSE)** © 2026 LEEKIYOON-SEC.
외부 데이터 및 탐지 룰은 위 [데이터 출처 & 라이선스](#데이터-출처--라이선스) 표의 각 라이선스를 따릅니다.
기업/영리 목적으로 룰을 재배포·통합할 경우 해당 라이선스(특히 GPL 계열의 copyleft, DRL의 author
표기 의무, VulnCheck의 출처 표기 의무)를 별도로 확인·준수해야 합니다.
