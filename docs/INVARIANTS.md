# Argus 불변 규칙 · 실측값

코드 주석을 걷어내면서, **깨지면 버그가 되는 규칙**과 **판단의 근거가 된 실측값**만
여기로 옮겼습니다. 코드를 고치기 전에 이 문서를 먼저 봅니다.

> 원래 주석은 git 이력에 그대로 있습니다 — `git show fb314b4:src/risk.py`

---

## 1. 수집 (`feed.py`)

| 규칙 | 깨지면 |
|:---|:---|
| 워터마크는 배치의 `fetchTime`으로 잡는다. 항목의 `dateUpdated`가 아니다 | 유실. 배치 시각보다 `dateUpdated`가 뒤처진 항목이 **6.4%**(30일 79,897건 실측, 최대 6.7시간) |
| 상한 절단은 **배치 경계에서만**. 상한에 걸린 배치는 통째로 포함 | 유실. 워터마크는 배치 시각 하나라 다음 실행이 `batch_at <= 워터마크`를 통째로 건너뛴다 |
| delta ZIP은 시간별이 아니라 **그날 자정부터의 누적**. 하루에 하나만 받는다 | 같은 내용을 몇 번씩 받는다 (19Z 110건 ⊂ 23Z 125건, 00Z 리셋) |
| `parse_record()`는 네트워크를 쓰지 않는다 | fast-lane 데드라인이 무의미해진다 |

**실측 (2026-09-01)**

```
배치 크기      6시간 창 24배치 · 중앙값 4건 · 최대 477건   ← 극단적으로 고르지 않다
ZIP 선충전     하루치 ZIP 하나로 591/607건 · 2.5초
개별 fetch     8워커 19건/s · 24워커 24건/s (그 위로는 안 오른다)
CVE 유입       평일 2,000~2,400건/일 · 최대 5,542 · 일요일 133
```

---

## 2. 판정 (`risk.py`)

| 규칙 | 근거 |
|:---|:---|
| **CVSS는 단독으로 어떤 알림도 만들지 않는다** | 아래 표. CNA·CISA ADP가 9.8을 일괄 부여하고 대다수는 악용 근거가 없다 |
| EPSS는 절대 점수가 아니라 percentile로 본다 | 점수 0.1은 임의값이고 모델 갱신 때 의미가 달라진다 |
| `fired_triggers`는 **누적**한다(합집합). 줄이지 않는다 | 줄이면 신호가 되돌아왔다 다시 켜질 때 재알림이 나간다 |
| 티어를 직접 계산하지 않는다. 트리거를 모으고 최고 등급을 유도한다 | 알림 억제와 알림 사유가 공짜로 나온다 |
| 메모리 손상 CWE(787/416)는 `WEAPONIZABLE_CWE`에 넣지 않는다 | 커널 CVE가 하루 수백 건이라 T2가 커널로 뒤덮인다 |

**알림 물량 실측 (2026-08-27~28, 3,951건)**

```
악용 신호만 (KEV·MSF·nuclei·EDB·EPSS p99)      15건/일   ← 채택
+ CVSS>=9 & 원격·무인증                       162건/일
+ CVSS>=9 & 원격·무인증·무관여·저복잡도            128건/일
+ 위 + 두 번째 근거                            57건/일
+ 주요 CNA의 CVSS>=9 사전인증 RCE                53건/일
```

**EPSS 분포 (366,357건 전량 덤프)**

```
p99.0 = 0.571   3,664건 (1.00%)   ← 알림 임계 (T1)
p95.0 = 0.093  18,318건 (5.00%)   ← 관찰 임계 (T2)
p90.0 = 0.041  36,640건
```

알림을 p99로 올린 이유: 신규 CVE는 EPSS가 낮게 시작하는 게 정상이라(모델에 아직 근거가
없다) p95는 신규분에서 거의 안 걸리고 대신 오래된 CVE가 대량으로 걸린다.

**티어 분포 실측**: T0 10 · T1 5 · T2 144 · T3 1,816 (건/일)

---

## 3. 소스측 대조 (`signal_snapshot.py`)

| 규칙 | 깨지면 |
|:---|:---|
| **수신 실패를 빈 집합으로 저장하지 않는다** (로더는 `None` 반환 → 소스 건너뜀) | 다음 실행에서 전량이 '신규'로 보여 알림 폭풍 |
| 저장하는 집합은 `기존 ∪ 이번에 처리한 것`. upstream 그대로가 아니다 | KEV 재등재·템플릿 리네임 때 재알림 |
| `commit()`은 **실제로 처리를 마친 것만** 더한다 | 처리 실패분이 사라진다 |
| digest를 먼저 비교하고 다르면 그때만 집합을 읽는다 | Supabase egress 초과 (무료 5GB/월) |

**최초 기록의 함정**: `stored_digest is None`이면 전량을 '이미 아는 것'으로 저장하고
**처리하지 않는다**(첫 실행 알림 폭풍 방지). 그래서 그 시점에 이미 KEV였던 CVE는 DB에
들어오지 않는다 → `src/backfill_exploited.py`로 소급한다(`silent=True`).

소급은 `pipeline.process(silent=True)`로 돈다. Slack 을 보내지 않는 것뿐 아니라
**`last_alert_at` 도 남기지 않는다** — 남기면 `get_missing_report_candidates`가
(`is_kev DESC` 정렬이라 맨 앞에서) 그 행들을 집어 GitHub Issue 를 대량 생성한다.
`fired_triggers` 는 기록하므로 다음 실행에서 재알림은 없고, 새 신호가 붙으면 그때
정상적으로 알림이 나간다.

방향을 뒤집은 이유: 예전 DB측 스윕은 조회 조건(`최근 30일 · 300건 · is_kev=false`)이
그대로 사각지대였다. 2년 전 저위험 CVE에 오늘 Metasploit 모듈이 올라오면 영영 못 봤다.

---

## 4. 처리 (`pipeline.py`)

| 규칙 | 깨지면 |
|:---|:---|
| T3은 DB에 아무것도 남기지 않는다 (이미 추적 중이던 행만 티어 갱신) | 행이 무한정 불어난다 |
| `RowCache`: **'조회했는데 없다'와 '조회를 못 했다'를 구분한다** | 조회 실패를 '없음'으로 처리하면 이미 알린 CVE가 재알림된다 |
| 저장 실패는 `failed`로 남긴다 | 대시보드 미반영 + 다음 실행 중복 알림 |
| 저장 형식(`_save`)은 이 한 곳에서만 만든다 | 두 레인의 판정·저장이 갈라진다 |

**실측 (604건 종단, 2026-09-01)**: 판정·저장 1.8초 · DB 왕복 61회(건별 방식이면 660회).
변경분의 **90.5%가 T3**이라 DB에 있을 리도 없는데 전부 왕복하고 있었다.

---

## 5. 저장 (`database.py`)

- Supabase 앞단 Cloudflare WAF는 CVE 본문의 공격 페이로드성 문자열(`../../etc/shadow`,
  `<script>`, SQLi 토큰)을 차단한다. **콘텐츠 결정적이라 재시도가 무의미하다** — 표시용
  텍스트에 ZWSP를 넣은 사본으로 저장한다(화면 동일). 탐지 룰 원문에는 넣지 않는다
  (붙여넣기가 깨진다).
- PostgREST는 한 응답에 최대 1,000행. `in_()` 청크는 200개(URL 길이 한도).

---

## 6. 화면 (`export_dashboard_data.py`, `docs/js/`)

| 규칙 | 깨지면 |
|:---|:---|
| **없는 티어를 특정 값으로 단정하지 않는다.** 행의 신호에서 `risk.evaluate`로 유도한다 | 실제로 났던 버그 — `or "T2"` 때문에 CISA KEV CVE가 '관찰'로 표시됐다 |
| 저장값과 유도값이 어긋나면 **더 위험한 쪽**을 쓴다 | 화면이 위험을 낮춰 부른다 |
| 티어는 목록에 **배지로 내보내지 않는다.** 악용 상태는 위협 신호 칸(KEV·MSF·NUCLEI…)이 이미 말한다 | 같은 사실을 두 칸에 쓰면 심각도 열이 넓어지고 읽기 어려워진다 |
| 목록 기본 정렬은 `tier_rank → cvss` (보이지 않는 우선순위) | 화면이 CVSS로 다시 줄 세우면 알림 간 건이 목록 아래에 있다 |
| **offset 페이징의 정렬 키는 `id`처럼 안 바뀌는 값이어야 한다** | `updated_at DESC` + offset 은 fast-lane 이 쓰는 동안 행이 페이지 경계를 넘나들어 건너뛰고 중복된다. export 건수가 회차마다 달라지고, 번역 순회는 영영 수렴하지 않는다 |
| 보존 정책은 **알림 티어(T0/T1) 행을 지우지 않는다** | 소급 채우기 행은 `last_alert_at` 이 비어 있어 '관찰 만료'로 오인된다. 2015~2020년 KEV 는 레코드가 안 바뀌어 90일이면 그대로 사라진다 |
| 번역 후보는 제목과 **설명을 함께** 본다 | 제목만 보면 제목은 한글인데 본문이 영문인 행이 다시는 후보로 안 올라온다 |
| export는 증분(`updated_at` 기준) | 90일 전량 ~15MB/회 → 월 10GB로 무료 한도 초과 |
| `rules`는 실제로 룰이 있는 행에만 싣는다 (`rules_snapshot`은 빈 껍데기라도 truthy) | 실측 2,217건 중 2,081건(93.9%)이 빈 껍데기였다 |
| **KPI 타일은 세는 기준을 필터 칩과 맞춘다** (`cveHasSignal`) | 타일이 티어 기준, 칩이 신호 기준이라 같은 말인데 숫자가 달랐다 |
| **KPI 타일은 클릭 대상이 아니다** — 필터는 검색줄 아래 한 곳에만 둔다 | 조작 지점이 두 군데로 갈리면 어디서 무엇이 걸렸는지 알 수 없다 |

**KPI 5개**: 추적 중 CVE · 🚨 악용 중 · 🧨 무기화 · 🔬 PoC 공개 · 🧠 AI 발견.
읽기만 하는 요약이다 — 필터는 검색줄 아래 칩에만 있다.
예전에는 '무기화 임박'(T1 개수)과 '무기화됨'(도구 공개 개수)이 나란히 놓여 무엇이 다른지
알 수 없었다 — 앞은 티어, 뒤는 신호라 기준 자체가 달랐다. 그래서 세는 기준만 칩과
맞췄고, 조작은 붙이지 않았다.

**티어를 화면에서 뺀 이유**: 등급 드롭다운은 신호 칩(악용 중·무기화·PoC…)과 거의 완전히
겹쳤고, 목록의 티어 배지도 위협 신호 칸과 같은 사실을 두 번 말했다. '알림이 나갔는가' 칩도
뺐다 — 대시보드에서 이미 확인되고, Slack 한 건이 누락됐을 때 그 사실이 화면에서도 가려지는
쪽이 오히려 문제다. 티어는 판정·정렬·알림에는 그대로 쓰되 화면에는 내보내지 않는다.

**제목 길이 실측**: 628건 기준 중앙값 59자, 25자 이하는 1건(0.2%). `_looks_english` 의
`len > 25` 하한은 번역 누락의 주원인이 아니었다 — 원인은 위의 offset 페이징이었다.

---

## 7. AI 발견 (`ai_provenance.py`)

- **정밀도가 전부다.** 자유텍스트(크레딧)를 보고 판단하므로 패턴을 조금만 넓혀도 소속을
  발견 주체로 오인한다. `Kostya Kortchinsky | OpenAI`는 OpenAI 소속 **사람** 연구원이다.
  `openai`·`anthropic`·`AI` 같은 일반어는 절대 넣지 않는다.
- 구조화된 피드는 Anthropic 공개 레저(ANT ID) 하나. 나머지(Big Sleep · ZeroPath · XBOW ·
  CodeMender · AIxCC)는 CVE `credits` 필드 매칭이다.
- 레저 응답의 Content-Type을 확인한다 — 사이트가 HTML 셸을 돌려줄 때가 있다.
- 물량 실측: 크레딧 보유 레코드 15%, AI 프로그램 매칭은 하루 1~2건(6일 8,096건 중 11건).

---

## 8. 예산 (`config.py`)

```
fast_max_changes        1,500   근거는 §1·§4 실측. 300이 막던 것은 건별 DB 왕복이었다
fast_deadline_minutes       5   Actions 타임아웃 8분 전에 스스로 마무리(워터마크 저장)
snapshot_cap               80   EPSS 모델 갱신 때 수천 건이 한꺼번에 임계를 넘는다
bulk_deadline_minutes      38   Actions 타임아웃 45분
translation_backfill_per_run  24
max_consecutive_failures    3   독약 레코드가 워터마크를 영구 고정하는 것을 막는다
quarantine_retry_hours     24
```

Actions 분은 **무제한**이다(public 저장소). '2,000분/월' 제약은 private 저장소 기준이다.

AI 모델은 Google AI Studio 하나, 역할마다 2단 + 정형 폴백:
분석 `gemini-3.5-flash-lite` → `gemini-3.1-flash-lite`,
번역 `gemma-4-31b-it` → `gemma-4-26b-a4b-it`. 한도는 모델별로 따로 잡힌다.

---

## 9. 라이선스 (실제 LICENSE 파일 확인)

| 소스 | 라이선스 | 의무 |
|:---|:---|:---|
| CVE (cvelistV5) | CC0 1.0 | 없음 |
| CISA KEV · SSVC/vulnrichment | 공공/CC0 1.0 | 없음 |
| EPSS (FIRST.org) | 무료 | 출처 표기 |
| nuclei-templates | MIT | 표기 |
| Splunk security_content | Apache-2.0 | 표기 |
| YARA Forge | GPL-3.0 도구 + **룰별 메타데이터** | 룰별 author·license 보존 |
| Metasploit | BSD-3-Clause | 표기 |
| OSV.dev | CC-BY 4.0 | 표기 |
| VulnCheck KEV | 무료 | **"This product uses VulnCheck KEV" 필수** |
| Anthropic CVD 레저 | 명시 없음 | 사실만 인용, 데이터셋 재배포 금지 |
| ~~Elastic detection-rules~~ | Elastic License 2.0 | **거부** — source-available, 서비스 제한 |

**Grype를 안 쓰는 이유**: 코드는 Apache-2.0이지만 grype-db는 패키지↔버전 *매칭* 데이터라
악용 신호가 아니다 — 1차 목표에 기여하지 않는다. 게다가 Anchore가 집계 데이터를
재라이선스하지 않아 원출처 조건(GHSA CC-BY-4.0, RedHat/SUSE/Oracle OVAL 벤더 약관)이
그대로 따라온다. 2단계에서 *로컬 도구*로 쓰는 건 문제없다.

VulnCheck 커뮤니티 티어는 `/v3/backup/`이다. `/v3/index/`는 상위 티어 전용이라
유효한 토큰으로도 401이 난다.

---

## 10. 운영에서 지킬 것

- 넓은 `except`가 곳곳에 있어 버그가 **조용한 실패**로만 보인다. `tests/test_lint.py`
  (pyflakes)를 두 워크플로의 실행 전 단계에 두는 이유다. 실제로 이 방식으로 세 개를 놓쳤다.
- 알림 물량 10~30건/일 유지. 50건을 넘으면 `risk.py` 임계 재조정.
- 탐지 → Slack p95 15분 미만.
- DB는 수동 관리. 스키마는 아래 SQL을 Supabase 콘솔에서 1회 실행.

---

## 11. 설정 (README를 지웠으므로 여기 남긴다)

**GitHub Secrets**

| Secret | 발급처 | 필수 |
|:---|:---|:--:|
| `GEMINI_API_KEY` | aistudio.google.com | ✅ |
| `SUPABASE_URL` · `SUPABASE_KEY` | supabase.com | ✅ |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook | ✅ |
| `GH_TOKEN` | GitHub PAT (issues:write) | ✅ |
| `NVD_API_KEY` | nvd.nist.gov | 선택 |
| `VULNCHECK_API_KEY` | vulncheck.com | 선택 (있으면 T0 커버리지↑) |

**DB 스키마** — Supabase SQL Editor에서 1회

```sql
create table if not exists cves (
  id                 text primary key,
  cvss_score         double precision,
  epss_score         double precision,
  is_kev             boolean,
  last_alert_state   jsonb,
  rules_snapshot     jsonb,
  report_url         text,
  has_official_rules boolean,
  last_rule_check_at timestamptz,
  last_alert_at      timestamptz,
  updated_at         timestamptz
);

create table if not exists pipeline_state (
  id         int primary key,
  state      jsonb       not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
insert into pipeline_state (id, state) values (1, '{}'::jsonb)
  on conflict (id) do nothing;

create table if not exists signal_snapshots (
  source     text primary key,
  digest     text        not null,
  cve_ids    jsonb       not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);
```

`signal_snapshots`가 없어도 파이프라인은 죽지 않지만 **소스측 에스컬레이션 대조가
동작하지 않는다.**

**첫 실행 순서**: Actions 탭에서 워크플로 활성화(`argus-fast.yml` 5분 ·
`argus.yml` 시간별) → Settings → Pages → Source 를 `GitHub Actions` 로 →
Argus Maintenance 에서 `package-index`·`rule-index`를 한 번씩 수동 실행 →
`backfill-exploited` 로 현재 악용 중인 CVE를 채운다(§3).
