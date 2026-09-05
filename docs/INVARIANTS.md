# Argus 불변 규칙 · 실측값

코드 주석을 걷어내면서, **깨지면 버그가 되는 규칙**과 **판단의 근거가 된 실측값**만
여기로 옮겼습니다. 코드를 고치기 전에 이 문서를 먼저 봅니다.

> 원래 주석은 git 이력에 그대로 있습니다 — `git show fb314b4:src/risk.py`

---

## 1. 수집 (`feed.py`)

| 규칙 | 깨지면 |
|:---|:---|
| **CVSS 는 전 버전을 모아 가장 높은 점수를 쓴다** (`collect_cvss`/`pick_cvss`) | 4.0 과 3.x 는 산식이 달라 실측 22%가 두 버전을 갖고 대부분 값이 다르다. 4.0 만 보면 같은 취약점을 남들보다 안전하다고 말하게 된다 |
| 화면·리포트·Slack 에 **어느 버전인지 적는다** | NVD 에서 9.9(3.1)를 본 사람이 우리 화면의 9.4(4.0)를 보면 무엇이 맞는지 알 수 없다 |
| 워터마크는 배치의 `fetchTime`으로 잡는다. 항목의 `dateUpdated`가 아니다 | 유실. 배치 시각보다 `dateUpdated`가 뒤처진 항목이 **6.4%**(30일 79,897건 실측, 최대 6.7시간) |
| 상한 절단은 **배치 경계에서만**. 상한에 걸린 배치는 통째로 포함 | 유실. 워터마크는 배치 시각 하나라 다음 실행이 `batch_at <= 워터마크`를 통째로 건너뛴다 |
| delta ZIP은 시간별이 아니라 **그날 자정부터의 누적**. 하루에 하나만 받는다 | 같은 내용을 몇 번씩 받는다 (19Z 110건 ⊂ 23Z 125건, 00Z 리셋) |
| `parse_record()`는 네트워크를 쓰지 않는다 | fast-lane 데드라인이 무의미해진다 |

**CVSS 버전 실측 (2026-09-01, 203건)**

```
두 버전 이상 보유   44건 (22%) · 그중 점수가 다른 것이 대부분
4.0 만 보던 때보다 점수가 올라가는 건   27건

  CVE-2026-82954   4.0=9.4  3.1=9.9      CVE-2026-82703   4.0=5.1  3.1=6.6
  CVE-2026-82914   4.0=6.9  3.1=7.3      CVE-2026-82905   4.0=5.3  3.1=6.3
```

CNA 가 4.0 만 내고 ADP(CISA vulnrichment)가 3.1 을 붙이는 경우가 흔하므로 둘을 합친다.
`baseScore` 가 없는 껍데기 블록은 건너뛴다 — 예전에는 그걸 만나면 `break` 해서 뒤의
멀쩡한 3.1 을 못 봤다.

**이미 저장된 행 (`src/backfill_cvss.py`)**

파이프라인을 고쳐도 **DB 에 있던 행은 옛 값 그대로다.** 새로 처리되는 CVE 부터만 맞고,
옛 행은 그 CVE 가 다시 바뀔 때까지 안 고쳐진다. 그 간극을 메우는 소급 도구다.
대상은 두 종류 — `cvss_version` 키가 없는 행(옛 코드가 쓴 행. 지금 코드는 점수가 없어도
빈 문자열로 항상 넣으므로 키의 유무가 곧 표식이다)과 **점수가 0 인 행**(키가 있어도 다시
본다. 조회가 실패해 못 채운 것을 다음 실행이 집어야 한다).

**두 가지 다른 고장을 고친다.**

| | 증상 | 원인 | 고치는 법 |
|:---|:---|:---|:---|
| ① 점수가 낮다 | 4.0=9.4 인데 3.1 은 9.9 | 버전을 하나만 읽고 `break` | cvelistV5 재판독 |
| ② 점수가 아예 없다 | N/A | **cvelistV5 에 `metrics` 블록이 없다** | NVD 를 한 번 더 본다 |

②는 재판독으로 못 고친다 — 소스에 데이터가 없다. 2016년 이전 CVE 가 구형 CVE 포맷에서
cvelistV5 로 일괄 변환되면서 CVSS 를 못 갖고 온 것이고, CNA 가 나중에 채우지도 않았다.

**N/A 574건 전수 조사 (2026-09-01, 배포 중인 13,095건 기준)**

```
cvelistV5 에 CVSS 있음    2건  ← 재판독으로 고쳐지는 것
cvelistV5 에 아예 없음  572건  ← 소스에 없다 (99.7%)
레코드 404                0건

연도    1999~2016 에 몰려 있다 · 2017~2020 은 0건 (변환 경계가 뚜렷하다)
티어    T0 571 · T2 2 · T1 1     ← 99.5%가 관측된 악용이다
```

**N/A 행의 99.5%가 T0** 였다. 시스템이 존재하는 이유인 행들이 심각도 칸을 비워 두고
있었다는 뜻이다. `_priority` 가 (티어 → 점수 0 우선) 로 세우므로 574건 전부가 한 회차
상한(1,500) 안에 들어온다.

**NVD 표본 25건**

```
CVSS 3.x/4.0 있음   4건 (16%)
CVSS 2.0 만 있음   21건 (84%)
NVD 에도 없음       0건
```

`CVE-2016-0736` → cvelistV5 `cna.metrics: null` · NVD `3.0 = 7.5`.

NVD 는 미국 정부 저작물이라 **퍼블릭 도메인·무료**이고, 이미 `backfill_vendors`·
`backfill_published` 가 쓰고 있어 새 의존성이 아니다. 키가 있으면 건당 0.7초,
없으면 8초 — 574건이면 7분 vs 76분이라 시간 예산(기본 2,400초)을 두고 넘으면
다음 실행이 이어서 본다. 연속 5회 실패하면 레이트리밋으로 보고 중단한다.

**CVSS 2.0 은 3.x/4.0 이 하나도 없을 때만 쓴다.** 산식도 척도도 달라서 둘을 한 `max` 에
넣고 비교하면 안 된다(CVE-2016-0736: v2=5.0 · v3.0=7.5). 대신 어느 버전인지 이미
화면·리포트·Slack 에 적고 있으므로 "7.5 (v2.0)"은 정직하게 읽힌다. 2.0 을 버리면
관측된 악용 480여 건이 심각도 칸을 계속 비워 둔다. **v2 벡터는 `PR` 대신 `Au` 를 쓰므로
`is_remote_unauth` 가 False 를 돌려준다 → `cvss_critical_remote` 가 켜질 수 없다.**
점수만 채우고 판정은 건드리지 않는다.

| 규칙 | 깨지면 |
|:---|:---|
| **점수를 내리지 않는다** | NVD 보충으로 받은 점수는 cvelistV5 레코드에 없다. 낮추기를 허용하면 멀쩡한 9.8 이 0.0 으로 지워진다. 진짜 하향 수정은 delta 피드가 정상 경로로 고친다 |
| 점수가 안 변해도 **`cvss_version` 키는 반드시 심는다** | 대상 선정 기준이 그 키라, 안 심으면 매 실행이 같은 행을 다시 받아온다 (수렴하지 않는다) |
| **CVSS 2.0 은 3.x/4.0 이 하나도 없을 때만** 쓴다 | 척도가 달라 한 `max` 로 비교할 수 없다. 반대로 2.0 을 아예 버리면 T0 480여 건이 계속 N/A 다 |
| NVD 조회는 **시간 예산**과 **연속 실패 중단**을 둔다 | 키 없이 574건이면 76분 — 잡 타임아웃(60분)을 넘긴다. 403 이 쏟아지면 회차를 통째로 버린다 |
| 티어는 **저장된 state 그대로**에서 다시 센다. 수집기를 다시 돌리지 않는다 | KEV·EPSS·PoC 를 재수신하다 한 소스가 실패하면 신호가 사라져 화면이 위험을 낮춰 부른다 |
| `updated_at` 을 갱신하지 않는다 | 보존 정책이 그 값으로 나이를 세므로 1만 건의 나이가 한꺼번에 초기화된다 |
| `notifier` 를 import 하지 않는다 | — |

**알림을 켤 수 없다는 것은 우연이 아니다.** CVSS 가 건드리는 트리거는
`cvss_critical_remote` 와 `unscored_major_cna` 둘뿐이고 **둘 다 T2** 다. 알림은 T0/T1
트리거로만 나가므로 이 도구는 구조적으로 Slack 을 만들 수 없다.
`tests/test_backfill_cvss.py` 가 이 성질을 전수로 지킨다.

점수를 찾으면 `unscored_major_cna`("점수 미부여 — 재평가 대기", T2)의 사유가 사라져
T2 → T3 로 내려가는 행이 생긴다. **정상이다** — 재평가를 기다릴 이유가 없어진 것이다.

**소급 효과 실측 (2026-09-01, 186건 · 옛 판독기를 그대로 재현해 대조)**

```
두 버전 이상 보유       43건 (23.1%)
점수가 올라가는 행      27건 (14.5%)     ← 소급 대상의 대략적인 비율
그중 N/A → 점수          0건            ← 옛 코드도 ADP 폴백은 갖고 있었다
```

**실측 (2026-09-01)**

```
배치 크기      6시간 창 24배치 · 중앙값 4건 · 최대 477건   ← 극단적으로 고르지 않다
ZIP 선충전     하루치 ZIP 하나로 591/607건 · 2.5초
개별 fetch     8워커 19건/s · 24워커 24건/s (그 위로는 안 오른다)
CVE 유입       평일 2,000~2,400건/일 · 최대 5,542 · 일요일 133
```

---

### 2-1. GitHub Actions 는 cron 대로 안 돈다 — 처리량을 회차 수로 계산하면 안 된다

`argus.yml` 의 cron 은 `18 * * * *`(시간당 1회)지만 **실제로는 하루 5.0회** 돈다.
스케줄 실행 30회(6일치) 실측:

```
간격      중앙값 4.8h · 평균 5.0h · 최소 2.4h · 최대 13.3h
분포      2~4시간 11회(38%) · 4시간 초과 18회(62%) · 1시간 이내 0회
실행률    설계 대비 21%
```

그런데 정작 한 회차는 **38분 예산 중 23초**만 쓰고 끝났다. 즉 병목은 시간이 아니라
`translation_backfill_per_run: 24` 라는 고정값 하나였다 — 24 x 5 = 120건/일 이라
미번역 2,340건을 지우는 데 20일이 걸린다.

지금은 남은 시간과 **남은 RPD·TPM** 으로 예산을 잡는다(`main._translation_budget`).

```
TPM 16,000(예약 4,000) → 사용 가능 12,000/분
청크(6건)당 ~1,500토큰  → 8청크/분 = 48건/분      ← 실효 병목은 TPM
RPM 30 → 180건/분                                  (안 걸린다)

18분 x 48건/분 = 864건/회차 x 5회 = 4,320건/일   (예전 120건/일 대비 36배)
```

| 규칙 | 깨지면 |
|:---|:---|
| **폴백 단은 각자 별도 한도다 — 단별로 계산해 가장 여유 있는 쪽을 쓴다** | 단을 돌며 `min` 을 누적하면 1단이 소진된 순간 2단이 멀쩡해도 예산이 0 이 된다 (테스트가 이 초안을 잡았다) |
| 분석 모델도 **TPM 을 센다** | `gemini`/`gemini_fb` 만 있고 분석 두 단은 빠져 있었다. `analyzer` 가 `record_call` 에 토큰을 안 넘겨 집계 자체가 안 됐다 |
| 한도 카운터는 **시간별 버킷 24h 롤링** | 지나간 버킷이 지워지는 것이 곧 '한도 리셋'이다. 절대 시각(자정)으로 세면 리셋 시점을 우리가 알 수 없다 |
| 한도 상태는 실행 사이에 **이월**된다 | 회차마다 0 에서 시작하면 하루 한도를 몇 배로 초과한다 |
| 한 회차가 표를 **한 바퀴 넘게** 돌지 않는다 | 백로그가 비면 영문이 안 나오는데, 예산이 남았다고 계속 돌면 시간 예산이 다할 때까지 같은 표를 다시 읽는다 |

**AI Studio 실측 한도** (`rate_limiter.py` 에 그대로 박아 둔다):

```
gemini (Gemma 4 31B)         RPM  30 · TPM  16,000 · RPD 14,400
gemini_fb (Gemma 4 26B)      RPM  30 · TPM  16,000 · RPD 14,400
gemini_analysis (3.5 FL)     RPM  15 · TPM 250,000 · RPD    500
gemini_analysis_fb (3.1 FL)  RPM  15 · TPM 250,000 · RPD    500
```

표에 TPD 열이 없다 — 프리티어에 일일 토큰 한도는 없는 것으로 보고 추적하지 않는다.

---

## 2. 판정 (`risk.py`)

**신호는 판정이 읽는 모양으로 저장돼야 한다** — 전수 검토에서 나온 가장 큰 고장.

`collector` 는 CISA vulnrichment 의 SSVC 를 `state['ssvc']['exploitation']` 중첩으로
넣었는데 `risk.evaluate` 는 `state['ssvc_exploitation']` 평탄한 키만 읽었다. export 와
`_waf_minimal_copy` 는 중첩본을 폴백으로 읽고 있어 **화면에는 'SSVC: active' 가 뜨는데
판정만 못 봤다.** 트리거 3개가 통째로 죽어 있었다.

```
배포본 13,275행에서 발화했어야 한 수
  ssvc_active        T0  악용 진행형        432건   ← 알림 트리거다
  ssvc_automatable   T2                  1,647건
  ssvc_total_impact  T2                  3,699건

최근 24h 변경분 1,487건으로 본 물량 (일일환산은 평일 유입 2,200건 기준)
  SSVC 끔 (고장 상태)          T0   0 · 추적   99건 →   146건/일
  ssvc_active 만              T0   6 · 추적  101건 →   149건/일
  automatable 또는 total 하나  T0   6 · 추적 1,007건 → 1,490건/일   ← 10배
  둘 다 요구 (채택)            T0   6 · 추적  155건 →   229건/일
```

`ssvc_technical_impact=total` 은 CISA 가 28% 에 붙이고 `automatable=yes` 는 12% 다 —
하나만 쓰면 추적 물량이 10배가 되어 90일 보존에 13만 행(배포 파일 230MB)이 된다.
그래서 **둘을 함께 요구하는 트리거 하나(`ssvc_high`)** 로 합쳤다. 벡터 조건(원격·무인증)을
더 걸어도 217건/일 로 거의 안 줄어 굳이 걸지 않는다.

`ssvc_active` 는 T0 알림이라 그냥 켜면 저장된 432건이 "처음 보는 신호"가 되어 순차로
Slack 을 쏜다. `src/backfill_signals.py` 가 발화 이력에 미리 채워 그걸 막는다
(기본값은 이번 수정이 새로 켜는 `ssvc_active` 만 — 다른 트리거까지 덮으면 나가야 할
알림을 영영 막는다).

| 규칙 | 근거 |
|:---|:---|
| **판정이 읽는 키와 수집이 쓰는 키가 같아야 한다** | 위 표. 화면은 폴백으로 가려 주므로 눈으로는 안 보인다 — 트리거별 발화 수를 세는 것이 유일한 검출 수단이다 |
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
| **리포트 본문은 `id` 하나만 있어도 만들어져야 한다.** 없는 값은 폴백 | 알림 시점 상태에는 `title_ko` 가 없다(번역은 나중) — `cve_data['title_ko']` 직접 참조로 KeyError 가 났고 except 가 삼켜 알림이 리포트 링크 없이 나갔다 |

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
| **offset 페이징의 정렬 키는 `id`처럼 안 바뀌는 값이어야 한다** (`export_cves`·`get_translation_backfill_candidates`·`tracked_states`·`get_tracked_ids` 전부) | `updated_at DESC` + offset 은 fast-lane 이 쓰는 동안 행이 페이지 경계를 넘나들어 건너뛰고 중복된다. export 건수가 회차마다 달라지고, 번역·백필 순회는 영영 수렴하지 않는다. 시뮬레이션(5,000행): 페이지당 쓰기 5/20/60건에 누락 13/37/115건, `id` 정렬은 전부 0건 |
| **순회 창은 실제로 소화한 만큼만 전진한다** | 번역이 한도(24건)에서 멈춰 놓고 offset 을 창 크기(200)만큼 밀었다. 한 창에 영문이 24건을 넘으면 나머지는 offset 이 지나가 버린다 — 실측 미번역 2,340건 중 **1,447건이 구조적으로 도달 불가**였고 CVE-2016-0193 이 그중 하나다 |
| **처리량은 '회차당 N건' 고정값이 아니라 남은 API 한도와 시간으로 정한다** | 아래 §2-1. GitHub 이 cron 대로 안 띄우므로 회차 수를 전제한 고정값은 실제 처리량을 예측하지 못한다 |
| 빈 응답을 '끝'으로 읽고 offset 을 0 으로 되감지 않는다 | `get_…_candidates` 는 예외를 삼키고 `[]` 를 돌려준다. 조회 한 번 실패에 순회가 처음으로 되감기면 뒤쪽 행은 영영 안 온다 |
| **export 는 `rule_manager` 가 내는 룰 종류를 다 싣는다** (`sigma`·`nuclei`·`splunk`·`yara`·`network`) | 인덱스도 리포트도 5종을 다루는데 export 만 3종으로 잘라, nuclei 템플릿과 Splunk ESCU 가 대시보드에서만 조용히 사라졌다 |
| **신호원을 못 받은 회차는 그 키를 만들지 않는다** — `pipeline.carry_forward` 가 판정 직전에 이전 값을 이월한다 | 로더가 실패해도 빈 인덱스를 돌려주므로 호출부가 '없음'으로 읽는다. 그 False 가 저장돼 원래 True 를 덮었다 — 재현하면 Log4Shell 이 T0 → T3 로 떨어진다. 관측된 False 는 덮지 않고 못 관측한 것만 채운다 |
| **저장은 이전에 알던 것을 지우지 않는다** | `title_ko` 는 `parse_record` 가 만들지 않는데 `_save` 가 state 에 없는 키를 버렸다 → **재처리 때마다 번역이 통째로 지워졌다.** 실측: 8일 이상 안 건드린 행은 99.9% 번역돼 있고, 하루 내 갱신된 행은 96.2%가 영문 |
| 이번 회차가 CVSS 를 하나도 못 찾았으면 **이전 점수를 지킨다** | 2016년 이전 CVE 는 cvelistV5 에 metrics 가 없어 `parse_record` 가 0.0 을 낸다. `backfill-cvss` 가 NVD 로 채운 값이 다음 fast-lane 에서 지워져 도구 자체가 무력해졌다. 레코드가 실제로 더 낮은 점수를 주면 그건 따른다 |
| **Slack 전송이 실패하면 발화 이력도 `last_alert_at` 도 남기지 않는다** | 반환값을 버리고 있었다 — 전송이 실패해도 재알림 억제가 걸려 그 CVE 는 두 번 다시 알리지 않았다. 웹훅이 바뀌거나 Slack 이 몇 분 죽으면 그 창의 알림이 전부 사라진다 |
| 만든 리포트 URL 은 **알림 성공 여부와 무관하게** 기록하고, 이미 있으면 다시 만들지 않는다 | 위 수정만 하면 실패할 때마다 GitHub Issue 가 새로 생긴다(실측 3회차에 3개) |
| **WAF 축소 저장은 필드를 버리지 않고 본문만 줄인다** (`_waf_minimal_copy`) | 고정 화이트리스트라 STATE_FIELDS 19개를 통째로 버렸다 — `cvss_vector`·`cvss_scores`·`affected`·`references`·`ssvc`·`ai_*`·`poc_urls`·`metasploit_modules`. 다음 회차 `carry_forward` 가 이 축소본을 '이전에 알던 것'으로 읽으므로 손실이 영구적이다. 실측 트리거 3개 소실. 그래도 막히면 4단계에서 **레코드로 다시 읽어올 수 있는 본문만** 버리고 번역·신호는 남긴다 |
| **탐지 룰 인덱스를 못 받은 회차는 `has_official_rules`·`rules_snapshot` 을 쓰지 않는다** (`rule_manager.index_ok()`) | 로더가 실패해도 `{}` 를 돌려주므로 '룰 없음'으로 DB 에 기록돼 이전에 확인해 둔 룰이 지워졌다. 룰 재확인도 이때는 건너뛴다 — 돌려봐야 7일 쿨다운만 태운다 |
| **룰 인덱스 생성이 부분 실패하면 실패한 엔진만 직전 배포본에서 이월한다** (`build_rule_index.carry_missing`) | SigmaHQ 하나만 403 이어도 sigma 가 빠진 인덱스가 배포되고, 그걸 읽은 파이프라인이 해당 CVE 를 '룰 없음'으로 기록했다. 전부 실패하거나 이월할 직전본도 없으면 덮어쓰지 않고 종료 |
| **지표를 못 받았으면 화면에 `unknown` 이라 쓴다 — 0% 나 No 가 아니다** | 리포트가 `EPSS 0.00%` · `KEV No` 로 적어 위험을 낮춰 불렀다. 실제로 관측된 0 은 그대로 0 이다 |
| 조회 실패로 끊긴 페이징은 **부분 결과를 돌려주지 않고 예외를 올린다** (`tracked_states`) | 백필 4종이 그걸 전량으로 믿고 "손볼 행 없음 → 정상 종료" 하거나 축소된 인덱스를 덮어썼다 |
| 수집한 필드는 `STATE_FIELDS` 에 있어야 저장된다 | `references` 가 빠져 있었다. 알림 시점에는 신선한 state 라 '벤더 권고' 버튼이 나오는데, 리포트 보강이 저장된 state 로 다시 만들면 참고 자료가 통째로 비었고 analyzer 입력에서도 사라졌다 |
| 데드라인에서 남은 구간은 **소비한 개수**로 끊는다 | `changes[len(outcomes):]` 는 outcomes 에 안 담기는 실패 건만큼 인덱스가 밀린다 — 이미 알림까지 나간 CVE 가 실패로 기록되고 3회 쌓이면 격리됐다 |
| 설명에서 만든 제목은 **단어 경계**에서 자른다 | `[:110]` 이면 'CVE-2016-0193' 이 '…or cause a de' 로 끊긴 채 화면 제목이 되고 번역 입력으로도 들어간다 |
| 보존 정책은 **알림 티어(T0/T1) 행을 지우지 않는다** | 소급 채우기 행은 `last_alert_at` 이 비어 있어 '관찰 만료'로 오인된다. 2015~2020년 KEV 는 레코드가 안 바뀌어 90일이면 그대로 사라진다 |
| **영향 제품은 자르지 않는다.** 전량을 `cve-products.json`(사전 압축)에 싣고 검색·상세·드롭다운이 그걸 본다 | 상한 3 이던 시절 실측으로 CVE 의 51.9%가 3개 초과, 제품 항목의 71%가 잘렸다 — '내가 쓰는 제품이 영향받나'를 검색으로 확인할 수 없었다 |
| 제품명이 없는 KEV 는 **CISA 의 vendorProject/product 로 메운다** | 옛 레코드는 affected 블록이 없어 'n/a' 다 — 무작위 120건 중 39건(32%). 하필 악용 중인 것들이라 제품으로 못 찾았다 |
| 검색은 공백으로 끊어 **토큰마다 AND** | 이어 붙인 한 덩어리에 substring 이면 서로 다른 칸에 걸친 검색이 안 되고 어순을 탄다 |
| 검색 중이면 목록에 **걸린 제품**을 띄운다 (첫 번째가 아니라) | 영향 제품 20개짜리에서 첫 번째만 띄우면 찾은 제품이 안 보여 '없네' 하고 지나친다 |
| 번역 후보는 제목과 **설명을 함께** 본다 | 제목만 보면 제목은 한글인데 본문이 영문인 행이 다시는 후보로 안 올라온다 |
| export는 증분(`updated_at` 기준) | 90일 전량 ~15MB/회 → 월 10GB로 무료 한도 초과 |
| **증분 병합은 DB 의 id 집합과 회원 자격을 맞춘다** (`live_ids`) | 병합은 `배포본 ∪ 신규`라 DB 에서 사라진 행을 못 지운다. 전량 export 때만 숫자가 떨어져 '추적 중 CVE'가 오르내렸다 |
| id 목록 조회 실패(`None`)는 **'전부 사라짐'이 아니다** | 그렇게 읽으면 대시보드가 통째로 비워진다 |
| 행수 상한은 **추적 행** 기준이고, 대시보드 구간(90일) 안은 안 지운다 | 전체 행 기준이면 상태 비워진 옛 행이 상한을 먼저 채우고, 오래된 순 삭제가 살아 있는 26일짜리 KEV 로 넘어간다 |
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

**영향 제품 실측 (2026-09-01, 664건)**

```
제품 항목        4,984개 · CVE당 중앙 4 · 평균 7.0 · 최대 66
3개 초과         51.9% · 잘려 나가던 항목 71%
고유 이름        제품 321종 · 벤더 116종 · 버전문자열 223종   ← 지독하게 반복된다
직렬화 크기      그대로 12.3MB  vs  사전 압축 1.6MB (gzip 0.2MB)
현재 cves.json   13,873건 · 22.7MB   ← 여기에 12.3MB 를 더 얹을 수는 없었다
```

**제품 데이터 품질 실측 (2026-09-01)**

```
최근 12시간 801건    쓸 만한 제품명 없음 3.6% · 항목 기준 n/a 0.6%   ← 신규는 깨끗하다
CISA KEV 120건      제품명 없음 32%  →  CISA 표기 폴백 후 0%
                    복구 예: Microsoft/Internet Explorer · Adobe/Flash Player
                            Oracle/Java Runtime Environment (JRE) · Zyxel/P660HN-T1A Routers
```

옛 CVE 레코드(2013~2017)는 구조화된 `affected` 가 없어 제품이 제목에만 있다.
검색은 제목·설명도 보므로 찾기는 하지만, 목록의 '영향 벤더' 칸과 드롭다운에는
`n/a` 로 떠서 없는 것처럼 보였다. KEV 표기는 사람이 정리한 값이라 그걸 쓴다.

**'추적 중 CVE'가 오르내린 이유 (2026-09-01 배포본 실측)**

```
cves.json 13,096건 · stats.total 13,096 · 중복 0        ← 두 파일은 서로 맞았다
티어 분포  T3 9,068(69%) · T2 2,948 · T0 1,045 · T1 35
updated 나이  최대 26일 · 90일 넘은 것 0건              ← 90일 창은 원인이 아니었다
```

원인은 두 경로가 서로 다른 집합을 만든 것이다.

```
번역이 돌면   → request_full_export() → 전량 export → 건수 = DB 실제 (낮음)
번역이 안 돌면 → 병합(배포본 ∪ 신규)  → DB 에서 사라진 행이 그대로 남음 (높음)
```

번역은 Gemma 503 등으로 실패할 수 있으니 두 모드가 번갈아 돌았고, 그때마다 숫자가
튀었다. 그리고 행이 애초에 사라지던 원인은 행수 상한이 **전체 행**을 세면서 오래된 순
삭제가 살아 있는 추적 행까지 먹은 것이다(그래서 최대 나이가 26일이었다).

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
| YARA Forge | **룰별 상이** (패키징 도구 자체는 GPL-3.0) | 룰별 author·source_url·license_url 보존 |
| Metasploit | BSD-3-Clause | 표기 |
| SigmaHQ sigma | DRL 1.1 | 룰별 author 보존 |
| Emerging Threats Open · Snort Community | MIT (레거시 SID 1–3464 는 GPLv2) | 표기 |
| nomi-sec/PoC-in-GitHub | **CC0 1.0** (LICENSE 확인) | 없음 — 다만 **URL 만 인용하고 PoC 원문은 게시하지 않는다** |
| Exploit-DB | 링크만 사용 | 원문 미게시 |
| NVD (NIST) | U.S. Government Work | 표기 |
| OSV.dev | CC-BY 4.0 | 표기 |
| VulnCheck KEV | 무료 | **"This product uses VulnCheck KEV" 필수** |
| Anthropic CVD 레저 | 명시 없음 | 사실만 인용, 데이터셋 재배포 금지 |
| ~~Elastic detection-rules~~ | Elastic License 2.0 | **거부** — source-available, 서비스 제한 |

탐지 룰 5종의 라이선스 문자열은 `build_rule_index.LICENSES` 가 실제로 화면까지
실어 나른다. **위 표와 그 사전은 같은 값을 말해야 한다** — 한쪽만 고치면 화면에
찍히는 고지와 여기 적힌 계약이 갈라진다.

### 9-1. 화면에 반드시 상시 표기되는 것

`docs/cve.html` 하단 `<footer class="site-footer">` 가 **유일한 완전 목록**이다.
모달 각주는 그 하단을 가리키기만 한다 — 목록을 두 곳에 두면 갈라지고,
예전처럼 **모달을 한 번도 안 연 방문자가 아무 출처도 못 보는** 상태가 된다.
룰 개별 라이선스·author 는 룰 본문 바로 위에 `renderRuleBlock` 이 함께 찍는다.

고지에 **없어야 하는 것**: `GitHub Advisory`. 코드 어디서도 가져오지 않는다 —
GHSA 는 OSV 덤프 안에 간접 포함될 뿐이다. `trickest` 도 같다 — PoC 출처는
`nomi-sec/PoC-in-GitHub` 하나다.

### 9-2. 실제로 접속하는 호스트 (무료 범위 확인용)

| 호스트 | 무엇 | 비용 |
|:---|:---|:---|
| `raw.githubusercontent.com` | cvelistV5 · Metasploit · nuclei · PoC-in-GitHub · 룰 원문 | 무료 |
| `api.github.com` | SigmaHQ·Splunk tarball, 주간 리포트 | **인증 시 5,000회/시 · 무토큰 60회/시** |
| `services.nvd.nist.gov` | CVSS·CPE 백필 | 무료 (**키 없으면 8.0초/요청**, 키 0.7초) |
| `www.cisa.gov` | KEV 피드 | 무료 |
| `epss.empiricalsecurity.com` | EPSS 전량 CSV.gz (FIRST.org 배포 호스트) | 무료 |
| `api.vulncheck.com` | VulnCheck KEV `/v3/backup/` | 커뮤니티 무료 |
| `storage.googleapis.com` | OSV 생태계 덤프 (OSV.dev 실제 전송 경로) | 무료 |
| `gitlab.com` | Exploit-DB 미러 CSV | 무료 |
| `rules.emergingthreats.net` · `www.snort.org` | 네트워크 룰 | 무료 |
| `github.com/YARAHQ/yara-forge/releases` | YARA 룰 묶음 | 무료 |
| `red.anthropic.com` | AI 발견 취약점 원장 | 무료 |
| Google AI Studio (SDK) | Gemini·Gemma 번역·분석 | **무료 티어 RPM/TPM/RPD 한도 내** |
| Supabase (SDK) | 저장 | 무료 500MB (→ Turso 5GB 로 이전 예정) |
| Slack Incoming Webhook | 알림 | 무료 |
| `*.github.io` | 배포본 자체 조회 (패키지 사전 등) | 무료 |

유료로 넘어가는 소스는 **없다**. 감시할 것은 두 가지 —
`build_rule_index._github_tarball` 이 토큰 없이도 동작해 익명 60회/시에 조용히
걸릴 수 있고, `osv_index` 가 주간 ZIP 을 캐시 없이 받는다.

**Grype를 안 쓰는 이유**: 코드는 Apache-2.0이지만 grype-db는 패키지↔버전 *매칭* 데이터라
악용 신호가 아니다 — 1차 목표에 기여하지 않는다. 게다가 Anchore가 집계 데이터를
재라이선스하지 않아 원출처 조건(GHSA CC-BY-4.0, RedHat/SUSE/Oracle OVAL 벤더 약관)이
그대로 따라온다. 2단계에서 *로컬 도구*로 쓰는 건 문제없다.

VulnCheck 커뮤니티 티어는 `/v3/backup/`이다. `/v3/index/`는 상위 티어 전용이라
유효한 토큰으로도 401이 난다.

---

## 10. 운영에서 지킬 것 · 로그에서 정상인 것

로그에 자주 뜨지만 **문제가 아닌 것**:

- `[WARNING] CVE-…: 레코드 없음 (404)` — Exploit-DB 등이 참조하는 CVE ID 가 아직
  cvelistV5 에 공개되지 않은 경우다(예약만 된 상태). 저장하지 않으므로 다음 회차에
  다시 잡고, 공개되면 그때 처리된다. 실측으로 EDB 인덱스 무작위·앞순 240건 중
  영구 미공개는 0건. 다만 이 건수가 수백으로 늘면 `snapshot_cap`(80)을 잠식하므로
  그때는 재시도 상한을 둬야 한다.
- `[WARNING] 일괄 번역 transient 오류(gemma-4-31b-it 1/3): 503 UNAVAILABLE` —
  Google 쪽 과부하다. `transient` 는 `_TR_STAGE_ADVANCE` 에 있어 3회 후 폴백 모델
  (`gemma-4-26b-a4b-it`)로 넘어가고, 그것도 실패하면 영문 원문으로 내려간다.
  파이프라인은 계속 돈다.

### 지킬 것

- 넓은 `except`가 곳곳에 있어 버그가 **조용한 실패**로만 보인다. `tests/test_lint.py`
  (pyflakes)를 두 워크플로의 실행 전 단계에 두는 이유다. 실제로 이 방식으로 세 개를 놓쳤다.
- 알림 물량 10~30건/일 유지. 50건을 넘으면 `risk.py` 임계 재조정.
- 탐지 → Slack p95 15분 미만.
- DB는 수동 관리. 스키마는 아래 SQL을 Supabase 콘솔에서 1회 실행.
- **대시보드 데이터(`docs/data/*.json`)를 커밋하지 않는다.** Pages 를 브랜치(`docs/`)
  로 서빙하던 시절 워크플로가 시간당 1건씩 커밋해 `.git` 이 100MB 가 됐다
  (`cves.json` 하나가 18MB). 지금은 Actions 가 만들어 Pages 아티팩트로 배포하고
  파이프라인 상태는 Supabase `pipeline_state` 에 있다. `.gitignore` 가 막고 있으므로
  예외를 뚫지 않는다.
- **`docs/` 는 곧 배포되는 사이트다.** 여기 두는 파일은 전부 공개된다 — 참조되지
  않는 파일을 남기면 그대로 공중에 실린다(실측: 삭제된 README 의 스크린샷 4종
  2.2MB 가 계속 서빙되고 있었다).

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

**옛 행 보정**: `backfill-cvss` 를 `dry_run` 체크한 채 한 번 돌려 상향 건수와 등급
이동을 로그로 확인한 뒤, 체크를 풀고 다시 돌린다. 한 회차 1,500건이고 남으면 다시
돌리면 이어서 처리한다 — 다 채우면 대상이 0 이 되어 더 돌릴 일이 없다.
NVD 조회가 붙어 있으므로 **`NVD_API_KEY` 를 먼저 넣는 게 좋다**(무료, NIST 발급).
키가 없으면 건당 8초라 574건에 76분이 걸려 한 회차에 다 못 끝낸다.
