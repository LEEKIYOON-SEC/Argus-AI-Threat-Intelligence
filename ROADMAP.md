# ARGUS 재편 로드맵: CVE 전용 위협 인텔리전스 플랫폼

## Context

ARGUS는 현재 CVE 스캐너 + IP 블랙리스트(The Shield) + IOC 통합 대시보드가 한 리포지토리에 얽혀 있다. 그 결과:
- **Supabase free tier 용량 부족** — `cves` + `shield_*` 테이블이 한 DB를 나눠 씀
- **AI 사용량 초과로 파이프라인 중단** — Groq TPD 소진
- **GitHub Actions 시간 과다** — 매시간 CVE 실행이 blacklist/IOC export + 외부 피드(URLhaus 등)까지 전부 재실행

사용자 최종 결정: **ARGUS = CVE 대시보드로 재정의하고, blacklist/IOC는 이 리포에서 완전히 제거한다("갈아엎기")**. blacklist는 추후 **별도 리포지토리 + 별도 DB**로 재구축 후 필요 시 통합. 구현은 사용량 초기화 후 Phase 단위로 순차 진행한다.

### 불변 원칙 (사용자 요구사항)

1. **100% 무료** — 유료 서비스 절대 금지, 전부 free tier로 구성
2. **DB 용량 최소화** — 상세 리포트(AI 분석 전문)는 **GitHub Issue에 저장**하고 DB에는 넣지 않는다. 대시보드는 요약+링크. free tier 용량 한계에 걸리면 안 됨
3. **룰 파이프라인 유지** — ① 공개 룰 존재 확인 → ② 없으면 AI가 수집된 데이터 기반으로 고정확도 룰 생성 → ③ 생성 불가 시 **불가 사유 명시**(`skip_reasons`). 이 3단계 구조는 ARGUS의 핵심이므로 변경하지 않는다
4. **룰 생성 정확도를 위한 풍부한 컨텍스트 유지** — nuclei 템플릿, Exploit-DB PoC 등을 AI 프롬프트에 넣는 건 룰 정확도를 위한 의도된 설계. 제거가 아니라 **수집 비용만 낮추는 방식으로 대체**한다
5. **Gemini 유지** — Gemini(번역) / Groq(분석·룰 생성)로 나눈 것은 **프리티어 사용량 분산 전략**. Groq로 통합하면 TPD가 더 빨리 소진되므로 두 서비스 체제를 유지한다
6. **테스트 스위트 불필요** — 기존 `test_argus.py`는 초기 개발기 디버깅용이었음. 최종 결과물 품질로 판단하며, 별도 pytest/CI는 구축하지 않는다 (현재 test_argus.py는 시그니처 불일치로 실행 불가 상태라 삭제만 한다)
7. **리포트는 기존 형태 유지** — GitHub Issue 리포트 포맷(배지, AI 분석, 벡터 해석, 룰, 현황)은 그대로. 더 나은 방안이 있으면 제안은 가능

### 탐색으로 확인된 핵심 사실
- 두 파이프라인은 **import 수준에서 이미 완전 분리** — `src/blacklist_ip/`는 자체 config/notifier를 갖고 CVE 모듈을 전혀 import하지 않음. 결합은 `src/export_dashboard_data.py::main()`(5단계 통합 export), 공유 `stats.json`, 두 워크플로우가 같은 export를 호출하는 지점뿐 → **삭제가 안전함**
- `docs/index.html`은 현재 **ioc.html로 리다이렉트** (랜딩이 IOC임)
- `requirements.txt`의 `docker`, `slack_sdk`는 **어디서도 사용 안 함** (dead)
- Sigma 검증은 YAML 구조 검사뿐(엔진 검증 없음), Yara만 실제 컴파일 검증, 네트워크 룰은 정규식 휴리스틱
- 룰 코드는 이미 cves.json에 export되는데(`rules_snapshot`) **대시보드가 렌더링하지 않음** — DB 추가 부담 없이 대시보드 개선 가능한 지점
- `main()`에 실패 알림 없음(매시간 cron이 조용히 실패 가능), 워크플로우에 pip 캐시/timeout 없음
- `cve-dashboard.js`는 `statsData.cve`를 읽으므로 stats.json에서 blacklist 섹션을 제거해도 JS 수정 불필요
- nuclei-templates 전체 tarball(수백MB)·GitHub Code Search(분당 10회 제한, 거의 항상 429)는 **목적은 정당하나 수집 방식이 비쌈**

---

## Phase 0 — 대청소: blacklist/IOC 완전 제거 (최우선, 1세션)

> 목표: CVE 잔재만 남기고 전부 제거. Actions 시간·DB 용량·복잡도 즉시 회수.

1. **아카이브 태그 생성** (삭제 전 안전장치): `git tag archive/shield-ioc-final` 후 push — 추후 별도 리포 구축 시 이 시점에서 코드 추출
2. **코드 삭제**:
   - `src/blacklist_ip/` 전체
   - `.github/workflows/blacklist.yml`
   - `docs/blacklist.html`, `docs/ioc.html`, `docs/js/blacklist-dashboard.js`, `docs/js/ioc-dashboard.js`
   - `docs/data/blacklist.json`, `docs/data/ioc*.json` (ioc.json은 원래 아무도 안 읽는 dead 파일)
   - `src/test_argus.py` (실행 불가 상태, 불변 원칙 6)
3. **`src/export_dashboard_data.py` → CVE 전용으로 축소**:
   - 유지: `_get_client`, `export_cves`, `export_stats`의 cve 절반, `_build_cve_tags`, `_generate_sample_data`의 CVE 부분
   - 삭제: `export_blacklist`, `_get_recovered_ips`, `_collect_urlhaus/_malwarebazaar/_phishtank/_openphish`, `collect_external_ioc_feeds`, `export_ioc`, `_write_ioc_files`, `_build_ip_tags`
   - `stats.json`은 `{generated_at, cve:{...}}`만 출력 — JS 수정 불필요
4. **랜딩 변경**: `docs/index.html` 리다이렉트 `ioc.html` → `cve.html`. `cve.html` 네비게이션에서 IOC/Blacklist 링크 제거
5. **requirements.txt 정리**: `docker`, `slack_sdk` 삭제 (dead)
6. **argus.yml**: commit 대상을 `docs/data/cves.json docs/data/stats.json`으로 축소
7. **Supabase**: `shield_*` 테이블 참조 코드 제거. 테이블 삭제는 사용자가 콘솔에서 (별도 리포 이전 후 권장 — 용량 즉시 회수)
8. **README.html 갱신**: Phase 2/3 설명 제거, CVE 전용 플랫폼으로 재기술

**효과**: 매시간 실행에서 외부 IOC 피드 호출 제거, export 시간 단축, DB 부하 절반 이하, 코드베이스 ~40% 감소

## Phase 1 — 안정화 · DB 용량 방어 (경량, 1세션)

> 테스트 스위트는 만들지 않는다 (불변 원칙 6). 운영 안정성과 DB 용량만 다룬다.

1. **파이프라인 실패 Slack 알림**: `main.py::main()` 최상위 try/except → 기존 `SLACK_WEBHOOK_URL`로 에러 전송 (알림 자체가 예외를 던지지 않게 가드) — 매시간 cron이 조용히 죽는 것 방지
2. **argus.yml 하드닝**: `cache: 'pip'`, `timeout-minutes: 30` — Actions 무료 시간 방어
3. **Supabase 재시도**: `database.py`에 tenacity `@retry` (이미 의존성에 있음)
4. **DB 보존 정책 (핵심)**: free tier 500MB 방어
   - 180일 지난 레코드의 `rules_snapshot`/`last_alert_state`(큰 JSON 필드)만 null 처리 — export 실행 시 함께 수행
   - 상세 정보는 어차피 GitHub Issue에 영구 보존되므로 데이터 손실 없음 (불변 원칙 2와 일치)
   - `last_alert_state`에 저장하는 필드 다이어트: 대시보드가 실제로 읽는 필드만 남기고 정리

## Phase 2 — 리소스 다이어트: 컨텍스트는 유지, 비용만 절감 (1세션)

> 원칙: 룰 생성 정확도용 컨텍스트(nuclei, Exploit-DB)는 **유지**하되 수집 방식만 저비용으로 교체 (불변 원칙 4). Gemini는 **유지** (불변 원칙 5).

1. **nuclei-templates: 전체 tarball → CVE별 타겟 조회**
   - 현재: 수백MB tarball을 매시간 다운로드 (`_download_nuclei_repo`)
   - 변경: nuclei-templates 리포의 CVE 인덱스만 캐시 → 해당 CVE의 템플릿 경로 확인 → 그 파일 하나만 raw.githubusercontent로 조회
   - 효과: 프롬프트에 들어가는 컨텍스트는 동일, 다운로드는 수백MB → 수KB
2. **Exploit-DB: Code Search API → CSV 매핑 + 직접 조회**
   - 현재: GitHub Code Search(분당 10회 제한)로 검색 → 거의 항상 429 + circuit breaker 차단되어 **사실상 동작 안 함**
   - 변경: `gitlab.com/exploit-database/exploitdb`의 `files_exploits.csv`(CVE→exploit 파일 매핑)를 캐시 → 매핑되면 해당 exploit 파일만 직접 조회
   - 효과: 지금은 못 얻던 PoC 컨텍스트를 안정적으로 확보 → **룰 정확도 오히려 상승**. `_search_github` + circuit breaker 코드는 제거
3. **룰셋 tarball 캐싱**: SigmaHQ/Yara-Rules/ET Open을 `actions/cache`로 24h 캐시 → 매시간 재다운로드 제거
4. **Gemini/Groq 역할 분담 유지 + 사용량 가시화**: 두 서비스 체제는 그대로. `rate_limiter`의 TPD 트래킹을 Gemini에도 확장해 실행 요약에서 양쪽 잔여량을 함께 확인

## Phase 3 — 룰 품질·신뢰도 강화 (1세션)

> 3단계 파이프라인(공개 룰 → AI 룰 → 불가 사유)은 그대로, 각 단계의 정확도만 올린다 (불변 원칙 3).

1. **pySigma 실검증**: `pysigma`(무료 pip, 오프라인 동작) 추가 → `_validate_sigma`에서 `SigmaCollection.from_yaml(code)` 파싱을 최종 게이트로. 기존 구조 검사는 사전 필터. docstring에만 있고 미구현인 `level` 검사도 실제 구현
2. **네트워크 룰 검증 강화**: `idstools` 또는 `suricataparser`(무료 pip, 순수 Python 룰 파서)로 실제 파싱 검증 — 정규식 휴리스틱 대체
3. **룰 신뢰 등급(trust tier)**: 룰마다 `trust: official-verified | ai-validated | ai-draft`를 `rules_snapshot`에 저장 (기존 필드 안에 문자열 하나 추가라 DB 부담 없음) → Issue·대시보드에 등급 배지
4. **AI 룰 자기검증 패스**: 생성 후 Groq에 "룰이 CVE 설명과 일치하는가, FP 위험은?" 저비용 검토 1회(`reasoning_effort: low`) — 불일치 시 폐기하고 `skip_reasons`에 사유 기록. TPD 게이트 뒤라 토큰 예산 안전
5. **불가 사유 고도화**: `skip_reasons`를 더 구체화 — 어떤 지표가 부족했는지, 어떤 소스(nuclei/ExploitDB/description)를 확인했는지 명시

## Phase 4 — 대시보드·리포트 강화 (DB 무부담 원칙, 1세션)

> 상세 리포트는 GitHub Issue 유지 (불변 원칙 2, 7). 대시보드는 **이미 export되는 데이터**만 더 잘 보여준다.

1. **탐지 룰 모달 렌더링**: cves.json에 **이미 들어있는** `entry["rules"]`를 모달에 `<pre>` + trust 배지로 표시 (기존 `escapeHtml`로 XSS 방어) — DB 변경 없음, 순수 JS
2. **룰 복사 버튼**: 룰별 클립보드 복사(`navigator.clipboard`) — 보안 장비에 바로 등록 가능
3. **상세 리포트 링크 강화**: 모달에서 GitHub Issue 링크를 더 눈에 띄게 (AI 분석 전문은 Issue에서 — 기존 설계 유지)
4. **클라이언트 사이드 export**: 필터된 CVE 목록 CSV/JSON 다운로드(Blob) — 서버·의존성 불필요
5. **Issue 리포트 포맷**: 기존 형태 유지. (제안: 룰 trust 등급 배지 추가 정도만 — P3와 연동)
6. (스트레치) STIX 2.1 번들 export — 순수 JS 객체 구성

## Phase 5 — 데이터 소스 확대 (1~2세션, 전부 무료·키 불필요)

> 목적 이중화: ① 룰 생성 프롬프트에 더 풍부한 컨텍스트 → 정확도 상승 ② 위험도 판단 신호 강화

| 소스 | 방식 | 제공 신호 |
|---|---|---|
| **CISA vulnrichment (ADP)** | 이미 다운로드하는 cvelistV5 레코드의 ADP 컨테이너 파싱 (추가 네트워크 비용 0) | SSVC Exploitation, CVSS/CWE 보강 — **최우선 ROI** |
| **ExploitDB** | P2에서 구축한 `files_exploits.csv` 매핑 재활용 | `has_public_exploit` 1급 신호 + 룰 프롬프트 컨텍스트 |
| **Metasploit** | `rapid7/metasploit-framework`의 `db/modules_metadata_base.json` 캐시 | `has_metasploit_module` — "무기화됨" 신호 |
| **KrCERT/KISA** (선택) | RSS/HTML 스크래핑 — 유지보수 취약, 후순위 | 국내 보안공지 "KR 공지" 배지 |

- 새 신호를 `_should_send_alert` 위험도 판단, `_should_generate_ai_rules` 게이트, `_build_cve_tags` 태그, Issue·대시보드 배지에 연결

---

## 실행 순서 요약

| 순서 | Phase | 핵심 산출물 | 규모 |
|:---:|---|---|---|
| 1 | P0 대청소 | blacklist/IOC 완전 제거, CVE 전용 export, 랜딩 변경 | 삭제 위주, 1세션 |
| 2 | P1 안정화 | 실패 알림, 하드닝, DB 보존 정책 | 경량, 1세션 |
| 3 | P2 다이어트 | nuclei/ExploitDB 저비용 수집 전환, 캐싱 (Gemini 유지) | 1세션 |
| 4 | P3 룰 품질 | pySigma/파서 검증, trust tier, 자기검증, 불가사유 고도화 | 1세션 |
| 5 | P4 대시보드 | 룰 렌더링·복사, CSV export (DB 무부담) | 1세션 |
| 6 | P5 소스 확대 | vulnrichment → ExploitDB 신호 → Metasploit → (KrCERT) | 1~2세션 |

각 Phase는 독립 커밋·배포 가능. P1↔P2 순서 교체 무방. P3~P5는 P0 완료 전제.

## 검증 방법

- **P0**: `python src/export_dashboard_data.py` 로컬 실행(자격증명 없으면 샘플 모드) → cves.json/stats.json만 생성 확인, `grep -r blacklist_ip src/` 0건, GitHub Pages에서 index→cve.html 랜딩 확인, argus.yml `workflow_dispatch` 수동 실행 green
- **P1**: 고의 오류 env로 실행해 Slack 실패 알림 도착 확인, Supabase 테이블 크기 추이 확인
- **P2**: argus.yml 수동 실행 → Actions 소요 시간 전후 비교, 로그에서 nuclei/ExploitDB 컨텍스트가 프롬프트에 정상 포함되는지 확인
- **P3~P5**: 실제 CVE 처리 결과의 Issue 리포트·Slack·대시보드를 육안 확인 — 룰 품질, 불가 사유 표시, trust 배지, Rate Limit 요약 로그로 호출 수 확인
