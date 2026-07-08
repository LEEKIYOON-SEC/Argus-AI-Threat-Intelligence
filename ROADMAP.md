# ARGUS 재편 로드맵: CVE 전용 위협 인텔리전스 플랫폼

## Context

ARGUS는 현재 CVE 스캐너 + IP 블랙리스트(The Shield) + IOC 통합 대시보드가 한 리포지토리에 얽혀 있다. 그 결과:
- **Supabase free tier 용량 부족** — `cves` + `shield_*` 테이블이 한 DB를 나눠 씀
- **AI 사용량 초과로 파이프라인 중단** — Groq TPD 소진
- **GitHub Actions 시간 과다** — 매시간 CVE 실행이 blacklist/IOC export + 외부 피드(URLhaus 등)까지 전부 재실행

사용자 최종 결정: **ARGUS = CVE 대시보드로 재정의하고, blacklist/IOC는 이 리포에서 완전히 제거한다("갈아엎기")**. blacklist는 추후 **별도 리포지토리 + 별도 DB**로 재구축 후 필요 시 통합. 이번 세션 산출물은 이 로드맵 문서이며, 구현은 사용량 초기화 후 Phase 단위로 순차 진행한다.

강화 우선순위(사용자 선택): ① 룰 품질·신뢰도 ② 대시보드·리포트 ③ 데이터 소스 확대. **모든 것은 100% 무료** (유료 서비스 절대 금지).

### 탐색으로 확인된 핵심 사실
- 두 파이프라인은 **import 수준에서 이미 완전 분리** — `src/blacklist_ip/`는 자체 config/notifier를 갖고 CVE 모듈을 전혀 import하지 않음. 결합은 `src/export_dashboard_data.py::main()`(5단계 통합 export), 공유 `stats.json`, 두 워크플로우가 같은 export를 호출하는 지점뿐 → **삭제가 안전함**
- `docs/index.html`은 현재 **ioc.html로 리다이렉트** (랜딩이 IOC임)
- `requirements.txt`의 `docker`, `slack_sdk`는 **어디서도 사용 안 함** (dead)
- `test_argus.py`는 `get_rules()` 시그니처 불일치(테스트 3인자 vs 실제 2인자)로 Test E/F **실행 불가**, 테스트 데이터 구조(중첩 dict)도 실제 코드(flat string)와 불일치
- Sigma 검증은 YAML 구조 검사뿐(엔진 검증 없음, pySigma 미설치), Yara만 실제 컴파일 검증, 네트워크 룰은 정규식 휴리스틱
- AI 분석(root_cause/scenario/mitigation)은 **GitHub Issue에만 존재** — `last_alert_state`에 저장되지 않아 대시보드(cves.json)에 못 나옴. 반면 룰 코드는 이미 cves.json에 export되는데 **대시보드가 렌더링하지 않음**
- `main()`에 실패 알림 없음(매시간 cron이 조용히 실패 가능), 워크플로우에 pip 캐시/timeout 없음
- `cve-dashboard.js`는 `statsData.cve`를 읽으므로 stats.json에서 blacklist 섹션을 제거해도 JS 수정 불필요

---

## Phase 0 — 대청소: blacklist/IOC 완전 제거 (최우선, 1세션)

> 목표: CVE 잔재만 남기고 전부 제거. Actions 시간·DB 용량·복잡도 즉시 회수.

1. **아카이브 태그 생성** (삭제 전 안전장치): `git tag archive/shield-ioc-final` 후 push — 추후 별도 리포 구축 시 이 시점에서 코드 추출
2. **코드 삭제**:
   - `src/blacklist_ip/` 전체
   - `.github/workflows/blacklist.yml`
   - `docs/blacklist.html`, `docs/ioc.html`, `docs/js/blacklist-dashboard.js`, `docs/js/ioc-dashboard.js`
   - `docs/data/blacklist.json`, `docs/data/ioc*.json` (ioc.json은 원래 아무도 안 읽는 dead 파일)
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

## Phase 1 — 안정화 (1세션)

1. **`test_argus.py` 삭제 → `tests/` pytest 재작성** (오프라인, API 키 불필요):
   - 대상 순수 함수: `collector._compute_content_hash`, `_is_bulk_commit`, `parse_affected`, `main._should_send_alert`, `is_target_asset`, `parse_cvss_vector`, `_should_generate_ai_rules`, `rule_manager._validate_sigma/_validate_yara/_validate_network_rule`, `_check_observables`, `rate_limiter.parse_retry_after`
   - 픽스처는 실제 코드가 기대하는 **flat 구조**로 작성
   - 라이브 통합 테스트가 필요하면 `tests/integration_smoke.py`로 분리, `workflow_dispatch` 수동 전용
2. **CI 워크플로우 신설** `.github/workflows/ci.yml`: push/PR 시 `pytest -q`, Python 3.11, `cache: pip`, `timeout-minutes: 15`
3. **파이프라인 실패 Slack 알림**: `main.py::main()` 최상위 try/except → 기존 `SLACK_WEBHOOK_URL`로 에러 전송 (알림 자체가 예외를 던지지 않게 가드)
4. **argus.yml 하드닝**: `cache: 'pip'`, `timeout-minutes: 30`
5. **Supabase 재시도**: `database.py`에 tenacity `@retry` (이미 의존성에 있음)
6. **DB 보존 정책**: 180일 지난 레코드의 `rules_snapshot`/`last_alert_state`만 null 처리 — export 실행 시 함께 수행. free tier 500MB 방어

## Phase 2 — AI·리소스 다이어트 (1세션)

> 페인포인트 직접 해결: "AI 사용량 많아서 멈추고, 액션 시간 오래 걸림"

1. **Gemini 제거 → Groq 통합**: `generate_korean_summary`(Gemini)를 Groq 분석 프롬프트에 흡수(분석 JSON에 `title_ko`/`summary_ko` 필드 추가) → 서비스 1개·키 1개·호출 1회 절감. `google-genai` 의존성·`GEMINI_API_KEY` 제거. 분석을 안 도는 저위험 CVE는 Groq 경량 번역 1회 or 원문 표시
2. **nuclei-templates 전체 tarball 다운로드 제거** (`_download_nuclei_repo`/`_search_local_nuclei`): 수백 MB를 매시간 받으면서 AI 프롬프트 참고용으로만 사용
3. **GitHub Code Search(`_search_github`) 제거**: 분당 10회 제한으로 거의 항상 429 + circuit breaker 차단. Exploit-DB 신호는 Phase 4의 CSV 방식으로 대체
4. **룰셋 tarball 캐싱**: SigmaHQ/Yara-Rules/ET Open을 `actions/cache`로 24h 캐시 → 매시간 재다운로드 제거

## Phase 3 — 룰 품질·신뢰도 강화 (1세션)

1. **pySigma 실검증**: `pysigma`(무료 pip, 오프라인 동작) 추가 → `_validate_sigma`에서 `SigmaCollection.from_yaml(code)` 파싱을 최종 게이트로. 기존 구조 검사는 사전 필터. docstring에만 있고 미구현인 `level` 검사도 실제 구현
2. **네트워크 룰 검증 강화**: `idstools` 또는 `suricataparser`(무료 pip, 순수 Python 룰 파서)로 실제 파싱 검증
3. **룰 신뢰 등급(trust tier)**: 룰마다 `trust: official-verified | ai-validated | ai-draft`를 `rules_snapshot`에 저장 → export가 이미 rules_snapshot을 내보내므로 자동으로 대시보드까지 전달. Issue·대시보드에 등급 배지
4. **AI 룰 자기검증 패스**: 생성 후 Groq에 "룰이 CVE 설명과 일치하는가, FP 위험은?" 저비용 검토 1회(`reasoning_effort: low`) — 불일치 시 폐기. TPD 게이트 뒤라 토큰 예산 안전

## Phase 4 — 대시보드·리포트 강화 (1세션)

1. **AI 분석을 대시보드로**: `create_github_issue`가 `analysis`도 반환 → `current_state["analysis"]` 병합 후 `last_alert_state` 저장 → `export_cves`에서 `entry["analysis"]` export → 모달에 root_cause/공격 시나리오/mitigation 렌더링
2. **탐지 룰 모달 렌더링**: cves.json에 **이미 들어있는** `entry["rules"]`를 모달에 `<pre>` + trust 배지로 표시 (기존 `escapeHtml`로 XSS 방어)
3. **클라이언트 사이드 export**: 룰별 클립보드 복사(`navigator.clipboard`), 필터된 목록 CSV/JSON 다운로드(Blob) — 서버·의존성 불필요
4. (스트레치) STIX 2.1 번들 export — 순수 JS 객체 구성

## Phase 5 — 데이터 소스 확대 (1~2세션, 전부 무료·키 불필요)

| 소스 | 방식 | 제공 신호 |
|---|---|---|
| **CISA vulnrichment (ADP)** | 이미 다운로드하는 cvelistV5 레코드의 ADP 컨테이너 파싱 (추가 네트워크 비용 0) | SSVC Exploitation, CVSS/CWE 보강 — **최우선 ROI** |
| **ExploitDB** | `gitlab.com/exploit-database/exploitdb`의 `files_exploits.csv` 캐시 (CVE→exploit 매핑) | `has_public_exploit` 1급 신호 |
| **Metasploit** | `rapid7/metasploit-framework`의 `db/modules_metadata_base.json` 캐시 | `has_metasploit_module` — "무기화됨" 신호 |
| **KrCERT/KISA** (선택) | RSS/HTML 스크래핑 — 유지보수 취약, 후순위 | 국내 보안공지 "KR 공지" 배지 |

- 새 신호를 `_should_send_alert` 위험도 판단, `_should_generate_ai_rules` 게이트, `_build_cve_tags` 태그, 대시보드 배지에 연결

---

## 실행 순서 요약

| 순서 | Phase | 핵심 산출물 | 규모 |
|:---:|---|---|---|
| 1 | P0 대청소 | blacklist/IOC 완전 제거, CVE 전용 export, 랜딩 변경 | 삭제 위주, 1세션 |
| 2 | P1 안정화 | pytest + CI + 실패알림 + 하드닝 + DB 보존 | 1세션 |
| 3 | P2 다이어트 | Gemini 제거, nuclei/CodeSearch 제거, 캐싱 | 1세션 |
| 4 | P3 룰 품질 | pySigma/파서 검증, trust tier, 자기검증 | 1세션 |
| 5 | P4 대시보드 | AI분석·룰 렌더링, 복사/CSV export | 1세션 |
| 6 | P5 소스 확대 | vulnrichment → ExploitDB → Metasploit → (KrCERT) | 1~2세션 |

각 Phase는 독립 커밋·배포 가능. P1↔P2 순서 교체 무방. P3~P5는 P0 완료 전제.

## 검증 방법

- **P0**: `python src/export_dashboard_data.py` 로컬 실행(자격증명 없으면 샘플 모드) → cves.json/stats.json만 생성 확인, `grep -r blacklist_ip src/` 0건, GitHub Pages에서 index→cve.html 랜딩 확인, argus.yml `workflow_dispatch` 수동 실행 green
- **P1**: `pytest -q` 전체 통과, CI green, 고의 오류 env로 Slack 실패 알림 도착 확인
- **P2~P5**: Phase마다 argus.yml 수동 실행 → Actions 소요 시간 전후 비교, Slack/Issue/대시보드 산출물 육안 확인, Rate Limit 요약 로그로 호출 수 감소 확인
