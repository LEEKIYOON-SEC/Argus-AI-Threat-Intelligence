# Argus - AI Threat Intelligence Platform

**AI 기반 위협 인텔리전스 자동화 플랫폼**

CVE 취약점 분석부터 탐지 룰 생성, IP 블랙리스트 관리까지 보안 운영에 필요한 위협 인텔리전스를 자동으로 수집하고 분석하여 Slack으로 전달합니다.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Slack Alert Examples](#slack-alert-examples)
- [Pipeline Details](#pipeline-details)
- [Testing](#testing)
- [Supabase Schema](#supabase-schema)
- [License](#license)

---

## Overview

Argus는 두 개의 독립 파이프라인으로 구성됩니다.

| 파이프라인 | 설명 | 실행 주기 |
|-----------|------|----------|
| **Phase 1 - CVE Scanner** | CVE 수집 → AI 분석 → 탐지 룰 생성 → Slack/GitHub Issue | 매 1시간 (UTC, `0 * * * *`) |
| **Phase 2 - The Shield** | IP 위협 피드 수집 → 평판 조회 → 스코어링 → 일일 리포트 | 매일 00:00 UTC (`0 0 * * *`) = 09:00 KST |

### 핵심 가치

- **자동화**: CVE 발표 → 분석 → 탐지 룰 → 보안 담당자 알림까지 사람 개입 없이 동작
- **AI 분석**: LLM 기반 근본 원인 분석, 공격 시나리오 생성, 맞춤형 탐지 룰 자동 생성
- **다중 엔진 룰**: Sigma, Snort 2.9/3, Suricata 5/7, YARA, Nuclei 등 실무 보안 장비에 바로 적용 가능
- **IP 위험도 관리**: 6개 위협 피드 통합, AbuseIPDB/InternetDB 보강, 방화벽 정책 자동 권고

---

## Architecture

```
                         GitHub Actions (Scheduler)
                                  │
              ┌───────────────────┴───────────────────┐
              │                                       │
     Phase 1: CVE Scanner                  Phase 2: The Shield
     (매 1시간, UTC)                        (매일 00:00 UTC = 09:00 KST)
              │                                       │
     ┌────────┴────────┐                    ┌────────┴────────┐
     │  1. 데이터 수집   │                    │  1. 피드 수집     │
     │  - CISA KEV     │                    │  - ET, Spamhaus  │
     │  - CVE Project  │                    │  - abuse.ch, Tor │
     │  - EPSS/NVD     │                    │  - Blocklist.de  │
     ├─────────────────┤                    ├──────────────────┤
     │  2. AI 분석      │                    │  2. Delta 계산    │
     │  - Groq LLM     │                    │  - 신규/제거 비교   │
     │  - 번역 (Gemini) │                    ├──────────────────┤
     ├─────────────────┤                    │  3. Enrichment    │
     │  3. 룰 생성      │                    │  - AbuseIPDB (선택)│
     │  - Sigma/Snort  │                    │  - InternetDB    │
     │  - YARA/Nuclei  │                    ├──────────────────┤
     ├─────────────────┤                    │  4. Scoring       │
     │  4. 알림 & 저장   │                    │  - 0~100점 산정    │
     │  - Slack        │                    ├──────────────────┤
     │  - GitHub Issue │                    │  5. 리포트 & 저장   │
     │  - Supabase     │                    │  - Slack 리포트    │
     └─────────────────┘                    │  - Supabase 저장  │
                                            └──────────────────┘
```

### 외부 서비스 연동

| 서비스 | 용도 | 인증 |
|-------|------|------|
| **CISA KEV** | 알려진 익스플로잇 취약점 목록 | 공개 API |
| **CVE Project** | 최신 CVE 메타데이터 | GitHub Token |
| **EPSS (FIRST.org)** | 익스플로잇 예측 점수 | 공개 API |
| **NVD** | CVSS, CWE 상세 정보 | API Key (선택) |
| **Groq** | LLM 기반 AI 분석/룰 생성 | API Key |
| **Google Gemini** | 한국어 번역 | API Key |
| **Supabase** | PostgreSQL 데이터베이스 | URL + Key |
| **Slack** | 알림 및 리포트 전송 | Webhook URL |
| **GitHub API** | Issue 생성, 룰 검색 | Token |
| **AbuseIPDB** | IP 평판 조회 (Shield 선택) | API Key |
| **InternetDB (Shodan)** | 포트/취약점 열거 | 공개 API |
| **SigmaHQ / ET Open** | 공개 탐지 룰 검색 | 공개 |

---

## Features

### Phase 1 - CVE Scanner

**데이터 수집**
- CISA KEV 실시간 추적
- 최근 2시간 내 발표된 CVE 자동 수집
- EPSS 점수 일괄 조회
- NVD CVSS/CWE 보강 (선택)
- PoC(Proof-of-Concept) 공개 여부 감지
- VulnCheck KEV 추가 소스 (선택)

**AI 분석 (Groq LLM)**
- 취약점 근본 원인 분석
- MITRE ATT&CK 기반 공격 시나리오 생성
- 비즈니스 영향도 평가
- 대응 방안 권고
- 탐지 룰 생성 가능성 판단 (Observable Gate)

**탐지 룰 자동 생성**
| 엔진 | 공개 룰 소스 | AI 생성 |
|------|------------|---------|
| **Sigma** | SigmaHQ | O |
| **Snort 2.9** | ET Open, Community | O |
| **Snort 3** | ET Open, Community | O |
| **Suricata 5** | ET Open | O |
| **Suricata 7** | ET Open | O |
| **YARA** | Yara-Rules | O |
| **Nuclei** | Nuclei Templates | - |

- 공개 룰 우선 사용, 없을 경우 AI가 생성
- AI 생성 룰은 정규식 기반 구문 검증 + 환각 방지 가드 적용
- 공식 룰 발견 시 기존 AI 룰을 대체하고 Slack으로 재알림

**알림 트리거 조건**
| 트리거 | 조건 | 아이콘 |
|--------|------|--------|
| `NEW` | 최초 발견된 CVE | `[NEW]` |
| `KEV` | CISA KEV 등록 | `[KEV]` |
| `EPSS` | EPSS >= 10% 이고 증가폭 > 5%p | `[EPSS]` |
| `CVSS` | CVSS 점수가 7.0 이상으로 상승 | `[CVSS]` |

**자산 매칭 (assets.json)**
- 1차: CVE `affected` 필드의 구조화된 vendor/product 매칭
- 2차: description 텍스트 검색 (fallback)
- 와일드카드(`*`) 지원으로 전체 모니터링 가능

### Phase 2 - The Shield (IP Blacklist)

**위협 피드 수집 (6개 소스)**
| 피드 | 제공자 | 기본 점수 | 설명 |
|------|--------|----------|------|
| ET Compromised IPs | Emerging Threats | 60 | 침해된 IP |
| ET Block IPs | Emerging Threats | 70 | 차단 권고 IP |
| Spamhaus DROP | Spamhaus | 80 | 스팸/봇넷 CIDR |
| Feodo C2 | abuse.ch | 90 | C&C 서버 IP |
| Tor Exit Nodes | TorProject | 40 | Tor 출구 노드 |
| Blocklist.de | Blocklist.de | 50 | 공격 IP 통합 |

**위험도 스코어링 (0~100점)**
```
최종 점수 = clamp(기본 점수 + 소스 보너스 + AbuseIPDB 조정 + InternetDB 조정, 0, 100)

- 기본 점수: 피드별 40~90점
- 소스 보너스: 추가 피드당 +5점 (최대 +15)
- AbuseIPDB 조정 (키 없으면 생략):
    confidence < 10 → -10
    confidence >= 10 → int(confidence * 0.25) + min(8, reports // 5)
    reports < 3이면 위 결과를 50% 감쇠
    (범위: -10 ~ +33)
- InternetDB 조정:
    위험 포트 수 * 3 (최대 +15) + 알려진 취약점 수 * 2 (최대 +10)
    (범위: 0 ~ +25)
```

| 등급 | 점수 | 의미 |
|------|------|------|
| Critical | 80+ | 즉시 차단 |
| High | 60~79 | 차단 권고 |
| Medium | 40~59 | 모니터링 |
| Low | 40 미만 | 참고 |

**방화벽 관리 자동 권고**
- 매일 신규 고위험 IP TOP 10 알림 (방화벽 등록 대상)
- 피드 제거 감지: 어제 Critical/High → 오늘 모든 피드에서 사라진 IP → 차단 해제 대상
- 등급 하락 감지: 어제 Critical/High → 오늘 Medium/Low로 하락 → 차단 해제 검토

---

## Project Structure

```
Argus-AI-Threat-Intelligence/
├── .github/workflows/
│   ├── argus_scheduler.yml           # Phase 1: CVE 스캔 워크플로우
│   ├── argus_test.yml                # 통합 테스트 워크플로우
│   └── shield_blacklist_daily.yml    # Phase 2: 일일 IP 블랙리스트
│
├── src/
│   ├── main.py                       # Phase 1 메인 파이프라인
│   ├── collector.py                  # CVE 데이터 수집기
│   ├── analyzer.py                   # AI 분석 엔진 (Groq LLM)
│   ├── rule_manager.py               # 탐지 룰 수집/생성 관리
│   ├── notifier.py                   # Slack 알림 (CVE 알림, 공식 룰 알림)
│   ├── database.py                   # Supabase 인터페이스
│   ├── config.py                     # 설정 관리 (클래스 상수 + 환경변수 검증)
│   ├── logger.py                     # 로깅
│   ├── rate_limiter.py               # API 속도 제한 관리
│   ├── performance_monitor.py        # 성능 모니터링
│   ├── test_argus.py                 # 통합 테스트 스크립트
│   │
│   └── blacklist_ip/                 # Phase 2: The Shield
│       ├── main.py                   # Shield 메인 파이프라인
│       ├── config.py                 # Shield 설정 로더 (환경변수 기반)
│       ├── collector_tier1.py        # 피드 수집기 (6개 소스)
│       ├── enricher_tier2.py         # IP 보강 (AbuseIPDB, InternetDB)
│       ├── scoring.py                # 위험도 스코어링
│       ├── delta.py                  # 일일 변동 계산
│       ├── store_supabase.py         # Supabase 저장소
│       ├── blacklist_ip_notifier.py  # Shield Slack 리포트
│       └── feeds.yml                 # 위협 피드 설정
│
├── assets.json                       # 모니터링 대상 자산 정의
├── config_prod.json                  # 운영 환경 설정 참조 파일 (*)
├── config_dev.json                   # 개발 환경 설정 참조 파일 (*)
├── requirements.txt                  # Python 의존성
└── README.md
```

> **(\*) `config_prod.json` / `config_dev.json` 참고:**
> 현재 코드는 이 JSON 파일을 런타임에 로드하지 않습니다. Phase 1 설정은 `src/config.py`의 `ArgusConfig` 클래스 상수로, Phase 2 설정은 `src/blacklist_ip/config.py`의 `Settings` dataclass 기본값 + 환경변수로 관리됩니다. JSON 파일은 설정값 레퍼런스 용도로만 존재하며, 향후 파일 기반 설정 로딩 기능 추가 시 활용할 예정입니다.

---

## Setup

### 1. 저장소 클론

```bash
git clone https://github.com/LEEKIYOON-SEC/Argus-AI-Threat-Intelligence.git
cd Argus-AI-Threat-Intelligence
```

### 2. 의존성 설치

```bash
pip install -r requirements.txt
```

**주요 의존성:**

| 패키지 | 용도 |
|--------|------|
| `requests` | HTTP API 호출 |
| `groq` | Groq LLM API 클라이언트 |
| `google-genai` | Google Gemini 번역 |
| `supabase` | Supabase 데이터베이스 |
| `slack_sdk` | Slack 메시지 빌드 |
| `PyYAML` | YAML 설정 파싱 |
| `yara-python` | YARA 룰 컴파일 검증 |
| `tenacity` | API 재시도 로직 |
| `pytz` | 시간대 관리 |

### 3. GitHub Secrets 설정

GitHub 저장소 Settings > Secrets and variables > Actions에 다음 시크릿을 등록합니다.

#### 필수 (Phase 1 - CVE Scanner)

| Secret | 설명 |
|--------|------|
| `GH_TOKEN` | GitHub Personal Access Token (Issue 생성, 룰 검색) |
| `SUPABASE_URL` | Supabase 프로젝트 URL |
| `SUPABASE_KEY` | Supabase anon/service key |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook URL |
| `GROQ_API_KEY` | Groq API 키 |
| `GEMINI_API_KEY` | Google Gemini API 키 |

> **`GITHUB_REPOSITORY`**: GitHub Actions 환경에서 자동 제공됩니다 (`owner/repo` 형식). 로컬 실행 시 이 변수가 없으면 GitHub Issue 생성이 스킵되며, AI 분석과 Slack 알림은 정상 동작합니다. 로컬에서 Issue까지 원하면 `export GITHUB_REPOSITORY="owner/repo"`를 설정하세요.

#### 필수 (Phase 2 - The Shield)

Phase 1과 공유하는 3개만 필수입니다:

| Secret | 설명 |
|--------|------|
| `SUPABASE_URL` | Supabase 프로젝트 URL |
| `SUPABASE_KEY` | Supabase anon/service key |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook URL |

> 3개 중 하나라도 없으면 Shield 시작 시 `RuntimeError`가 발생합니다.

#### 선택

| Secret | 용도 | 미설정 시 동작 |
|--------|------|--------------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB IP 평판 조회 (Free tier: 1,000 조회/일) | AbuseIPDB enrichment 단계 스킵, InternetDB만 사용 |
| `NVD_API_KEY` | NVD API (Phase 1: CVSS/CWE 상세 조회) | NVD 보강 없이 진행 |
| `VULNCHECK_API_KEY` | VulnCheck API (Phase 1: 확장 KEV 소스) | VulnCheck 소스 없이 진행 |

---

## Configuration

### assets.json - 모니터링 대상 자산

```json
{
  "active_rules": [
    { "vendor": "*", "product": "*" }
  ]
}
```

와일드카드(`*`)는 모든 CVE를 모니터링합니다. 특정 제품만 모니터링하려면:

```json
{
  "active_rules": [
    { "vendor": "apache", "product": "struts" },
    { "vendor": "microsoft", "product": "exchange_server" },
    { "vendor": "atlassian", "product": "confluence" }
  ]
}
```

### Phase 1 설정 (`src/config.py` ArgusConfig 클래스)

Phase 1의 설정값은 `ArgusConfig` 클래스 상수로 하드코딩되어 있습니다. 주요 값:

| 설정 | 현재 값 | 설명 |
|------|---------|------|
| `MODEL_PHASE_0` | `gemma-3-27b-it` | 번역/요약용 모델 |
| `MODEL_PHASE_1` | `openai/gpt-oss-120b` | 심층 분석용 모델 |
| `max_workers` | 3 | 병렬 CVE 처리 워커 수 |
| `cve_fetch_hours` | 2 | 최근 N시간 내 CVE 수집 |
| `rule_check_interval_days` | 7 | 공식 룰 재확인 주기 |
| `github_api calls_per_hour` | 5000 | GitHub API rate limit |
| `groq_api calls_per_minute` | 30 | Groq API rate limit |

### Phase 2 설정 (`src/blacklist_ip/config.py` Settings dataclass)

Phase 2의 설정값은 `Settings` dataclass 기본값으로 정의되어 있습니다. 주요 값:

| 설정 | 기본값 | 설명 |
|------|--------|------|
| `critical_threshold` | 80 | Critical 등급 기준 |
| `high_threshold` | 60 | High 등급 기준 |
| `medium_threshold` | 40 | Medium 등급 기준 |
| `source_bonus_step` | 5 | 추가 피드당 보너스 점수 |
| `source_bonus_cap` | 15 | 소스 보너스 최대값 |
| `max_enrich_count` | 500 | 최대 enrichment 대상 수 (GitHub Actions timeout 방어) |
| `enrich_workers` | 10 | InternetDB 병렬 워커 수 |
| `topn_report` | 10 | Slack TOP N 리포트 수 |
| `abuseipdb_daily_max` | 1,000 | AbuseIPDB 일일 쿼터 |
| `cache_ttl (AbuseIPDB)` | 24시간 | AbuseIPDB 캐시 TTL |
| `cache_ttl (InternetDB)` | 72시간 | InternetDB 캐시 TTL |

### feeds.yml - 위협 피드 설정

```yaml
feeds:
  - name: ET_compromised_ips
    url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    format: "plain_ip"
    base_score: 60
    category: "ET compromised-ips"
  # ... (6개 피드)
```

---

## Usage

### Phase 1 - CVE Scanner

**GitHub Actions (권장):**

Actions 탭 > `Argus Threat Intel Scan` > Run workflow

스케줄 (매 1시간, UTC):
```yaml
# .github/workflows/argus_scheduler.yml
on:
  schedule:
    - cron: '0 * * * *'
```

**로컬 실행:**
```bash
export GH_TOKEN="..."
export SUPABASE_URL="..."
export SUPABASE_KEY="..."
export SLACK_WEBHOOK_URL="..."
export GROQ_API_KEY="..."
export GEMINI_API_KEY="..."

# Issue 생성까지 원하면 (선택):
export GITHUB_REPOSITORY="owner/repo"

python src/main.py
```

> **참고:** `GITHUB_REPOSITORY`가 없으면 GitHub Issue 생성만 스킵됩니다. Slack 알림, AI 분석, Supabase 저장은 정상 동작합니다.

### Phase 2 - The Shield

**GitHub Actions (매일 00:00 UTC = 09:00 KST 자동 실행):**

자동 스케줄 설정 완료 (timeout: 45분). 수동 실행: Actions 탭 > `The Shield - Daily Blacklist IP Report` > Run workflow

**로컬 실행:**
```bash
# 필수 (3개)
export SLACK_WEBHOOK_URL="..."
export SUPABASE_URL="..."
export SUPABASE_KEY="..."

# 선택 (없으면 AbuseIPDB enrichment 스킵)
export ABUSEIPDB_API_KEY="..."

PYTHONPATH=src python -m blacklist_ip.main --mode daily --tz Asia/Seoul
```

> **`PYTHONPATH=src`**: Shield는 `src/blacklist_ip/` 패키지로 실행되므로 `PYTHONPATH=src`를 반드시 지정해야 합니다. GitHub Actions 워크플로우에도 동일하게 설정되어 있습니다.

---

## Slack Alert Examples

### 1. 신규 CVE 알림

```
[NEW] 신규 CVE: CVE-2024-12345
───────────────────────────────
Apache Struts OGNL 인젝션을 통한 원격 코드 실행

영향받는 제품:
  Vendor: Apache
  Product: Struts
  Versions: 2.3.5 ~ 2.5.30
  Patch: 2.5.31
───────────────────────────────
  CVSS        EPSS       KEV       CWE
  9.8         85.2%      YES       CWE-917
───────────────────────────────
Apache Struts의 Content-Type 헤더를 통한 OGNL
인젝션으로 원격 코드 실행이 가능합니다...

  [AI 상세 분석 리포트 →]  (GitHub Issue 링크)
```

### 2. 공식 룰 발견 알림

```
  공식 룰 발견: CVE-2021-44228
───────────────────────────────
이전에 AI 생성 룰로 보고된 취약점에 대한
공식 검증된 룰이 발견되었습니다.
───────────────────────────────

  Sigma (Public SigmaHQ)
  ┌─────────────────────────────┐
  │ title: Log4Shell Detection  │
  │ status: stable              │
  │ logsource:                  │
  │   product: java             │
  │ detection:                  │
  │   selection:                │
  │     CommandLine|contains:   │
  │       'jndi:ldap'           │
  └─────────────────────────────┘

  SNORT2 (Public Snort 2.9 ET Open)
  ┌─────────────────────────────┐
  │ alert tcp $EXTERNAL_NET ... │
  └─────────────────────────────┘

  SNORT3 (Public Snort 3 Community)
  ┌─────────────────────────────┐
  │ alert http $EXTERNAL_NET ...│
  └─────────────────────────────┘

  SURICATA5 (Public Suricata 5 ET Open)
  ┌─────────────────────────────┐
  │ alert http $EXTERNAL_NET ...│
  └─────────────────────────────┘

  SURICATA7 (Public Suricata 7 ET Open)
  ┌─────────────────────────────┐
  │ alert http $EXTERNAL_NET ...│
  └─────────────────────────────┘

  YARA (Public Yara-Rules)
  ┌─────────────────────────────┐
  │ rule Log4Shell_Exploit {    │
  │   ...                       │
  └─────────────────────────────┘

총 6개 엔진의 공식 룰 발견.
위 룰을 복사하여 보안 장비에 등록하세요.

  [전체 룰 + 상세 리포트 보기 →]
```

### 3. The Shield 일일 리포트

```
  The Shield 일일 위협 IP 리포트 (2025-02-17)
───────────────────────────────
총 수집: 4,521개
  - 신규: 287개 (+6.3%)
  - 제거: 143개
───────────────────────────────
  Critical (80+)    High (60-79)
       42              318
  Medium (40-59)    Low (<40)
     1,892            2,269
───────────────────────────────

  신규 고위험 IP TOP 10:
  1. 45.xx.xx.xx (92점) - abuse.ch Feodo C2
     AbuseIPDB 98% (reports=247), Ports [22, 80, 443]
  2. 91.xx.xx.xx (87점) - ET Block-IPs
     AbuseIPDB 85% (reports=52), Ports [22, 8080]
  ...

───────────────────────────────
  방화벽 블랙리스트 관리

  제거 대상 (2건):
  어제 고위험 -> 오늘 모든 피드에서 사라짐. 차단 해제하세요.
  - 1.2.3.4 (어제 92점/Critical) - botnet
  - 5.6.7.8 (어제 78점/High) - scanner

  등급 하락 검토 (3건):
  어제 고위험 -> 오늘 Medium/Low로 하락. 차단 해제를 검토하세요.
  - 9.10.11.12 (Critical 85점 -> Medium 45점) - spam
  - 13.14.15.16 (High 72점 -> Low 28점) - scanner

───────────────────────────────
API usage - AbuseIPDB: 287, InternetDB: 287
```

---

## Pipeline Details

### Phase 1 실행 흐름

```
1. Health Check
   └─ 환경 변수 검증 (6개 필수), assets.json 로드

2. 공식 룰 재탐색 (Official Rule Re-discovery)
   └─ 이전 AI 생성 룰의 CVE에 대해 공식 룰이 새로 발표되었는지 확인
   └─ 발견 시: GitHub Issue 업데이트 + Slack 알림

3. 데이터 수집
   ├─ CISA KEV 전체 목록 가져오기
   ├─ 최근 2시간 CVE 수집 (CVE Project API)
   └─ EPSS 점수 배치 조회

4. 병렬 CVE 처리 (3 workers)
   ├─ NVD 보강 (CVSS, CWE) - NVD_API_KEY 있을 때
   ├─ 자산 매칭 (affected vendor/product → description fallback)
   ├─ 알림 트리거 판정 (NEW/KEV/EPSS/CVSS)
   ├─ 한국어 번역 (Google Gemini)
   ├─ 고위험 시 (CVSS >= 7.0 또는 KEV) GitHub Issue 생성
   │   ├─ AI 근본 원인 분석
   │   ├─ 공격 시나리오 (MITRE ATT&CK)
   │   ├─ 탐지 룰 생성 (Sigma/Snort/Suricata/YARA)
   │   └─ 대응 방안 권고
   │   └─ GITHUB_REPOSITORY 미설정 시 Issue 생성만 스킵
   ├─ Slack 알림 전송
   └─ Supabase DB 업데이트
```

### Phase 2 실행 흐름

```
Step 1/5: Tier 1 피드 수집
   └─ 6개 위협 피드 다운로드 (개별 실패 허용)

Step 2/5: Delta 계산
   ├─ 어제 vs 오늘 indicator 세트 비교 (Supabase 기반)
   ├─ 신규/제거 IP 식별
   └─ 어제 고위험 중 제거된 IP 식별

Step 3/5: Tier 2 Enrichment
   ├─ 신규 IP만 대상 (CIDR 표기 "/" 포함 indicator는 제외)
   ├─ base_score 기준 우선순위 정렬 (높은 점수 우선)
   ├─ 하드캡 적용: 최대 500개 (max_enrich_count)
   ├─ AbuseIPDB 순차 조회 (1초 간격, ABUSEIPDB_API_KEY 없으면 스킵)
   ├─ InternetDB 병렬 조회 (10 workers)
   └─ 캐시 활용 (AbuseIPDB 24h, InternetDB 72h TTL)

Step 4/5: Scoring
   ├─ 기본 점수 + 소스 보너스 + AbuseIPDB 조정 + InternetDB 조정
   ├─ 등급 분류 (Critical 80+ / High 60+ / Medium 40+ / Low)
   └─ 등급 하락 IP 감지 (어제 고위험 → 오늘 중/저위험)

Step 5/5: 저장 + 리포트
   ├─ Supabase에 일별 스냅샷 저장
   └─ Slack 일일 리포트 전송
```

---

## Testing

통합 테스트를 통해 각 모듈의 동작을 검증합니다.

### GitHub Actions에서 실행

Actions 탭 > `Argus Phase 1 Test` > 테스트 대상 선택 > Run workflow

### 로컬에서 실행

```bash
cd src

# 전체 테스트
python test_argus.py

# 개별 테스트
python test_argus.py --test A    # Observable Gate 검증
python test_argus.py --test B    # AI 룰 생성 (실제 API 호출)
python test_argus.py --test C    # 공개 룰 검색
python test_argus.py --test D    # 공식 룰 Slack 알림
python test_argus.py --test E    # 전체 파이프라인
python test_argus.py --test F    # get_rules 흐름 검증

# 복수 테스트
python test_argus.py --test D,E
```

### 테스트 항목

| 테스트 | 설명 | API 호출 |
|--------|------|----------|
| **A** | Observable Gate: AI 룰 생성 가능 여부 판단 | 없음 |
| **B** | AI 룰 생성: Groq API로 Sigma/Snort/YARA 생성 | Groq |
| **C** | 공개 룰 검색: SigmaHQ, ET Open 등에서 룰 탐색 | GitHub |
| **D** | Slack 알림: 모든 엔진 공식 룰 발견 시뮬레이션 | Slack |
| **E** | 전체 파이프라인: 수집→분석→룰→Slack | 전체 |
| **F** | get_rules 흐름: skip_reasons, nuclei 포함 검증 | Groq, GitHub |

---

## Supabase Schema

### Phase 1 테이블

```sql
-- CVE 이력
CREATE TABLE cve_history (
  cve_id TEXT PRIMARY KEY,
  first_seen TIMESTAMPTZ,
  last_updated TIMESTAMPTZ,
  cvss REAL,
  epss REAL,
  is_kev BOOLEAN,
  alert_reasons TEXT[],
  analysis JSONB,
  rules JSONB,
  issue_url TEXT
);
```

### Phase 2 테이블

```sql
-- 일별 스냅샷 메타
CREATE TABLE shield_daily_snapshots (
  date DATE PRIMARY KEY,
  total_count INTEGER,
  new_count INTEGER,
  removed_count INTEGER,
  api_usage JSONB
);

-- 일별 indicator 상세
CREATE TABLE shield_indicators (
  date DATE,
  indicator TEXT,
  type TEXT,
  category TEXT,
  sources TEXT[],
  base_score INTEGER,
  final_score INTEGER,
  risk TEXT,
  enrichment JSONB,
  PRIMARY KEY (date, indicator)
);

-- Enrichment 캐시
CREATE TABLE shield_enrichment_cache (
  indicator TEXT,
  provider TEXT,
  data JSONB,
  ttl_until TIMESTAMPTZ,
  PRIMARY KEY (indicator, provider)
);
```

---

## License

MIT License

Copyright (c) 2025 LEEKIYOON-SEC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.