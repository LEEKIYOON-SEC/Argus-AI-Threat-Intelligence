# Argus - AI Threat Intelligence Platform

**AI 기반 위협 인텔리전스 자동화 플랫폼**

CVE 취약점 분석부터 탐지 룰 생성, IP 블랙리스트 관리, IOC 통합까지 보안 운영에 필요한 위협 인텔리전스를 자동으로 수집·분석하여 Slack으로 전달하고, GitHub Pages 대시보드로 시각화합니다.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Dashboard](#dashboard)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Slack Alert Examples](#slack-alert-examples)
- [Pipeline Details](#pipeline-details)
- [Supabase Schema](#supabase-schema)
- [License](#license)

---

## Overview

Argus는 세 개의 독립 파이프라인으로 구성됩니다.

| 파이프라인 | 설명 | 실행 주기 |
|-----------|------|----------|
| **Phase 1 - CVE Scanner** | CVE 수집 → AI 분석 → 탐지 룰 생성 → Slack/GitHub Issue | 수동 실행 (`workflow_dispatch`) |
| **Phase 2 - The Shield** | IP 위협 피드 수집 → 평판 조회 → 스코어링 → 일일 리포트 | 매일 00:00 UTC (`0 0 * * *`) = 09:00 KST |
| **Phase 3 - IOC Dashboard** | CVE + IP + URL + Hash + Rule → 통합 IOC 시각화 | Phase 1/2 실행 시 자동 export |

### 핵심 가치

- **자동화**: CVE 발표 → 분석 → 탐지 룰 → 보안 담당자 알림까지 사람 개입 없이 동작
- **AI 분석**: LLM 기반 근본 원인 분석, 공격 시나리오 생성, 맞춤형 탐지 룰 자동 생성
- **다중 엔진 룰**: Sigma, Snort 2.9/3, Suricata 5/7, YARA 등 실무 보안 장비에 바로 적용 가능
- **IP 위험도 관리**: 8개 위협 피드 통합, AbuseIPDB/InternetDB 보강, 기간 기반 가중치, 카테고리별 임계값, 방화벽 정책 자동 권고
- **IOC 통합**: URLhaus, MalwareBazaar, PhishTank/OpenPhish 피드 연동, 타입별 Lazy-Load 대시보드
- **스마트 필터링**: 콘텐츠 해시 기반 벌크 커밋 감지로 메타데이터 패치 무시, 실제 변경된 CVE만 처리
- **Thread-Safe Rate Limiting**: 10개 API 엔드포인트별 속도 제어, 429 자동 대응, 사용률 요약 리포트

---

## Architecture

```
                         GitHub Actions (Scheduler)
                                  │
         ┌────────────────────────┼────────────────────────┐
         │                        │                        │
Phase 1: CVE Scanner     Phase 2: The Shield      Phase 3: IOC Export
(수동 실행)               (매일 09:00 KST)          (자동 연동)
         │                        │                        │
┌────────┴────────┐     ┌────────┴────────┐     ┌────────┴────────┐
│  1. 데이터 수집   │     │  1. 피드 수집     │     │  1. CVE → IOC    │
│  - CISA KEV     │     │  - ET, Spamhaus  │     │  2. IP → IOC     │
│  - CVE Project  │     │  - abuse.ch      │     │  3. Rule → IOC   │
│  - EPSS/NVD     │     │  - Tor (이중화)   │     │  4. URLhaus      │
│  - 스마트 필터링  │     │  - ThreatFox     │     │  5. MalwareBazaar│
├─────────────────┤     │  - Blocklist.de  │     │  6. PhishTank    │
│  2. AI 분석      │     ├──────────────────┤     │     /OpenPhish   │
│  - Groq LLM     │     │  2. Delta 계산    │     └────────┬────────┘
│  - 번역 (Gemini) │     │  - 신규/제거 비교   │              │
├─────────────────┤     ├──────────────────┤     ┌────────┴────────┐
│  3. 룰 생성      │     │  3. Enrichment    │     │  GitHub Pages    │
│  - Sigma/Snort  │     │  - AbuseIPDB     │     │  대시보드         │
│  - YARA         │     │  - InternetDB    │     │  - CVE 대시보드   │
├─────────────────┤     ├──────────────────┤     │  - IP 대시보드    │
│  4. 알림 & 저장   │     │  4. Scoring       │     │  - IOC 통합      │
│  - Slack        │     │  - 카테고리별 임계값 │     └─────────────────┘
│  - GitHub Issue │     │  - 기간 기반 가중치  │
│  - Supabase     │     ├──────────────────┤
└─────────────────┘     │  5. 리포트 & 저장   │
                        │  - Slack 리포트    │
                        │  - Supabase 저장  │
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
| **URLhaus** | 악성 URL 피드 | 공개 API |
| **MalwareBazaar** | 악성코드 해시 피드 | 공개 API |
| **PhishTank** | 피싱 URL 피드 | API Key (선택) |
| **OpenPhish** | 피싱 URL 피드 (PhishTank fallback) | 공개 |
| **ThreatFox** | C2/Malware IP 피드 | 공개 API |

---

## Features

### Phase 1 - CVE Scanner

**데이터 수집**
- CISA KEV 실시간 추적
- 최근 2시간 내 발표된 CVE 자동 수집 (스마트 필터링 적용)
- 콘텐츠 해시 기반 벌크 커밋 감지 → 메타데이터 패치 무시
- EPSS 점수 배치 조회
- NVD CVSS/CWE 보강 (선택)
- PoC(Proof-of-Concept) 공개 여부 감지
- VulnCheck KEV 추가 소스 (선택)
- GitHub Advisory DB 패키지 정보 조회

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
| **Snort 3** | Community | O |
| **Suricata 5** | ET Open | O |
| **Suricata 7** | ET Open | O |
| **YARA** | Yara-Rules | O |

- 공개 룰 우선 사용, 없을 경우 AI가 생성
- AI 생성 룰은 정규식 기반 구문 검증 + 환각 방지 가드 적용
- 공식 룰 발견 시 기존 AI 룰을 대체하고 Slack으로 재알림

**알림 트리거 조건**
| 트리거 | 조건 | 설명 |
|--------|------|------|
| `신규 취약점` | 최초 발견된 CVE | DB에 없는 새 CVE |
| `KEV 등재` | CISA KEV 등록 | 기존 CVE가 KEV 등재 |
| `EPSS 급증` | EPSS >= 10% 이고 증가폭 > 5%p | 익스플로잇 가능성 급증 |
| `CVSS 위험도 상향` | CVSS 점수가 7.0 이상으로 상승 | 위험도 재평가 |

**자산 매칭 (assets.json)**
- 1차: CVE `affected` 필드의 구조화된 vendor/product 매칭
- 2차: description 텍스트 검색 (fallback)
- 와일드카드(`*`) 지원으로 전체 모니터링 가능

### Phase 2 - The Shield (IP Blacklist)

**위협 피드 수집 (8개 소스)**
| 피드 | 제공자 | 기본 점수 | 설명 |
|------|--------|----------|------|
| ET Compromised IPs | Emerging Threats | 60 | 침해된 IP |
| ET Block IPs | Emerging Threats | 70 | 차단 권고 IP |
| Spamhaus DROP | Spamhaus | 80 | 스팸/봇넷 CIDR |
| Feodo C2 | abuse.ch | 90 | C&C 서버 IP |
| Tor Exit Nodes (공식) | TorProject | 40 | Tor 출구 노드 |
| Tor Exit Nodes (dan.me.uk) | dan.me.uk | 40 | Tor 출구 노드 (이중화) |
| Blocklist.de | Blocklist.de | 50 | 공격 IP 통합 |
| ThreatFox C2/Malware | abuse.ch | 85 | C2/악성코드 IP |

**위험도 스코어링 (0~100점)**
```
최종 점수 = clamp(기본 점수 + 소스 보너스 + AbuseIPDB 조정
                  + InternetDB 조정 + 기간 가중치, 0, 100)

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
- 기간 기반 가중치 (연속 등장 일수):
    1일(신규): 0, 2일: +2, 3일: +4, ... 7일+: +12 (cap)
    (범위: 0 ~ +12)
```

**카테고리별 임계값 오버라이드**

카테고리에 따라 동일한 점수라도 위험 등급이 달라집니다:

| 카테고리 | Critical | High | Medium | 비고 |
|---------|----------|------|--------|------|
| 기본 (글로벌) | 80+ | 60+ | 40+ | 대부분의 카테고리 |
| botnet/C2/malware/exploit | 70+ | 50+ | 30+ | 즉각 차단 필요 |
| scanner/bruteforce/compromised | 75+ | 55+ | 35+ | 탐색/무차별 공격/침해 |
| tor | 90+ | 75+ | 50+ | 단독으로는 위험 낮음 |

**방화벽 관리 자동 권고**
- 매일 신규 고위험 IP TOP 10 알림 (방화벽 등록 대상)
- 피드 제거 감지: 어제 Critical/High → 오늘 모든 피드에서 사라진 IP → 차단 해제 대상
- 등급 하락 감지: 어제 Critical/High → 오늘 Medium/Low로 하락 → 차단 해제 검토

### Phase 3 - IOC Dashboard & External Feeds

**외부 IOC 피드 연동**
| 피드 | 유형 | 설명 |
|------|------|------|
| URLhaus | URL | abuse.ch 악성 URL (온라인 상태) |
| MalwareBazaar | Hash | abuse.ch 악성코드 SHA256 해시 |
| PhishTank | URL | 검증된 피싱 URL |
| OpenPhish | URL | 피싱 URL (PhishTank 실패 시 fallback) |

**IOC 통합 데이터 구조 (타입별 Lazy-Load)**

대시보드는 전체 IOC를 한 번에 로드하지 않고, 타입별 분리 파일로 필요할 때만 로드합니다:

| 파일 | 내용 |
|------|------|
| `ioc-meta.json` | 통계만 포함 (초기 로드용, 경량) |
| `ioc-cve.json` | CVE IOC 데이터 |
| `ioc-ip.json` | IP 블랙리스트 IOC 데이터 |
| `ioc-url.json` | 악성/피싱 URL IOC 데이터 |
| `ioc-hash.json` | 악성코드 해시 IOC 데이터 |
| `ioc-rule.json` | 탐지 룰 IOC 데이터 |

---

## Dashboard

GitHub Pages 기반 정적 대시보드로, Supabase 직접 호출 없이 `docs/data/*.json` 파일을 로드합니다.

| 페이지 | URL | 설명 |
|--------|-----|------|
| **IOC 통합** (메인) | `/` → `/ioc.html` | CVE, IP, URL, Hash, Rule 통합 뷰 |
| **CVE 대시보드** | `/cve.html` | CVE 심각도 분포, 벤더 TOP 10, 일별 추이 |
| **Blacklist IP** | `/blacklist.html` | IP 위험도 분포, 카테고리별 통계, 평판 회복 IP |

> `index.html`은 `ioc.html`로 자동 리디렉트됩니다.

---

## Project Structure

```
Argus-AI-Threat-Intelligence/
├── .github/workflows/
│   ├── argus.yml                     # Phase 1: CVE 스캔 워크플로우
│   └── blacklist.yml                 # Phase 2: 일일 IP 블랙리스트
│
├── src/
│   ├── main.py                       # Phase 1 메인 파이프라인
│   ├── collector.py                  # CVE 데이터 수집기 (스마트 필터링)
│   ├── analyzer.py                   # AI 분석 엔진 (Groq LLM)
│   ├── rule_manager.py               # 탐지 룰 수집/생성 관리
│   ├── notifier.py                   # Slack 알림 (CVE 알림, 공식 룰 알림)
│   ├── database.py                   # Supabase 인터페이스
│   ├── config.py                     # 설정 관리 (ArgusConfig 클래스)
│   ├── logger.py                     # 로깅
│   ├── rate_limiter.py               # Thread-Safe API 속도 제한 (v3.0)
│   ├── export_dashboard_data.py      # 대시보드 데이터 Export + 외부 IOC 수집
│   ├── test_argus.py                 # 통합 테스트 스크립트
│   │
│   └── blacklist_ip/                 # Phase 2: The Shield
│       ├── main.py                   # Shield 메인 파이프라인
│       ├── config.py                 # Shield 설정 (Settings dataclass)
│       ├── collector_tier1.py        # 피드 수집기 (8개 소스, ThreatFox JSON 파서 포함)
│       ├── enricher_tier2.py         # IP 보강 (AbuseIPDB, InternetDB, 분리 캡)
│       ├── scoring.py                # 위험도 스코어링 (카테고리별 임계값, 기간 가중치)
│       ├── delta.py                  # 일일 변동 계산
│       ├── store_supabase.py         # Supabase 저장소
│       ├── blacklist_ip_notifier.py  # Shield Slack 리포트
│       └── feeds.yml                 # 위협 피드 설정 (8개)
│
├── docs/                             # GitHub Pages 대시보드
│   ├── index.html                    # → ioc.html 리디렉트
│   ├── ioc.html                      # IOC 통합 대시보드 (메인)
│   ├── cve.html                      # CVE 대시보드
│   ├── blacklist.html                # IP 블랙리스트 대시보드
│   ├── css/style.css                 # 공통 스타일
│   ├── js/
│   │   ├── chart.js                  # 차트 유틸리티
│   │   ├── cve-dashboard.js          # CVE 대시보드 로직
│   │   ├── blacklist-dashboard.js    # IP 대시보드 로직
│   │   └── ioc-dashboard.js          # IOC 통합 대시보드 로직
│   └── data/                         # Export된 JSON 데이터 (자동 생성)
│       ├── cves.json
│       ├── blacklist.json
│       ├── stats.json
│       ├── ioc-meta.json             # IOC 통계 (경량)
│       ├── ioc-cve.json              # CVE IOC
│       ├── ioc-ip.json               # IP IOC
│       ├── ioc-url.json              # URL IOC (URLhaus, PhishTank)
│       ├── ioc-hash.json             # Hash IOC (MalwareBazaar)
│       └── ioc-rule.json             # Rule IOC
│
├── assets.json                       # 모니터링 대상 자산 정의
├── config_prod.json                  # 운영 환경 설정 참조 파일 (*)
├── config_dev.json                   # 개발 환경 설정 참조 파일 (*)
├── requirements.txt                  # Python 의존성
└── README.md
```

> **(\*) `config_prod.json` / `config_dev.json` 참고:**
> 현재 코드는 이 JSON 파일을 런타임에 로드하지 않습니다. Phase 1 설정은 `src/config.py`의 `ArgusConfig` 클래스 상수로, Phase 2 설정은 `src/blacklist_ip/config.py`의 `Settings` dataclass 기본값 + 환경변수로 관리됩니다.

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

> **`GITHUB_REPOSITORY`**: GitHub Actions 환경에서 자동 제공됩니다. 로컬 실행 시 미설정하면 GitHub Issue 생성만 스킵됩니다.

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
| `ABUSEIPDB_API_KEY` | AbuseIPDB IP 평판 조회 (Free tier: 1,000 조회/일) | AbuseIPDB enrichment 스킵, InternetDB만 사용 |
| `NVD_API_KEY` | NVD API (Phase 1: CVSS/CWE 상세 조회) | NVD 보강 없이 진행 |
| `VULNCHECK_API_KEY` | VulnCheck API (Phase 1: 확장 KEV 소스) | VulnCheck 소스 없이 진행 |
| `PHISHTANK_API_KEY` | PhishTank API (IOC 피싱 URL 수집) | API 키 없이 공개 엔드포인트 사용 (실패 시 OpenPhish fallback) |

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

| 설정 | 현재 값 | 설명 |
|------|---------|------|
| `MODEL_PHASE_0` | `gemma-3-27b-it` | 번역/요약용 모델 |
| `MODEL_PHASE_1` | `openai/gpt-oss-120b` | 심층 분석용 모델 |
| `max_workers` | 3 | 병렬 CVE 처리 워커 수 |
| `cve_fetch_hours` | 2 | 최근 N시간 내 CVE 수집 |
| `max_cves_per_run` | 50 | 한 실행당 최대 처리 CVE 수 |
| `max_rule_recheck` | 10 | 공식 룰 재확인 배치 크기 |
| `rule_check_interval_days` | 7 | 공식 룰 재확인 주기 |
| `bulk_commit_threshold` | 100 | 벌크 커밋 판단 기준 (파일 수) |

### Phase 1 Rate Limiter (`src/rate_limiter.py`)

Thread-Safe Rate Limiter v3.0이 10개 API 엔드포인트를 관리합니다:

| API | 한도 | 윈도우 | 최소 간격 |
|-----|------|--------|----------|
| `github` | 5,000/h | 3,600s | 0.5s |
| `github_search` | 8/min | 60s | 7.0s |
| `groq` | 15/min | 60s | 5.0s |
| `gemini` | 25/min | 60s | 2.5s |
| `epss` | 60/min | 60s | 1.0s |
| `kev` | 10/h | 3,600s | 2.0s |
| `nvd` | 40/30s | 30s | 1.0s |
| `vulncheck` | 40/min | 60s | 1.5s |
| `github_advisory` | 100/h | 3,600s | 0.5s |
| `ruleset_download` | 20/h | 3,600s | 2.0s |

- 사용률 80% 이상 시 속도 조절, 90% 이상 시 추가 대기
- 429 응답 시 `Retry-After` 헤더 파싱 후 자동 대기
- 실행 종료 시 API별 사용량 요약 출력

### Phase 2 설정 (`src/blacklist_ip/config.py` Settings dataclass)

| 설정 | 기본값 | 설명 |
|------|--------|------|
| `critical_threshold` | 80 | Critical 등급 기준 (글로벌) |
| `high_threshold` | 60 | High 등급 기준 (글로벌) |
| `medium_threshold` | 40 | Medium 등급 기준 (글로벌) |
| `source_bonus_step` | 5 | 추가 피드당 보너스 점수 |
| `source_bonus_cap` | 15 | 소스 보너스 최대값 |
| `max_enrich_count` | 500 | AbuseIPDB 최대 enrichment 대상 수 |
| `max_enrich_internetdb` | 5,000 | InternetDB 최대 enrichment 대상 수 |
| `enrich_workers` | 20 | InternetDB 병렬 워커 수 |
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

  - name: ThreatFox_IP
    url: "https://threatfox.abuse.ch/export/json/ip-port/recent/"
    format: "threatfox_json"
    base_score: 85
    category: "ThreatFox C2/Malware"
  # ... (8개 피드)
```

지원 포맷: `plain_ip`, `cidr`, `csv_simple`, `threatfox_json`

---

## Usage

### Phase 1 - CVE Scanner

**GitHub Actions (수동 실행):**

Actions 탭 > `Argus CVE Monitor` > Run workflow

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

수동 실행: Actions 탭 > `Argus Blacklist IP Monitor` > Run workflow

**로컬 실행:**
```bash
# 필수 (3개)
export SLACK_WEBHOOK_URL="..."
export SUPABASE_URL="..."
export SUPABASE_KEY="..."

# 선택 (없으면 AbuseIPDB enrichment 스킵)
export ABUSEIPDB_API_KEY="..."

python -m src.blacklist_ip.main --mode daily --tz Asia/Seoul
```

### Dashboard Data Export

대시보드 데이터는 Phase 1/2 워크플로우 실행 시 자동으로 export됩니다. 로컬에서 수동 실행:

```bash
export SUPABASE_URL="..."
export SUPABASE_KEY="..."

python src/export_dashboard_data.py
```

> Supabase 자격증명이 없으면 빈 샘플 데이터가 생성되어 대시보드가 에러 없이 로드됩니다.

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
  │ ...                         │
  └─────────────────────────────┘

  SNORT2 (Public Snort 2.9 ET Open)
  ┌─────────────────────────────┐
  │ alert tcp $EXTERNAL_NET ... │
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
  - 1.2.3.4 (어제 92점/Critical) - botnet
  - 5.6.7.8 (어제 78점/High) - scanner

  등급 하락 검토 (3건):
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
   ├─ AI 룰만 있는 CVE → 공식 룰 교체
   ├─ 룰 없는 고위험 CVE → 새 공식 룰 적용
   ├─ 배치 제한: 10건/실행
   └─ 쿨다운: 성공 7일 / 실패 1일 (빠른 재시도)

3. 데이터 수집 (스마트 필터링)
   ├─ CISA KEV + VulnCheck KEV
   ├─ 최근 2시간 CVE 수집 (GitHub Commits API)
   │   ├─ Phase 1: 커밋별 CVE ID 추출 + 벌크 감지
   │   ├─ Phase 2: 일반 커밋 CVE → 전부 처리
   │   └─ Phase 3: 벌크 커밋 CVE → 콘텐츠 해시 비교 → 스킵
   └─ EPSS 점수 배치 조회

4. 우선순위 정렬 + 배치 제한
   ├─ 신규 CVE 우선 처리
   └─ 최대 50건/실행

5. 병렬 CVE 처리 (3 workers)
   ├─ 추가 위협 인텔리전스 (NVD, PoC, Advisory)
   ├─ 자산 매칭 (affected → description fallback)
   ├─ 알림 트리거 판정 (신규/KEV/EPSS/CVSS)
   ├─ 한국어 번역 (Google Gemini)
   ├─ 고위험 시 GitHub Issue + AI 분석 + 룰 생성
   ├─ Slack 알림
   └─ Supabase DB 업데이트

6. Slack 배치 요약 전송

7. Rate Limit 사용 요약 출력
```

### Phase 2 실행 흐름

```
Step 1/5: Tier 1 피드 수집
   └─ 8개 위협 피드 다운로드 (개별 실패 허용, ThreatFox JSON 파서)

Step 2/5: Delta 계산
   ├─ 어제 vs 오늘 indicator 세트 비교 (Supabase 기반)
   ├─ 신규/제거 IP 식별
   └─ 어제 고위험 중 제거된 IP 식별

Step 3/5: Tier 2 Enrichment
   ├─ 신규 IP만 대상 (CIDR 제외)
   ├─ base_score 기준 우선순위 정렬 (높은 점수 우선)
   ├─ AbuseIPDB 최대 500개 (분리 캡), 순차 조회 (1초 간격)
   ├─ InternetDB 최대 5,000개 (분리 캡), 병렬 조회 (20 workers)
   └─ 캐시 활용 (AbuseIPDB 24h, InternetDB 72h TTL)

Step 4/5: Scoring
   ├─ 기본 점수 + 소스 보너스 + AbuseIPDB + InternetDB + 기간 가중치
   ├─ 카테고리별 임계값 오버라이드 적용
   └─ 등급 하락 IP 감지 (어제 고위험 → 오늘 중/저위험)

Step 5/5: 저장 + 리포트
   ├─ Supabase에 일별 스냅샷 저장
   └─ Slack 일일 리포트 전송 (방화벽 관리 권고 포함)
```

### Dashboard Export 흐름

```
Step 1/5: CVE 데이터 export (Supabase → cves.json, 페이지네이션)
Step 2/5: 블랙리스트 IP export (Supabase → blacklist.json, 평판 회복 IP 포함)
Step 3/5: 외부 IOC 피드 수집 (URLhaus → MalwareBazaar → PhishTank/OpenPhish)
Step 4/5: IOC 통합 데이터 export (타입별 분리 파일 생성)
Step 5/5: 통계 집계 (stats.json)
```

---

## Supabase Schema

### Phase 1 테이블

```sql
-- CVE 이력
CREATE TABLE cves (
  id TEXT PRIMARY KEY,
  cvss_score REAL,
  epss_score REAL,
  is_kev BOOLEAN,
  has_official_rules BOOLEAN DEFAULT FALSE,
  last_alert_at TIMESTAMPTZ,
  last_alert_state JSONB,
  rules_snapshot JSONB,
  report_url TEXT,
  last_rule_check_at TIMESTAMPTZ,
  content_hash TEXT,
  updated_at TIMESTAMPTZ
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
