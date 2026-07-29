<div align="center">

# Argus

**매일 반복하던 취약점 확인 업무를 자동화한 CVE 위협 인텔리전스 파이프라인**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![GitHub Actions](https://img.shields.io/badge/Runtime-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)](.github/workflows/argus.yml)
[![Dashboard](https://img.shields.io/badge/Dashboard-GitHub%20Pages-222?logo=github&logoColor=white)](https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/cve.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-3fb950)](LICENSE)
[![Infra Cost](https://img.shields.io/badge/Infra-Free%20Tier-3fb950)](#운영-비용)

### 🔗 [**라이브 대시보드 바로가기**](https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/cve.html)

`https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/cve.html`

</div>

![Argus Dashboard](docs/assets/dashboard.png)

---

## 왜 만들었나

보안 업무를 하면서 매일 같은 일을 반복했습니다.

새로 공개된 CVE를 확인하려고 **NVD**를 열고, 실제로 악용되고 있는지 보려고 **CISA KEV**를 확인하고,
악용 가능성 점수를 보려고 **EPSS**를 찾고, 공격 코드가 돌아다니는지 **ExploitDB·Metasploit**을 뒤지고,
영향받는 패키지를 보려고 **GitHub Advisory**를 열고, 탐지할 방법이 있는지 **SigmaHQ**를 검색합니다.

여기까지 하고 나서야 비로소 판단할 수 있습니다 — *"이게 우리 자산에 해당하나? 지금 대응해야 하나?"*

문제는 이 과정을 **CVE 한 건마다** 반복해야 한다는 것이었습니다. 하루에 쏟아지는 신규 CVE는 수백에서
수천 건인데, 그중 정작 오늘 손대야 할 건 몇 건뿐입니다. **그 몇 건을 찾기 위해 나머지 전부를 사람이
훑어야 하는 구조**가 비효율적이라고 느꼈습니다.

그래서 이 순회를 자동화했습니다. 흩어진 출처를 기계가 모으고, 실제 악용 신호로 걸러내고,
우리 자산에 해당하는지 대조한 뒤, **사람은 판단이 필요한 것만 받아보는** 것이 목표였습니다.

> 저는 개발자가 아닌 보안 실무자라, 구현은 Claude를 활용한 **바이브 코딩**으로 진행했습니다.
> 코드를 직접 짜는 대신 *무엇이 필요하고 왜 그래야 하는지*를 정의하는 데 집중했습니다.

---

## 무엇이 달라졌나

| | 자동화 전 (수작업) | 자동화 후 (Argus) |
| :--- | :--- | :--- |
| **정보 수집** | 6~7개 사이트를 CVE마다 순회 | 한 번의 실행으로 전부 수집·병합 |
| **위험 판단** | CVSS 점수만 보고 판단 | KEV·EPSS·Metasploit·SSVC를 종합해 3단계 자동 분류 |
| **자산 대조** | 벤더/제품명을 눈으로 대조 | `assets.json` 등록 자산과 자동 매칭 |
| **분석·정리** | 영문 원문을 읽고 직접 정리 | 근본 원인·공격 시나리오·대응 방안을 한국어 리포트로 자동 생성 |
| **놓침 방지** | 바쁘면 그냥 지나감 | 워터마크 기반 이어받기로 실행이 끊겨도 재수집 |
| **사후 추적** | 한 번 보고 끝 | 저위험이던 CVE가 악용되기 시작하면 자동 재알림 |

급한 건은 Slack으로 즉시, 나머지는 대시보드에 쌓이고, 주간 요약이 GitHub Issue로 발행됩니다.
**확인하러 돌아다니던 시간이 알림을 읽는 시간으로 바뀌었습니다.**

---

## 실제 화면

**▶︎ [라이브 대시보드에서 직접 확인](https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/cve.html)** — 실제 운영 중인 데이터입니다.

심각도 · 위협 신호(악용 중 · 무기화 · PoC · 공개 룰) · 벤더 · 제품 · 기간(월/일)으로 좁혀 볼 수 있고,
필터링한 결과를 CSV · JSON · **STIX 2.1** 로 내보낼 수 있습니다.

<div align="center">

![CVE 상세](docs/assets/detail.png)

<sub>CVE를 클릭하면 위협 신호·영향 자산·공개 탐지 룰을 한 화면에서 확인하고, AI 상세 분석 리포트로 이동합니다.</sub>

</div>

---

## 동작 방식

![Architecture](docs/assets/architecture.png)

취약점 관리의 출발점인 **"무엇을 지킬 것인가(자산 식별)"** 부터 수집·분류·분석·전달까지,
실무에서 밟던 순서를 그대로 자동화했습니다.

**위험도는 3단계로 나뉩니다.** 실무에서 CVSS 7점대는 하루 수백 건이라, 점수만으로는 걸러지지 않기 때문입니다.

| 단계 | 조건 | 처리 |
| :--- | :--- | :--- |
| **Critical** | KEV 등재 · Metasploit 무기화 · SSVC 악용 진행형 · EPSS 급증 · CVSS 9+ | GitHub Issue 리포트 + Slack 즉시 알림 |
| **High** | CVSS 7~8.9 (다른 악용 신호 없음) | 대시보드 추적 + Slack 요약에 건수 집계 |
| **Low** | 그 외 | 등록 자산이면 추적, 아니면 중복 방지용 최소 기록만 |

등록한 자산에 해당하면 **High도 Critical과 동일하게** 리포트가 발행됩니다 — 실제 대응 대상이기 때문입니다.

---

## 핵심 기능

| | 기능 | 설명 |
|:--:|---|---|
| 🎯 | **자산 기준 위험도 티어링** | 등록 자산은 저위험까지 추적, 미등록(전체 감시)은 고위험만 수신해 알림 노이즈 차단 |
| 🧠 | **AI 심층 분석** | 근본 원인 · MITRE ATT&CK 공격 시나리오 · 공격 벡터 해석 · 대응 방안을 한국어로 생성 |
| 🚨 | **실제 악용 신호 우선** | CISA KEV · EPSS · Metasploit · ExploitDB · CISA SSVC를 종합해 "무기화·악용 진행형"을 최상위 노출 |
| 🔎 | **공개 탐지 룰 매칭** | SigmaHQ · ET Open · Yara-Rules에서 해당 CVE의 검증된 룰을 찾아 리포트에 첨부(출처·라이선스 보존) |
| 📈 | **에스컬레이션 재알림** | 저위험이던 CVE가 KEV 등재·EPSS 급등으로 고위험 전환되면 자동 재알림 |
| 🔁 | **무누락 수집** | 워터마크 기반 이어받기 + 소프트 데드라인으로 실행이 중단돼도 다음 회차가 빈틈 없이 재수집 |
| 📅 | **주간 요약 리포트** | 직전 주 탐지 결과(신규 · KEV · 무기화 · 영향 제품 TOP)를 GitHub Issue로 자동 발행 |
| 📊 | **웹 대시보드 & Export** | 위협 중심 다크 대시보드 + CSV · JSON · **STIX 2.1** 내보내기 |

---

## AI 스택

두 공급자를 조합해 한쪽 장애·한도 소진에도 분석이 멈추지 않도록 다중화했습니다.

| 용도 | 모델 | 공급자 | 비고 |
|---|---|---|---|
| **심층 분석 (주)** | `gpt-oss-120b` → `qwen3.6-27b` | Groq | 추론형. 앞 모델의 일일 한도 소진 시 다음 모델로 캐스케이드 |
| **심층 분석 (비상)** | `gemini-3.1-flash-lite` | Google AI Studio | Groq 전 모델 소진·장애 시 폴백 → 알림 지연 방지 |
| **한국어 번역** | `gemma-4-31b` | Google AI Studio | CVE 제목·설명 요약 (분석과 예산 분리) |

> AI API 키(Groq · Google AI Studio)는 **이용자가 직접 발급**해 GitHub Secrets에 등록합니다.
> 무료 티어 한도 내 사용을 전제로 설계했으며, 각 AI 서비스의 이용약관은 이용자 책임하에 준수해야 합니다.

---

## 데이터 출처 & 라이선스

Argus가 사용하는 모든 외부 데이터와 그 라이선스입니다. **재게시 시 원 출처·author·라이선스 고지를 보존**하며,
저작권이 제출자에게 있는 PoC·익스플로잇 원문(ExploitDB·nomi-sec 등)은 **재게시하지 않고 링크만** 표시합니다.

| 데이터 | 용도 | 라이선스 / 취급 방침 |
|---|---|---|
| **CVE Program** (cvelistV5) | CVE 원본 레코드 | CC0 1.0 (퍼블릭 도메인) |
| **CISA KEV** | 실제 악용 확인 목록 | U.S. Government Work (퍼블릭 도메인) |
| **CISA vulnrichment** (SSVC) | 악용 상태·CVSS·CWE 보강 | CC0 1.0 |
| **NVD** (NIST) | CVSS·CWE·CPE 보충 | U.S. Government Work (퍼블릭 도메인) |
| **EPSS** (FIRST.org) | 악용 확률 점수 | 무료 공개 · **출처 표기**(대시보드/리포트에 FIRST.org 명시) |
| **GitHub Advisory** | 영향 패키지 정보 | GitHub ToS |
| **PoC** (nomi-sec / trickest) | PoC 공개 신호 | 개별 PoC 저작권=제출자 → **원문 미게시, 링크만** |
| **ExploitDB** | 공개 익스플로잇 신호 | 개별 PoC 저작권=제출자 → **원문 미게시, 링크만** |
| **Metasploit** metadata | 무기화 신호 | BSD-3-Clause (출처: Rapid7 표기) |
| **SigmaHQ** | 공개 탐지 룰 | DRL 1.1 (author 표기 보존) |
| **ET Open** (Emerging Threats) | 공개 네트워크 룰 | MIT (레거시 SID 1–3464는 GPLv2) |
| **Snort Community** | 공개 네트워크 룰 | GPLv2 |
| **Yara-Rules** | 공개 YARA 룰 | GPL-2.0 |

> 📌 **기업/영리 목적 활용 시 유의**
> 이 저장소의 **코드**는 아래 MIT 라이선스로 자유롭게 사용할 수 있으나, 위 **외부 데이터·룰**은 각자의
> 라이선스(GPL·DRL·CC0 등)를 따릅니다. 룰을 자사 제품·서비스에 재배포·통합할 경우 해당 라이선스(특히
> GPL 계열의 copyleft, DRL의 author 표기 의무)를 별도로 확인·준수해야 합니다.

---

## 직접 써보기

<details>
<summary><b>설정 펼치기</b></summary>

### 1. 감시할 자산 등록 (`assets.json`)

가장 먼저 할 일은 **무엇을 지킬지 정하는 것**입니다. `active_rules`에 벤더/제품을 추가합니다.
무엇이 설치돼 있는지 모호하면 `syft` 같은 SBOM 도구로 인벤토리를 먼저 파악한 뒤 등록하면 좋습니다.

```json
{
  "active_rules": [
    { "vendor": "microsoft", "product": "exchange_server" },
    { "vendor": "*",         "product": "nginx" },
    { "vendor": "fortinet",  "product": "*" }
  ]
}
```

| 표기 | 의미 | 쓰는 상황 |
|---|---|---|
| `vendor` / `product` | 특정 벤더의 특정 제품 | 정확히 아는 자산 |
| `*` / `product` | **제품만** 감시 (벤더 무관) | 벤더 표기를 모르거나 여러 벤더가 배포하는 제품 |
| `vendor` / `*` | **특정 벤더**의 모든 제품 | 그 벤더 제품을 폭넓게 쓰는 경우 |
| `*` / `*` | 전체 감시 | 자산 확정 전 — 고위험만 수신 |

> 벤더/제품명은 대소문자와 `_`·공백 표기 차이를 흡수해 매칭합니다 (`exchange_server` ↔ `Exchange Server`).
> CVE 레코드에 벤더 정보가 없으면 NVD CPE와 설명 텍스트로 보완합니다.

### 2. GitHub Secrets 등록

| Secret | 발급처 | 필수 |
|---|---|:--:|
| `GROQ_API_KEY` | [console.groq.com](https://console.groq.com) | ✅ |
| `GEMINI_API_KEY` | [aistudio.google.com](https://aistudio.google.com) | ✅ |
| `SUPABASE_URL` · `SUPABASE_KEY` | [supabase.com](https://supabase.com) | ✅ |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook | ✅ |
| `GH_TOKEN` | GitHub PAT (issues:write) | ✅ |
| `NVD_API_KEY` | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | 선택 (없으면 조회 속도 제한) |
| `VULNCHECK_API_KEY` | [vulncheck.com](https://vulncheck.com) | 선택 (없으면 건너뜀) |

### 3. 실행

- **Actions** 탭에서 워크플로를 활성화하면 정기 실행됩니다. (`.github/workflows/argus.yml`)
- **Settings → Pages** 를 `docs/` 로 설정하면 대시보드가 게시됩니다.

</details>

---

## 운영 비용

전 구성요소가 **무료 티어** 안에서 동작하도록 설계했습니다 — GitHub Actions(실행) · GitHub Pages(대시보드) ·
Supabase(DB) · Groq / Google AI Studio(AI). 추가 서버나 유료 구독 없이 개인·소규모 팀이 운영할 수 있습니다.

무료 한도를 지키기 위해 상세 분석 리포트는 DB가 아닌 **GitHub Issue**에 보존하고, DB에는 대시보드 표시와
재알림 판단에 필요한 최소 정보만 저장합니다. 외부 API 호출은 한도 관리자가 선제적으로 조절합니다.

---

> ⚠️ 이 도구가 생성·표시하는 AI 분석 결과와 위험도 분류는 **참고용**입니다.
> 실제 대응·패치 결정은 각 조직의 환경과 공식 벤더 권고를 함께 검토해 판단하시기 바랍니다.

---

## License

Code is licensed under the **[MIT License](LICENSE)** © 2026 LEEKIYOON-SEC.
외부 데이터 및 탐지 룰은 위 [데이터 출처 & 라이선스](#데이터-출처--라이선스) 표의 각 라이선스를 따릅니다.
