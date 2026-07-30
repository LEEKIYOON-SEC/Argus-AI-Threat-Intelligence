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

보안 업무를 하면서 매일 아침 하던 일이 있습니다. **어제 공개된 CVE 중 우리가 손대야 할 게 있는지 확인하는 일**입니다.

순서는 늘 같았습니다.

먼저 **우리가 무엇을 쓰는지** 알아야 합니다. 그래서 `syft`로 Linux·Windows 서버의 SBOM을 떠서 실제 설치된
벤더·제품 목록을 만들어 두었습니다. 이 목록이 없으면 CVE를 봐도 판단할 근거가 없습니다.

그 다음부터가 매일 반복되는 부분입니다. 새로 공개된 CVE를 하나씩 열어 **영향 받는 벤더·제품이 그 목록에
있는지 대조합니다.** 대부분은 여기서 끝납니다 — 우리와 무관하니까요. 남는 소수만 실제로 악용되고 있는지
(**CISA KEV**), 악용될 확률이 얼마인지(**EPSS**), 공격 코드가 이미 돌아다니는지(**ExploitDB · Metasploit**),
악용 진행 상태가 어떤지(**CISA SSVC**)를 확인합니다. 그리고 마지막으로 패치·완화 방법과 **탐지할 룰이
공개돼 있는지**(**SigmaHQ · ET Open · Snort Community · Yara-Rules**)를 찾습니다.

문제는 판단의 어려움이 아니라 **횟수**였습니다. 하루에 공개되는 신규 CVE는 수백에서 수천 건인데, 실제로 우리
자산에 걸리는 건 그중 극히 일부입니다. 즉 **업무 시간의 대부분이 "우리와 상관없음"을 확인하는 데 쓰였습니다.**
영문 원문을 읽고, 벤더마다 표기가 다른 제품명을 눈으로 맞춰보고, 사이트를 순회하면서요. 바쁜 날은 이 대조를
건너뛰게 되는데, 건너뛴 날에 하필 KEV에 올라간 건이 섞여 있으면 그게 사고가 됩니다.

기계가 훨씬 잘할 수 있는 일이었습니다. 사람이 필요한 건 대조가 아니라, 대조를 통과한 **그 몇 건을 어떻게
처리할지 결정하는 일**이니까요. 그래서 이 순서를 그대로 자동화했습니다.

```
① 자산 목록 확보   syft로 Linux·Windows SBOM → 실제 설치된 벤더·제품
       │
② 자산 대조        신규 CVE의 영향 벤더·제품이 그 목록에 있는가?   ← 1차 필터, 대부분 여기서 종료
       │
③ 위험도 판단      통과분만 CISA KEV · EPSS · ExploitDB · Metasploit · SSVC로 실제 악용 신호 확인
       │
④ 대응 근거 확보   패치·완화 방안 + 공개 탐지 룰 (SigmaHQ · ET Open · Snort Community · Yara-Rules)
       │
⑤ 전달             급한 건은 Slack 즉시 · 상세 리포트는 GitHub Issue · 나머지는 대시보드에서 추적
```

①은 처음 한 번(그리고 자산이 바뀔 때) 하면 되고, **②~⑤는 GitHub Actions가 매시간 대신 수행합니다.**
확인하러 돌아다니던 시간이 알림을 읽는 시간으로 바뀌었습니다.

> 저는 개발자가 아닌 보안 실무자입니다. 구현은 Claude 바이브 코딩을 이용해 자동화했고,
> 제가 집중한 부분은 *무엇을 어떤 순서로 걸러야 하는지* 정의하는 쪽이었습니다.

---

## 자산 목록은 SBOM에서 뽑았습니다

추측으로 자산을 적으면 대조 자체가 의미 없어집니다. 그래서 **실제로 설치돼 있는 것만** 목록에 올렸습니다.
Linux와 Windows 모두 `syft` 하나로 통일했습니다.

```bash
# Linux 서버
syft dir:/ -o cyclonedx-json > sbom-linux.json

# Windows 서버
syft dir:C:\ -o cyclonedx-json > sbom-windows.json
```

SBOM에서 `supplier`(벤더)와 `name`(제품)을 추출해 `assets.json`의 `active_rules`로 등록하면, 이후 수집되는
모든 CVE가 이 목록과 대조됩니다.

실무에서 걸린 부분은 **표기 불일치**였습니다. SBOM은 `Microsoft Corporation`, CVE 레코드는 `microsoft`,
제품명은 `exchange_server` ↔ `Exchange Server`처럼 제각각입니다. 그래서 대소문자·`_`·공백 차이는 코드에서
흡수하고, 벤더 표기를 신뢰할 수 없을 때는 `*`로 **제품만** 지정할 수 있게 했습니다.

---

## 무엇이 달라졌나

| | 자동화 전 (수작업) | 자동화 후 (Argus) |
| :--- | :--- | :--- |
| **자산 대조** | CVE마다 벤더·제품명을 눈으로 확인 | SBOM 기반 자산 목록과 자동 매칭 — 해당 없으면 그 자리에서 종료 |
| **정보 수집** | 6~7개 사이트를 CVE마다 순회 | 대조를 통과한 건만 한 번의 실행으로 수집·병합 |
| **위험 판단** | CVSS 점수만 보고 판단 | KEV·EPSS·Metasploit·SSVC를 종합해 3단계 자동 분류 |
| **대응 근거** | 영문 원문을 읽고 정리 + 룰 직접 검색 | 근본 원인·공격 시나리오·대응 방안 한국어 리포트 + 공개 탐지 룰 자동 첨부 |
| **놓침 방지** | 바쁘면 그냥 지나감 | 워터마크 기반 이어받기로 실행이 끊겨도 다음 회차가 재수집 |
| **사후 추적** | 한 번 보고 끝 | 저위험이던 CVE가 악용되기 시작하면 자동 재알림 |

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

## 자동 발행되는 상세 리포트

즉시 대응이 필요한 건과 **등록 자산에 해당하는 건**은 GitHub Issue로 상세 리포트가 발행됩니다.
아래는 실제로 발행된 이슈를 그대로 캡처한 것입니다.

![자동 발행 리포트 예시](docs/assets/report.png)

<sub>실제 발행 이슈 — Fortinet FortiOS (CISA KEV 등재 · SSVC 악용 진행형).
대응 우선순위 배너 → 위험도 배지(CVSS · EPSS · KEV · SSVC) → 위협 신호 → 한국어 개요(영문 원문 접이식)
→ 영향 받는 자산(벤더/제품/버전) → AI 심층 분석(근본 원인 · 공격 벡터 해석 · MITRE ATT&CK 시나리오 · 비즈니스 영향)
→ 권고 대응 방안 → 조치 체크리스트 → 공개 탐지 룰 → 참고 자료 → 데이터 출처 고지 순으로 구성됩니다.</sub>

---

## 동작 방식

![Architecture](docs/assets/architecture.png)

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
| 🔎 | **공개 탐지 룰 매칭** | SigmaHQ · ET Open · Snort Community · Yara-Rules에서 해당 CVE의 검증된 룰을 찾아 리포트에 첨부(출처·라이선스 보존) |
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

가장 먼저 할 일은 **무엇을 지킬지 정하는 것**입니다. 위 [SBOM 단계](#자산-목록은-sbom에서-뽑았습니다)로 파악한
벤더/제품을 `active_rules`에 추가합니다.

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
