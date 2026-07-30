<div align="center">

# Argus

**매일 반복하던 취약점 확인 업무를 자동화한 CVE 위협 인텔리전스 파이프라인**

SBOM으로 만든 자산 목록에 걸리지 않는 CVE는 앞단에서 걸러내고, 남은 소수만 보안 담당자가 판단합니다.

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

보안 담당자로 일하면서 매일 아침 하던 일이 있습니다. 어제 공개된 CVE 중에 우리가 손대야 할 게 있는지
확인하는 일입니다.

이걸 하려면 우리가 뭘 쓰고 있는지부터 알아야 합니다. 그래서 `syft`로 Linux·Windows 서버의 SBOM을 떠서
실제 설치된 벤더·제품 목록을 먼저 만들어 뒀습니다.

그 다음은 매일 똑같습니다. 새로 올라온 CVE를 열어서 영향 받는 벤더·제품이 그 목록에 있는지 봅니다.
없으면 거기서 끝입니다. 있는 것만 실제로 악용되고 있는지(CISA KEV), 악용될 확률이 얼마인지(EPSS),
공격 코드가 이미 공개됐는지(ExploitDB·Metasploit), 악용 상태가 어떤지(CISA SSVC)를 확인합니다.
그리고 패치 방법과 탐지 룰이 공개돼 있는지(SigmaHQ·ET Open·Snort Community·Yara-Rules)를 찾습니다.

어려운 판단은 아닙니다. 문제는 양입니다. 하루에 새로 공개되는 CVE가 수백에서 수천 건인데, 그중 우리 자산에
걸리는 건 손에 꼽습니다. 결국 하루 대부분을 "우리랑 상관없음"을 확인하는 데 씁니다. 영문 원문 읽고,
벤더마다 다르게 쓰는 제품명 눈으로 맞춰보고, 사이트 여기저기 들어가면서요. 바쁘면 건너뛰게 되는데,
건너뛴 날에 KEV 등재된 게 섞여 있으면 그게 사고가 됩니다.

건너뛰면 무엇이 위험한지는 분명합니다. 공개된 취약점은 하루만 지나도 N-day가 되고, PoC가 돌기 시작하면
그다음은 시간 문제입니다. CISA KEV는 등재 기준 자체가 "조치 방법이 이미 있는 취약점"이어서, 이 목록에
오른 건은 곧 **패치가 나와 있는데도 실제로 악용됐다**는 뜻입니다. 국내에서도 같은 일이 반복됩니다.

| 시점 | 무슨 일이 있었나 | 결과 |
| :--- | :--- | :--- |
| 2017-10 | 오라클이 WebLogic 원격코드실행 취약점(`CVE-2017-10271`) 패치 배포 | 이후 CISA KEV 등재(2022-02) · 랜섬웨어 악용 확인 |
| 2024-11 | 국내 대학 2곳, 같은 패치를 **6년 이상** 적용하지 않은 상태로 침해 | 개인정보보호위원회 과징금 1억 9,300만원 · 4,280만원 |
| 2025-08 | 국내 카드사, 결제 서버 **48대 중 1대**에 같은 패치가 누락된 상태로 침해 | 고객 297만 명 정보 유출(카드번호·CVC 등 민감정보 28만 명) |

<sub>공개 8년이 지난 취약점 하나가 국내에서 계속 반복됐습니다. 출처: 개인정보보호위원회 처분(2024-11-14),
금융당국 합동조사 결과 및 관련 보도(2025), CISA KEV 카탈로그(2026-07-29). 피해 기관은 업종으로만 적었습니다.</sub>

마지막 사고에서 문제가 된 건 48대 중 1대였습니다. 무엇이 어디에 설치돼 있는지 목록이 없으면, 이런 누락은
눈으로 찾을 수 없습니다.

제로데이는 이 파이프라인의 범위가 아닙니다. 패치도 정보도 없는 시점의 공격은 행위 기반 탐지 장비가 맡을
영역이고, Argus는 공개된 다음부터 조치 전까지의 구간을 맡습니다.

금융권에서는 이 구간이 규정 의무이기도 합니다. 전자금융감독규정 제15조 제1항 제2호는 "시스템프로그램 등의
긴급하고 중요한 보정(patch)사항에 대하여 즉시 보정작업 실시"를 요구합니다. 다만 **무엇이 긴급하고 중요한지는
규정이 정해주지 않습니다.** 그 판정을 무엇으로 하느냐가 실무이고, Argus는 그 근거를 자동으로 만듭니다.

보안 담당자가 할 일은 대조가 아니라, 대조를 통과한 몇 건을 어떻게 처리할지 정하는 쪽입니다.
그래서 이 순서를 그대로 자동화했고, 빠르게 만들려고 Claude 바이브 코딩을 이용했습니다.

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

①은 자산이 바뀔 때만 하면 되고, ②~⑤는 GitHub Actions가 매시간 돌립니다. 이제 수백 건을 직접 훑지
않습니다. 자산에 걸린 몇 건만 확인하면 되고, 바빠서 건너뛰는 날도 없어졌습니다. 남는 시간은 실제로
대응해야 하는 취약점에 씁니다.

---

## 자산 목록은 SBOM으로 만들었습니다

추측으로 적으면 대조가 의미 없어서, 서버에서 `syft`로 실제 설치된 목록을 뽑았습니다.

```bash
# Linux
sudo syft / -o cyclonedx-json=sbom-linux.json
```

```powershell
# Windows
syft C:\ -o cyclonedx-json=sbom-windows.json
```

여기서 나온 벤더와 제품명을 `assets.json`에 등록해 쓰고 있습니다. 표기가 서로 달라서
(`Microsoft Corporation` / `microsoft`, `Exchange Server` / `exchange_server`) 대소문자와 `_`·공백 차이는
코드에서 흡수하고, 벤더를 특정하기 어려우면 `*`로 제품만 지정합니다.

---

## 무엇이 달라졌나

| | 기존 업무 (담당자가 직접) | Argus |
| :--- | :--- | :--- |
| **자산 대조** | CVE마다 벤더·제품명을 눈으로 확인 | SBOM 기반 자산 목록과 자동 매칭, 해당 없으면 그 자리에서 종료 |
| **정보 수집** | 6~7개 사이트를 CVE마다 순회 | 대조를 통과한 건만 한 번의 실행으로 수집·병합 |
| **위험 판단** | CVSS 점수만 보고 판단 | KEV·EPSS·Metasploit·SSVC를 종합해 3단계 자동 분류 |
| **대응 근거** | 영문 원문을 읽고 정리 + 룰 직접 검색 | 근본 원인·공격 시나리오·대응 방안 한국어 리포트 + 공개 탐지 룰 자동 첨부 |
| **놓침 방지** | 바쁘면 그냥 지나감 | 워터마크 기반 이어받기로 실행이 끊겨도 다음 회차가 재수집 |
| **사후 추적** | 한 번 보고 끝 | 저위험이던 CVE가 악용되기 시작하면 자동 재알림 |

---

## 실제 화면

실제 악용 여부, 자산 영향, 탐지 룰 존재 여부를 한눈에 봅니다. 걸러낸 결과는 CSV·JSON·STIX 2.1로
내보냅니다.

CVSS 벡터는 점수 하나로 뭉쳐 두지 않고 항목별로 쪼개, **위험을 높이는 조건만 빨갛게** 칠했습니다
(아래 화면의 `공격 벡터` 줄 — 네트워크 접근·권한 불필요는 빨강, 높은 공격 복잡도·무결성 영향 없음은 회색).
같은 5.3점이어도 어디가 문제인지가 바로 드러납니다.

<div align="center">

![CVE 상세](docs/assets/detail.png)

<sub>CVE를 클릭하면 위협 신호·영향 자산·공개 탐지 룰을 한 화면에서 확인하고, AI 상세 분석 리포트로 이동합니다.</sub>

</div>

---

## 자동 발행되는 상세 리포트

즉시 대응이 필요한 건과 등록 자산에 걸린 건은 GitHub Issue로 상세 리포트가 올라옵니다.
아래는 실제로 발행된 이슈를 그대로 캡처한 것입니다.

조치 체크리스트를 채우고 이슈를 닫으면 그대로 조치 이력이 됩니다. 무엇을 언제 왜 조치했는지가 한 곳에
모여 있어, 사후 점검이나 감사 대응 때 따로 정리할 자료를 만들지 않아도 됩니다.

![자동 발행 리포트 예시](docs/assets/report.png)

<sub>실제 발행 이슈 — Fortinet FortiOS (CISA KEV 등재 · SSVC 악용 진행형).
대응 우선순위 배너 → 위험도 배지(CVSS · EPSS · KEV · SSVC) → 위협 신호 → 한국어 개요(영문 원문 접이식)
→ 영향 받는 자산(벤더/제품/버전) → AI 심층 분석(근본 원인 · 공격 벡터 해석 · MITRE ATT&CK 시나리오 · 비즈니스 영향)
→ 권고 대응 방안 → 조치 체크리스트 → 공개 탐지 룰 → 참고 자료 → 데이터 출처 고지 순으로 구성됩니다.</sub>

---

## 동작 방식

![Architecture](docs/assets/architecture.png)

하루치가 실제로 이렇게 줄어듭니다.

```
신규 CVE               1,800건
      │  ① 자산 대조 (SBOM 목록)
      ▼
자산에 영향                12건   ← 담당자가 볼 대상
      │  ② 악용 신호 · 심각도
      ▼
즉시 대응(Critical)         2건   → Slack 알림 + GitHub Issue 리포트
```

<sub>자산 목록을 공개 저장소에 올릴 수 없어 라이브 인스턴스는 전체 감시(`*/*`)로 돌리고 있습니다.
위 감소 폭은 자산을 등록했을 때를 가정한 예시입니다. 유입량(하루 수백~수천 건)은 실제 수집 기준입니다.</sub>

위험도는 3단계로 나눕니다. CVSS 7점대가 하루 수백 건씩 나오니 점수만으로는 걸러지지 않습니다.

| 단계 | 조건 | 처리 |
| :--- | :--- | :--- |
| **Critical** | KEV 등재 · Metasploit 무기화 · SSVC 악용 진행형 · EPSS 급증 · CVSS 9+ | GitHub Issue 리포트 + Slack 즉시 알림 |
| **High** | CVSS 7~8.9 (다른 악용 신호 없음) | 대시보드 추적 + Slack 요약에 건수 집계 |
| **Low** | 그 외 | 등록 자산이면 추적, 아니면 중복 방지용 최소 기록만 |

등록한 자산에 걸리면 High도 Critical과 똑같이 리포트를 발행합니다. 실제로 대응해야 하는 건이니까요.

---

## 핵심 기능

| | 기능 | 설명 |
|:--:|---|---|
| 🎯 | **자산 기준 1차 필터** | SBOM 목록에 걸린 것만 통과. 등록 자산은 저위험까지 추적, 미등록(전체 감시)은 고위험만 수신 |
| 🚨 | **실제 악용 신호 우선** | CISA KEV · EPSS · Metasploit · ExploitDB · CISA SSVC를 종합해 "무기화·악용 진행형"을 최상위 노출 |
| 🧠 | **AI 심층 분석** | 필터를 통과한 건만 근본 원인 · MITRE ATT&CK 공격 시나리오 · 공격 벡터 해석 · 대응 방안을 한국어로 생성 |
| 🔎 | **공개 탐지 룰 매칭** | SigmaHQ · ET Open · Snort Community · Yara-Rules에서 해당 CVE의 검증된 룰을 찾아 리포트에 첨부(출처·라이선스 보존) |
| 📈 | **에스컬레이션 재알림** | 저위험이던 CVE가 KEV 등재·EPSS 급등으로 고위험 전환되면 자동 재알림 |
| 🔁 | **무누락 수집** | 워터마크 기반 이어받기 + 소프트 데드라인으로 실행이 중단돼도 다음 회차가 빈틈 없이 재수집 |
| 📅 | **주간 요약 리포트** | 직전 주 탐지 결과(신규 · KEV · 무기화 · 영향 제품 TOP)를 GitHub Issue로 자동 발행 |
| 📊 | **웹 대시보드 & Export** | 위협 중심 다크 대시보드 + CSV · JSON · STIX 2.1 내보내기 |

---

## AI 스택

추론 품질이 좋은 모델을 먼저 쓰고, 일일 한도가 차거나 장애가 나면 다음 모델로 넘깁니다.
분석이 멈추지 않게 공급자도 두 곳을 섞었습니다.

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

가장 먼저 할 일은 무엇을 지킬지 정하는 것입니다. 위 [SBOM 단계](#자산-목록은-sbom으로-만들었습니다)로 파악한
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

> 벤더/제품명은 대소문자와 `_`·공백 표기 차이를 흡수해 매칭합니다 (`Exchange Server` ↔ `exchange_server`).
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

개인이나 소규모 팀이 별도 서버 없이 운영할 수 있도록 전부 무료 티어 안에서 돌아가게 만들었습니다.
실행은 GitHub Actions, 대시보드는 GitHub Pages, DB는 Supabase, AI는 Groq와 Google AI Studio를 씁니다.

한도를 지키려고 상세 분석 리포트는 DB가 아니라 GitHub Issue에 남기고, DB에는 대시보드 표시와 재알림
판단에 필요한 최소 정보만 넣습니다. 외부 API 호출량은 한도 관리자가 미리 조절합니다.

---

> ⚠️ 이 도구가 생성·표시하는 AI 분석 결과와 위험도 분류는 **참고용**입니다.
> 실제 대응·패치 결정은 각 조직의 환경과 공식 벤더 권고를 함께 검토해 판단하시기 바랍니다.

---

## License

Code is licensed under the **[MIT License](LICENSE)** © 2026 LEEKIYOON-SEC.
외부 데이터 및 탐지 룰은 위 [데이터 출처 & 라이선스](#데이터-출처--라이선스) 표의 각 라이선스를 따릅니다.

---

<div align="center">

**🔗 [라이브 대시보드](https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/cve.html)**

`https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/cve.html`

</div>
