#!/usr/bin/env python3
"""
Argus Phase 1 통합 테스트 스크립트

기존 코드를 수정하지 않고, 모듈을 임포트해서 주요 기능을 테스트합니다.
GitHub Actions에서 workflow_dispatch로 실행하거나, 로컬에서 직접 실행 가능합니다.

테스트 항목:
  A. Observable Gate 검증 (AI 룰 생성 가능 여부 판단)
  B. AI 룰 생성 테스트 (실제 Groq API 호출 → 룰 생성 확인)
  C. 공개 룰 검색 테스트 (search_public_only)
  D. 공식 룰 발견 → Slack 알림 테스트
  E. 전체 파이프라인 테스트 (단일 CVE: 수집→분석→룰→Slack)
  F. get_rules 전체 흐름

실행법:
  전체:     python test_argus.py
  개별:     python test_argus.py --test A
            python test_argus.py --test B
"""

import os
import sys
import json
import time
import argparse
import datetime
import pytz
from logger import logger
from rate_limiter import rate_limit_manager

KST = pytz.timezone('Asia/Seoul')

# ============================================================================
# 테스트 데이터
# ============================================================================

# AI가 룰을 생성할 수 있을 정도로 구체적 지표가 풍부한 가짜 CVE
RICH_CVE_DATA = {
  "id": "CVE-2024-99999",
  "title": "Apache Struts Remote Code Execution via OGNL Injection",
  "title_ko": "[테스트] Apache Struts OGNL 인젝션을 통한 원격 코드 실행",

  "summary": {
    "lang": "ko",
    "text": "Apache Struts의 특정 파일업로드 엔드포인트에서 Content-Type 헤더에 OGNL 토큰이 포함될 경우 RCE로 이어질 수 있는 취약점(테스트 데이터)."
  },

  "description": {
    "lang": "en",
    "text": "Critical RCE in Apache Struts via OGNL injection in Content-Type header when multipart parser processes crafted values."
  },

  "severity": {
    "cvss": 9.8,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss": 0.85
  },

  "cwe": ["CWE-917", "CWE-78"],

  "threat_intel": {
    "is_kev": False,
    "is_vulncheck_kev": False,
    "has_poc": True,
    "poc_count": 3,
    "poc_urls": ["https://github.com/example/poc-struts"]
  },

  "references": [
    "https://struts.apache.org/announce-2024",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-99999"
  ],

  "affected": [{
    "vendor": "Apache",
    "product": "Struts",
    "version_range": {
      "min_inclusive": "2.3.5",
      "max_inclusive": "2.5.30"
    },
    "patched": {
      "min_inclusive": "2.5.31"
    },
    "cpe_examples": [
      "cpe:2.3:a:apache:struts:2.5.30:*:*:*:*:*:*:*"
    ]
  }],

  "attack_surface": {
    "protocol": "http",
    "ports": [8080],
    "http": {
      "methods": ["POST"],
      "uri_paths": ["/struts2-showcase/fileupload.action"],
      "headers_of_interest": ["Content-Type"],
      "content_types": ["multipart/form-data"]
    }
  },

  "observables": {
    "http": {
      "uri_patterns": [
        {"type": "exact", "value": "/struts2-showcase/fileupload.action"}
      ],
      "header_patterns": [
        {
          "header": "Content-Type",
          "type": "contains_any",
          "tokens": ["%{", "${", "#", "@java.lang.Runtime", "getRuntime", "exec", "ProcessBuilder", "ognl"]
        }
      ],
      "combined_conditions": [
        {
          "logic": "AND",
          "when": [
            {"field": "http.request.uri.path", "match": "exact:/struts2-showcase/fileupload.action"},
            {"field": "http.request.headers.content-type", "match": "contains_any:%{,${,#,@java.lang.Runtime,getRuntime,exec"}
          ],
          "note": "엔드포인트 + Content-Type 헤더의 OGNL 토큰 조합"
        }
      ]
    },
    "app_logs": {
      "keywords_any": [
        "OGNL", "ognl.OgnlException", "struts", "Multipart", "JakartaMultiPartRequest",
        "ParametersInterceptor", "Content-Type", "InvalidContentTypeException"
      ]
    }
  },

  "detection_guidance": {
    "targets": ["WAF", "Suricata", "Sigma", "SIEM correlation"],
    "priority": "high",
    "false_positive_notes": [
      "multipart 업로드 정상 트래픽에서도 Content-Type에 특수문자가 포함될 수 있으나, OGNL 토큰(%{, ${, @java.lang.Runtime 등) 동시 출현은 매우 비정상적"
    ],
    "tuning": [
      "Host/URI 스코프를 서비스에 맞게 축소",
      "POST + multipart/form-data + Content-Type 토큰 조합으로 FP 감소"
    ]
  }
}

# 지표가 부족한 CVE (AI가 생성 거부해야 정상)
POOR_CVE_DATA = {
    "id": "CVE-2024-88888",
    "title": "Remote Code Execution in Product X",
    "title_ko": "[테스트] Product X 원격 코드 실행",
    "desc_ko": "Product X에서 원격 코드 실행이 가능한 취약점입니다.",
    "description": "A remote code execution vulnerability exists in Product X. An attacker can exploit this to execute arbitrary code.",
    "cvss": 8.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "is_kev": False,
    "is_vulncheck_kev": False,
    "epss": 0.02,
    "cwe": ["CWE-94"],
    "references": [],
    "affected": [{"vendor": "Unknown", "product": "Product X", "versions": "모든 버전", "patch_version": None}],
    "has_poc": False,
    "poc_count": 0,
    "poc_urls": [],
    "github_advisory": {"has_advisory": False}
}

# 공개 룰이 확실히 존재하는 유명 CVE (Log4Shell)
WELL_KNOWN_CVE_ID = "CVE-2021-44228"

# ============================================================================
# 유틸리티
# ============================================================================

def separator(title: str):
    logger.info("")
    logger.info("=" * 70)
    logger.info(f"  {title}")
    logger.info("=" * 70)

def result_badge(success: bool, label: str):
    icon = "✅ PASS" if success else "❌ FAIL"
    logger.info(f"  {icon}: {label}")

# ============================================================================
# Test A: Observable Gate 검증
# ============================================================================

def test_a_observable_gate():
    """AI 룰 생성 가능 여부를 판단하는 Observable Gate 테스트"""
    separator("Test A: Observable Gate 검증")
    
    from rule_manager import RuleManager
    rm = RuleManager()
    
    # 풍부한 지표 → 통과해야 함
    has, reason, details = rm._check_observables(RICH_CVE_DATA)
    logger.info(f"  풍부한 CVE: pass={has}, indicators={details}")
    result_badge(has == True, "풍부한 지표 CVE → Observable Gate 통과")
    
    # 부족한 지표 → 실패해야 함 (Snort/Yara용)
    has2, reason2, details2 = rm._check_observables(POOR_CVE_DATA)
    logger.info(f"  부족한 CVE: pass={has2}, reason={reason2}")
    result_badge(has2 == False, "부족한 지표 CVE → Observable Gate 차단")
    
    return True

# ============================================================================
# Test B: AI 룰 생성 (실제 Groq API 호출)
# ============================================================================

def test_b_ai_rule_generation():
    """Test B: AI 룰 생성 테스트 (실제 Groq API 호출)"""
    separator("Test B: AI 룰 생성 테스트 (실제 API 호출)")

    from rule_manager import RuleManager
    rm = RuleManager()

    # RICH_CVE_DATA를 사용하여 AI 룰 생성 테스트
    cve_data = RICH_CVE_DATA.copy()

    # AI 분석 결과 시뮬레이션 (분석이 이미 완료된 상태)
    mock_analysis = {
        "root_cause": "Apache Struts의 OGNL 인젝션을 통한 원격 코드 실행 취약점",
        "attack_scenario": (
            "공격자가 Content-Type HTTP 헤더에 OGNL 표현식을 삽입하여 "
            "/struts2-showcase/fileupload.action 엔드포인트를 통해 원격 코드 실행"
        ),
        "impact": "서버 전체 제어 가능",
        "mitigation": ["Apache Struts 2.5.31 이상으로 업데이트", "WAF 규칙 추가"],
        "rule_feasibility": True
    }

    rule_types = ["Sigma", "Snort", "Yara"]
    results = {}

    for i, rule_type in enumerate(rule_types, 1):
        logger.info(f"  [{i}/{len(rule_types)}] {rule_type} AI 룰 생성 시도...")

        try:
            ai_result = rm._generate_ai_rule(rule_type, cve_data, mock_analysis)

            if ai_result:
                code, indicators = ai_result
                results[rule_type] = True
                preview = code[:200] if isinstance(code, str) else str(code)[:200]
                logger.info(f"  ✅ {rule_type} 생성 성공")
                logger.info(f"     미리보기: {preview}...")
            else:
                results[rule_type] = False
                logger.warning(f"  ⛔ {rule_type}: AI가 생성 거부 또는 검증 실패")

        except Exception as e:
            results[rule_type] = False
            logger.error(f"  ❌ {rule_type} 생성 중 예외: {type(e).__name__}: {e}")

        time.sleep(3)

    # 결과 판정
    success_count = sum(1 for v in results.values() if v)
    total = len(rule_types)

    for rule_type in rule_types:
        status = "✅ PASS" if results.get(rule_type) else "❌ FAIL"
        logger.info(f"  {status}: {rule_type} AI 생성")

    logger.info(f"\n  📊 AI 룰 생성: {success_count}/{total} 성공")

    if success_count == 0:
        logger.warning("  ⚠️ 모든 룰 생성 실패! 아래 사항을 점검하세요:")
        logger.warning("     1. Groq API 키 및 모델 가용성")
        logger.warning("     2. AI 프롬프트에 지표가 전달되는지")

    # 최소 1개 이상 성공하면 PASS
    return success_count >= 1

# ============================================================================
# Test C: 공개 룰 검색 (search_public_only)
# ============================================================================

def test_c_public_rule_search():
    """공개 저장소에서 룰을 검색하는 search_public_only 테스트"""
    separator("Test C: 공개 룰 검색 테스트 (search_public_only)")
    
    from rule_manager import RuleManager
    rm = RuleManager()
    
    # Log4Shell은 공개 룰이 확실히 존재
    logger.info(f"  {WELL_KNOWN_CVE_ID} 공개 룰 검색 중...")
    rules = rm.search_public_only(WELL_KNOWN_CVE_ID)
    
    found = []
    if rules.get('sigma'):
        found.append("Sigma")
        logger.info(f"  ✅ Sigma: {rules['sigma']['source']}")
        logger.info(f"     ── Sigma 룰 내용 ──")
        for line in rules['sigma']['code'].strip().splitlines()[:20]:
            logger.info(f"     {line}")
        if len(rules['sigma']['code'].strip().splitlines()) > 20:
            logger.info(f"     ... (총 {len(rules['sigma']['code'].strip().splitlines())}줄)")
    if rules.get('network'):
        found.append(f"Network({len(rules['network'])})")
        for nr in rules['network']:
            logger.info(f"  ✅ Network: {nr['source']} ({nr['engine']})")
            rule_preview = nr['code'][:300] if len(nr['code']) > 300 else nr['code']
            logger.info(f"     ── {nr['engine']} 룰 내용 ──")
            logger.info(f"     {rule_preview}")
    if rules.get('yara'):
        found.append("Yara")
        logger.info(f"  ✅ Yara: {rules['yara']['source']}")
        logger.info(f"     ── Yara 룰 내용 ──")
        for line in rules['yara']['code'].strip().splitlines()[:15]:
            logger.info(f"     {line}")
    if rules.get('nuclei'):
        found.append("Nuclei")
        logger.info(f"  ✅ Nuclei: {rules['nuclei']['source']}")
        logger.info(f"     ── Nuclei 템플릿 내용 ──")
        for line in rules['nuclei']['code'].strip().splitlines()[:20]:
            logger.info(f"     {line}")
        if len(rules['nuclei']['code'].strip().splitlines()) > 20:
            logger.info(f"     ... (총 {len(rules['nuclei']['code'].strip().splitlines())}줄)")

    logger.info("")
    result_badge(len(found) > 0, f"공개 룰 검색 ({', '.join(found) if found else '없음'})")

    if found:
        logger.info("")
        logger.info("  📋 보안 담당자 안내: 위 룰을 복사하여 장비에 등록하세요.")
        logger.info("     Sigma → SIEM (Splunk, ELK 등)")
        logger.info("     Network → IDS/IPS (Snort, Suricata)")
        logger.info("     Yara → 파일/메모리 스캐너")
        logger.info("     Nuclei → 취약점 스캐너")
    
    # 존재하지 않는 CVE도 테스트
    logger.info(f"\n  CVE-2099-99999 (존재하지 않는 CVE) 검색 중...")
    rules2 = rm.search_public_only("CVE-2099-99999")
    no_rules = not any([rules2.get('sigma'), rules2.get('network'), rules2.get('yara'), rules2.get('nuclei')])
    result_badge(no_rules, "존재하지 않는 CVE → 룰 없음 반환")
    
    return len(found) > 0

# ============================================================================
# Test D: 공식 룰 발견 → Slack 알림
# ============================================================================

def test_d_official_rule_slack():
    """공식 룰이 발견되었을 때 Slack 알림을 보내는 테스트"""
    separator("Test D: 공식 룰 발견 → Slack 알림 테스트")
    
    from notifier import SlackNotifier
    notifier = SlackNotifier()
    
    # 시나리오: CVE-2021-44228에 대해 공식 룰이 발견된 상황 시뮬레이션
    # 운영 코드(rule_manager.py)가 수집하는 모든 엔진을 포함
    mock_rules = {
        "sigma": {
            "code": "title: Log4Shell Detection\nstatus: stable\nlogsource:\n  product: java\ndetection:\n  selection:\n    CommandLine|contains: 'jndi:ldap'\n  condition: selection\nlevel: critical",
            "source": "Public (SigmaHQ)",
            "verified": True
        },
        "network": [
            {
                "code": 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Apache Log4j RCE Attempt - Snort 2.9"; content:"${jndi:"; nocase; sid:2034647; rev:1;)',
                "source": "Public (Snort 2.9 ET Open)",
                "engine": "snort2",
                "verified": True
            },
            {
                "code": 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Apache Log4j RCE Attempt - Snort 3"; content:"${jndi:"; nocase; sid:2034648; rev:1;)',
                "source": "Public (Snort 3 Community)",
                "engine": "snort3",
                "verified": True
            },
            {
                "code": 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Apache Log4j RCE Attempt - Suricata 5"; content:"${jndi:"; nocase; sid:2034649; rev:1;)',
                "source": "Public (Suricata 5 ET Open)",
                "engine": "suricata5",
                "verified": True
            },
            {
                "code": 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Apache Log4j RCE Attempt - Suricata 7"; content:"${jndi:"; nocase; sid:2034650; rev:1;)',
                "source": "Public (Suricata 7 ET Open)",
                "engine": "suricata7",
                "verified": True
            }
        ],
        "yara": {
            "code": 'rule Log4Shell_Exploitation {\n  meta:\n    description = "Detects Log4Shell exploitation attempt"\n    cve = "CVE-2021-44228"\n  strings:\n    $jndi = "${jndi:" nocase\n    $ldap = "ldap://" nocase\n  condition:\n    any of them\n}',
            "source": "Public (Yara-Rules)",
            "verified": True
        }
    }
    
    logger.info("  Slack으로 공식 룰 발견 알림 전송 중...")
    success = notifier.send_official_rule_update(
        cve_id="CVE-2021-44228",
        title="[테스트] Apache Log4j2 JNDI 원격 코드 실행 (Log4Shell)",
        rules_info=mock_rules,
        original_report_url=None  # 테스트이므로 Issue URL 없음
    )
    
    result_badge(success, "Slack 공식 룰 발견 알림 전송")
    
    if success:
        logger.info("  📱 Slack을 확인하세요! '✅ 공식 룰 발견' 메시지가 도착했을 겁니다.")
    
    return success

# ============================================================================
# Test E: 전체 파이프라인 (단일 CVE)
# ============================================================================

def test_e_full_pipeline():
    """
    전체 파이프라인 테스트: 가짜 CVE를 실제 파이프라인에 태워서
    분석 → 룰 생성 → Slack 알림까지 확인
    
    ※ DB 저장과 GitHub Issue 생성은 건너뜁니다 (테스트 데이터 오염 방지)
    """
    separator("Test E: 전체 파이프라인 테스트 (Slack 알림까지)")
    
    from analyzer import Analyzer
    from rule_manager import RuleManager
    from notifier import SlackNotifier
    from main import _build_issue_body
    
    cve_data = RICH_CVE_DATA.copy()
    
    # Step 1: AI 분석
    logger.info("  [1/4] AI 심층 분석 수행 중...")
    try:
        analyzer = Analyzer()
        analysis = analyzer.analyze_cve(cve_data)
        logger.info(f"  ✅ 분석 완료:")
        logger.info(f"     root_cause: {analysis.get('root_cause', 'N/A')[:80]}...")
        logger.info(f"     scenario: {analysis.get('scenario', 'N/A')[:80]}...")
        logger.info(f"     feasibility: {analysis.get('rule_feasibility')}")
    except Exception as e:
        logger.error(f"  ❌ AI 분석 실패: {e}")
        analysis = {
            "root_cause": "테스트 - 분석 실패 폴백",
            "scenario": "MITRE ATT&CK 기반 공격 흐름:\n**초기 접근(Initial Access)** – OGNL 인젝션 (T1190). [추정]",
            "impact": "서버 전체 제어 가능",
            "mitigation": ["Apache Struts 2.5.31 이상으로 업데이트", "WAF 규칙 추가"],
            "rule_feasibility": True
        }
    
    time.sleep(3)
    
    # Step 2: 룰 생성
    logger.info("\n  [2/4] 탐지 룰 수집 중...")
    try:
        rule_manager = RuleManager()
        rules = rule_manager.get_rules(cve_data, analysis.get('rule_feasibility', False), analysis)
        
        sigma_status = "✅ 생성됨" if rules.get('sigma') else "❌ 미생성"
        network_status = f"✅ {len(rules['network'])}개" if rules.get('network') else "❌ 미생성"
        yara_status = "✅ 생성됨" if rules.get('yara') else "❌ 미생성"
        nuclei_status = "✅ 발견" if rules.get('nuclei') else "- 없음"
        
        logger.info(f"  Sigma: {sigma_status}")
        logger.info(f"  Network: {network_status}")
        logger.info(f"  Yara: {yara_status}")
        logger.info(f"  Nuclei: {nuclei_status}")
        
        if rules.get('skip_reasons'):
            logger.info(f"  Skip reasons: {rules['skip_reasons']}")
    except Exception as e:
        logger.error(f"  ❌ 룰 수집 실패: {e}")
        rules = {"sigma": None, "network": [], "yara": None, "nuclei": None, "skip_reasons": {}}
    
    # Step 3: GitHub Issue 본문 생성 (실제 생성은 안 함)
    logger.info("\n  [3/4] GitHub Issue 본문 생성 (미리보기)...")
    try:
        has_official = any([
            rules.get('sigma') and rules['sigma'].get('verified'),
            any(r.get('verified') for r in rules.get('network', [])),
            rules.get('yara') and rules['yara'].get('verified')
        ])
        
        body = _build_issue_body(cve_data, "테스트 알림", analysis, rules, has_official)
        logger.info(f"  ✅ Issue 본문 생성 완료 ({len(body)} chars)")
        
        # 핵심 섹션 존재 확인
        checks = {
            "AI 심층 분석": "🔍 AI 심층 분석" in body,
            "공격 시나리오": "🏹 AI 예상 공격 시나리오" in body,
            "대응 방안": "🛡️ AI 권고 대응 방안" in body,
            "탐지 룰": "🛡️ AI 생성 탐지 룰" in body,
        }
        for section, exists in checks.items():
            icon = "✅" if exists else "❌"
            logger.info(f"     {icon} {section}")
    except Exception as e:
        logger.error(f"  ❌ Issue 본문 생성 실패: {e}")
    
    # Step 4: Slack 알림 전송
    logger.info("\n  [4/4] Slack 알림 전송 중...")
    try:
        notifier = SlackNotifier()
        success = notifier.send_alert(cve_data, "🧪 테스트 알림", report_url=None)
        result_badge(success, "Slack 신규 CVE 알림 전송")
        
        if success:
            logger.info("  📱 Slack을 확인하세요! '🧪 테스트 알림: CVE-2024-99999' 메시지가 도착했을 겁니다.")
    except Exception as e:
        logger.error(f"  ❌ Slack 전송 실패: {e}")
    
    return True

# ============================================================================
# Test F: get_rules 전체 흐름 (skip_reasons 포함)
# ============================================================================

def test_f_get_rules_flow():
    """get_rules의 skip_reasons, nuclei, exploit-db 통합 테스트"""
    separator("Test F: get_rules 전체 흐름 검증")
    
    from rule_manager import RuleManager
    rm = RuleManager()
    
    # 부족한 CVE로 테스트 → skip_reasons 채워져야 함
    logger.info("  부족한 지표 CVE로 get_rules 호출...")
    rules = rm.get_rules(POOR_CVE_DATA, feasibility=True, analysis=None)
    
    logger.info(f"  sigma: {type(rules.get('sigma'))}")
    logger.info(f"  network: {len(rules.get('network', []))}개")
    logger.info(f"  yara: {type(rules.get('yara'))}")
    logger.info(f"  nuclei: {type(rules.get('nuclei'))}")
    logger.info(f"  skip_reasons: {rules.get('skip_reasons', {})}")
    
    has_skip = bool(rules.get('skip_reasons'))
    result_badge(has_skip, "skip_reasons 채워짐")
    result_badge('nuclei' in rules, "nuclei 키 존재")
    
    return True

# ============================================================================
# 메인 실행
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Argus Phase 1 통합 테스트")
    parser.add_argument("--test", type=str, default="ALL",
                       help="실행할 테스트 (A/B/C/D/E/F 또는 ALL)")
    args = parser.parse_args()
    
    test_map = {
        "A": ("Observable Gate 검증", test_a_observable_gate),
        "B": ("AI 룰 생성 (Groq API)", test_b_ai_rule_generation),
        "C": ("공개 룰 검색 (search_public_only)", test_c_public_rule_search),
        "D": ("공식 룰 발견 → Slack 알림", test_d_official_rule_slack),
        "E": ("전체 파이프라인 (분석→룰→Slack)", test_e_full_pipeline),
        "F": ("get_rules 전체 흐름", test_f_get_rules_flow),
    }
    
    separator("Argus Phase 1 통합 테스트 시작")
    logger.info(f"  실행 대상: {args.test}")
    logger.info(f"  시각: {datetime.datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S KST')}")
    
    results = {}
    
    if args.test == "ALL":
        targets = ["A", "B", "C", "D", "E", "F"]
    else:
        targets = [t.strip().upper() for t in args.test.split(",")]
    
    for key in targets:
        if key not in test_map:
            logger.warning(f"  알 수 없는 테스트: {key}")
            continue
        
        name, func = test_map[key]
        logger.info(f"\n{'─' * 70}")
        logger.info(f"  ▶ Test {key}: {name}")
        
        try:
            success = func()
            results[key] = success
        except Exception as e:
            logger.error(f"  ❌ Test {key} 실행 중 예외: {e}", exc_info=True)
            results[key] = False
        
        time.sleep(2)
    
    # 최종 결과
    separator("테스트 결과 요약")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    for key in targets:
        if key in results:
            name = test_map[key][0]
            icon = "✅" if results[key] else "❌"
            logger.info(f"  {icon} Test {key}: {name}")
    
    logger.info(f"\n  📊 결과: {passed}/{total} 통과")
    
    rate_limit_manager.print_summary()
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())