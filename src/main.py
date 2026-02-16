import os
import datetime
import time
import requests
import pytz
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
from google import genai
from google.genai import types

# 우리가 만든 모듈들
from logger import logger
from config import config
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
from analyzer import Analyzer
from rule_manager import RuleManager
from rate_limiter import rate_limit_manager

# KST 타임존 (한국 표준시)
KST = pytz.timezone('Asia/Seoul')

# Gemini 클라이언트 (한국어 번역용)
gemini_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# ==============================================================================
# [1] CVSS 벡터 해석 매핑
# ==============================================================================
# CVSS 벡터 문자열을 한국어로 변환하는 사전입니다.
# 예: "AV:N" → "공격 경로: 네트워크"
# 
# 왜 필요한가요?
# - "AV:N/AC:L/PR:N" 같은 암호 같은 문자열은 보안 전문가만 이해할 수 있어요
# - 이것을 "공격 경로: 네트워크, 복잡성: 낮음" 같이 읽기 쉽게 바꿔줍니다
CVSS_MAP = {
    # ==========================================
    # [CVSS 3.1 Base Metrics]
    # ==========================================
    "AV:N": "공격 경로: 네트워크 (Network)", "AV:A": "공격 경로: 인접 (Adjacent)", "AV:L": "공격 경로: 로컬 (Local)", "AV:P": "공격 경로: 물리적 (Physical)",
    "AC:L": "복잡성: 낮음", "AC:H": "복잡성: 높음",
    "PR:N": "필요 권한: 없음", "PR:L": "필요 권한: 낮음", "PR:H": "필요 권한: 높음",
    "UI:N": "사용자 관여: 없음", "UI:R": "사용자 관여: 필수",
    "S:U": "범위: 변경 없음", "S:C": "범위: 변경됨 (Changed)",
    "C:H": "기밀성: 높음", "C:L": "기밀성: 낮음", "C:N": "기밀성: 없음",
    "I:H": "무결성: 높음", "I:L": "무결성: 낮음", "I:N": "무결성: 없음",
    "A:H": "가용성: 높음", "A:L": "가용성: 낮음", "A:N": "가용성: 없음",

    # ==========================================
    # [CVSS 3.1 Temporal / Threat Metrics]
    # ==========================================
    "E:X": "악용 가능성: 미정의", "E:U": "악용 가능성: 입증 안됨", "E:P": "악용 가능성: 개념 증명(PoC)", "E:F": "악용 가능성: 기능적", "E:H": "악용 가능성: 높음",
    "RL:X": "대응 수준: 미정의", "RL:O": "대응 수준: 공식 패치", "RL:T": "대응 수준: 임시 수정", "RL:W": "대응 수준: 우회 가능", "RL:U": "대응 수준: 사용 불가",
    "RC:X": "보고 신뢰도: 미정의", "RC:U": "보고 신뢰도: 미확인", "RC:R": "보고 신뢰도: 합리적", "RC:C": "보고 신뢰도: 확인됨",

    # ==========================================
    # [CVSS 3.1 Environmental Metrics]
    # ==========================================
    "MAV:N": "수정된 경로: 네트워크", "MAV:A": "수정된 경로: 인접", "MAV:L": "수정된 경로: 로컬", "MAV:P": "수정된 경로: 물리적",
    "MAC:L": "수정된 복잡성: 낮음", "MAC:H": "수정된 복잡성: 높음",
    "MPR:N": "수정된 권한: 없음", "MPR:L": "수정된 권한: 낮음", "MPR:H": "수정된 권한: 높음",
    "MUI:N": "수정된 관여: 없음", "MUI:R": "수정된 관여: 필수",
    "MS:U": "수정된 범위: 변경 없음", "MS:C": "수정된 범위: 변경됨",
    "MC:H": "수정된 기밀성: 높음", "MC:L": "수정된 기밀성: 낮음", "MC:N": "수정된 기밀성: 없음",
    "MI:H": "수정된 무결성: 높음", "MI:L": "수정된 무결성: 낮음", "MI:N": "수정된 무결성: 없음",
    "MA:H": "수정된 가용성: 높음", "MA:L": "수정된 가용성: 낮음", "MA:N": "수정된 가용성: 없음",
    "CR:X": "기밀성 요구: 미정의", "CR:L": "기밀성 요구: 낮음", "CR:M": "기밀성 요구: 보통", "CR:H": "기밀성 요구: 높음",
    "IR:X": "무결성 요구: 미정의", "IR:L": "무결성 요구: 낮음", "IR:M": "무결성 요구: 보통", "IR:H": "무결성 요구: 높음",
    "AR:X": "가용성 요구: 미정의", "AR:L": "가용성 요구: 낮음", "AR:M": "가용성 요구: 보통", "AR:H": "가용성 요구: 높음",

    # ==========================================
    # [CVSS 4.0 Base Metrics]
    # ==========================================
    "AT:N": "공격 기술: 없음", "AT:P": "공격 기술: 존재(Present)",
    "VC:H": "취약시스템 기밀성: 높음", "VC:L": "취약시스템 기밀성: 낮음", "VC:N": "취약시스템 기밀성: 없음",
    "VI:H": "취약시스템 무결성: 높음", "VI:L": "취약시스템 무결성: 낮음", "VI:N": "취약시스템 무결성: 없음",
    "VA:H": "취약시스템 가용성: 높음", "VA:L": "취약시스템 가용성: 낮음", "VA:N": "취약시스템 가용성: 없음",
    "SC:H": "후속시스템 기밀성: 높음", "SC:L": "후속시스템 기밀성: 낮음", "SC:N": "후속시스템 기밀성: 없음",
    "SI:H": "후속시스템 무결성: 높음", "SI:L": "후속시스템 무결성: 낮음", "SI:N": "후속시스템 무결성: 없음",
    "SA:H": "후속시스템 가용성: 높음", "SA:L": "후속시스템 가용성: 낮음", "SA:N": "후속시스템 가용성: 없음",

    # ==========================================
    # [CVSS 4.0 Environmental (Modified Base) Metrics]
    # ==========================================
    "MAT:N": "수정된 공격 기술: 없음", "MAT:P": "수정된 공격 기술: 존재",
    "MVC:H": "수정된 취약시스템 기밀성: 높음", "MVC:L": "수정된 취약시스템 기밀성: 낮음", "MVC:N": "수정된 취약시스템 기밀성: 없음",
    "MVI:H": "수정된 취약시스템 무결성: 높음", "MVI:L": "수정된 취약시스템 무결성: 낮음", "MVI:N": "수정된 취약시스템 무결성: 없음",
    "MVA:H": "수정된 취약시스템 가용성: 높음", "MVA:L": "수정된 취약시스템 가용성: 낮음", "MVA:N": "수정된 취약시스템 가용성: 없음",
    "MSC:H": "수정된 후속시스템 기밀성: 높음", "MSC:L": "수정된 후속시스템 기밀성: 낮음", "MSC:N": "수정된 후속시스템 기밀성: 없음", "MSC:S": "수정된 후속시스템 기밀성: 안전(Safety)",
    "MSI:H": "수정된 후속시스템 무결성: 높음", "MSI:L": "수정된 후속시스템 무결성: 낮음", "MSI:N": "수정된 후속시스템 무결성: 없음", "MSI:S": "수정된 후속시스템 무결성: 안전(Safety)",
    "MSA:H": "수정된 후속시스템 가용성: 높음", "MSA:L": "수정된 후속시스템 가용성: 낮음", "MSA:N": "수정된 후속시스템 가용성: 없음", "MSA:S": "수정된 후속시스템 가용성: 안전(Safety)",

    # ==========================================
    # [CVSS 4.0 Supplemental Metrics]
    # ==========================================
    "S:X": "안전(Safety): 미정의", "S:N": "안전(Safety): 무시 가능", "S:P": "안전(Safety): 존재(Present)",
    "AU:X": "자동화 가능성: 미정의", "AU:N": "자동화 가능성: 아니오", "AU:Y": "자동화 가능성: 예",
    "R:X": "복구(Recovery): 미정의", "R:A": "복구: 자동", "R:U": "복구: 사용자", "R:I": "복구: 복구 불가",
    "V:X": "가치 밀도: 미정의", "V:D": "가치 밀도: 분산(Diffuse)", "V:C": "가치 밀도: 집중(Concentrated)",
    "RE:X": "대응 노력: 미정의", "RE:L": "대응 노력: 낮음", "RE:M": "대응 노력: 보통", "RE:H": "대응 노력: 높음",
    "U:X": "긴급성: 미정의", "U:Clear": "긴급성: 명확함", "U:Green": "긴급성: 낮음(Green)", "U:Amber": "긴급성: 주의(Amber)", "U:Red": "긴급성: 높음(Red)"
}

# ==============================================================================
# [2] 유틸리티 함수들
# ==============================================================================

def parse_cvss_vector(vector_str: str) -> str:
    """
    CVSS 벡터 문자열을 한국어로 변환
    
    작동 원리:
    1. 벡터를 '/'로 분리 (예: AV:N/AC:L → ['AV:N', 'AC:L'])
    2. 각 부분을 사전에서 찾아 한국어로 변환
    3. HTML 줄바꿈(<br>)으로 연결
    
    Args:
        vector_str: "CVSS:3.1/AV:N/AC:L/..." 형식
    
    Returns:
        "• 공격 경로: 네트워크<br>• 복잡성: 낮음<br>..." 형식
    """
    if not vector_str or vector_str == "N/A":
        return "정보 없음"
    
    parts = vector_str.split('/')
    mapped_parts = []
    
    for part in parts:
        if ':' in part:
            full_key = part
            desc = CVSS_MAP.get(full_key, f"**{part}**")
            if full_key in CVSS_MAP:
                mapped_parts.append(f"• {desc}")
            else:
                mapped_parts.append(f"• {part}")
    
    return "<br>".join(mapped_parts)

def is_target_asset(cve_description: str, cve_id: str) -> Tuple[bool, Optional[str]]:
    """
    자산 필터링 (감시 대상인지 확인)
    
    config의 TARGET_ASSETS와 CVE 설명을 비교해서
    우리가 관심있는 제품인지 판단합니다.
    
    작동 원리:
    1. assets.json에서 감시 대상 로드
    2. CVE 설명에 벤더명과 제품명이 있는지 확인
    3. 와일드카드(*) 지원
    
    Args:
        cve_description: CVE 설명 텍스트
        cve_id: CVE ID
    
    Returns:
        (매칭 여부, 매칭 정보)
    
    예시:
    - assets.json에 "apache/struts" 등록
    - CVE 설명에 "apache struts" 포함
    - → (True, "Matched: apache/struts")
    """
    desc_lower = cve_description.lower()
    
    for target in config.get_target_assets():
        vendor = target.get('vendor', '').lower()
        product = target.get('product', '').lower()
        
        # 전체 감시 모드
        if vendor == "*" and product == "*":
            return True, "All Assets (*)"
        
        # 벤더/제품 매칭
        if vendor in desc_lower and (product == "*" or product in desc_lower):
            return True, f"Matched: {vendor}/{product}"
    
    return False, None

def generate_korean_summary(cve_data: Dict) -> Tuple[str, str]:
    """
    Gemini 한국어 번역 (v3.0 - rate_limit_manager + 429 재시도)
    """
    prompt = f"""
Task: Translate Title and Summarize Description into Korean.
[Input] Title: {cve_data['title']} / Desc: {cve_data['description']}
[Format]
제목: [Korean Title]
내용: [Korean Summary (Max 3 lines)]
Do NOT add intro/outro.
"""
    
    max_retries = 2
    
    for attempt in range(max_retries + 1):
        try:
            rate_limit_manager.check_and_wait("gemini")
            
            response = gemini_client.models.generate_content(
                model=config.MODEL_PHASE_0,
                contents=prompt,
                config=types.GenerateContentConfig(
                    safety_settings=[types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    )]
                )
            )
            
            rate_limit_manager.record_call("gemini")
            
            text = response.text.strip()
            title_ko, desc_ko = cve_data['title'], cve_data['description'][:200]
            
            for line in text.split('\n'):
                if line.startswith("제목:"):
                    title_ko = line.replace("제목:", "").strip()
                if line.startswith("내용:"):
                    desc_ko = line.replace("내용:", "").strip()
            
            return title_ko, desc_ko
            
        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                retry_after = rate_limit_manager.parse_retry_after(error_str)
                wait_time = retry_after if retry_after else 60
                if attempt < max_retries:
                    logger.warning(
                        f"Gemini 429 수신 (시도 {attempt + 1}/{max_retries + 1}), "
                        f"{wait_time:.0f}초 대기 후 재시도..."
                    )
                    rate_limit_manager.handle_429("gemini", wait_time)
                    continue
                else:
                    logger.warning(f"Gemini 429 재시도 소진, 원본 사용: {cve_data['id']}")
            else:
                logger.warning(f"번역 실패: {e}, 원본 사용")
            
            return cve_data['title'], cve_data['description'][:200]

# ==============================================================================
# [3] GitHub Issue 생성/업데이트
# ==============================================================================

def create_github_issue(cve_data: Dict, reason: str) -> Tuple[Optional[str], Optional[Dict]]:
    """
    GitHub Issue 생성
    
    High Risk CVE에 대해 상세한 분석 리포트를 GitHub Issue로 생성합니다.
    
    왜 GitHub Issue?
    - Slack 메시지는 금방 묻혀버려요
    - GitHub Issue는 영구 보존되고, 검색 가능하고, 추적 가능합니다
    - 팀원들이 댓글로 토론하고 작업을 할당할 수 있어요
    
    작동 과정:
    1. Analyzer로 CVE 심층 분석
    2. RuleManager로 탐지 룰 생성/수집
    3. 마크다운 리포트 작성
    4. GitHub API로 Issue 생성
    5. 룰 정보 반환 (DB 저장용)
    
    Args:
        cve_data: CVE 정보
        reason: 알림 사유
    
    Returns:
        (Issue URL, 룰 정보)
    """
    token = os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    
    if not repo:
        logger.warning("GITHUB_REPOSITORY 미설정, Issue 생성 건너뜀")
        return None, None
    
    try:
        # Step 1: AI 분석
        logger.info(f"AI 분석 시작: {cve_data['id']}")
        analyzer = Analyzer()
        analysis = analyzer.analyze_cve(cve_data)
        
        # Step 2: 룰 생성/수집
        logger.info(f"룰 수집 시작: {cve_data['id']}")
        rule_manager = RuleManager()
        rules = rule_manager.get_rules(cve_data, analysis.get('rule_feasibility', False), analysis)
        
        # Step 3: 공식 룰 존재 여부 확인
        has_official = any([
            rules.get('sigma') and rules['sigma'].get('verified'),
            any(r.get('verified') for r in rules.get('network', [])),  # network는 리스트!
            rules.get('yara') and rules['yara'].get('verified')
        ])
        
        # Step 4: 마크다운 리포트 구성
        body = _build_issue_body(cve_data, reason, analysis, rules, has_official)
        
        # Step 5: GitHub API 호출
        url = f"https://api.github.com/repos/{repo}/issues"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        payload = {
            "title": f"[Argus] {cve_data['id']}: {cve_data['title_ko']}",
            "body": body,
            "labels": ["security", "cve"]
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        
        issue_url = response.json().get("html_url")
        logger.info(f"GitHub Issue 생성 성공: {issue_url}")
        
        return issue_url, {"has_official": has_official, "rules": rules}
        
    except Exception as e:
        logger.error(f"GitHub Issue 생성 실패: {e}")
        return None, None

def _sanitize_for_table(text: str) -> str:
    """마크다운 테이블 셀 안전하게 만들기 (| 와 줄바꿈 이스케이프)"""
    if not text or text == '-':
        return text
    # | → \| (테이블 구분자 깨짐 방지)
    text = text.replace('|', '\\|')
    # 줄바꿈 → <br> (테이블 내 줄바꿈)
    text = text.replace('\n', '<br>')
    return text

def _build_issue_body(cve_data: Dict, reason: str, analysis: Dict, rules: Dict, has_official: bool) -> str:
    """
    GitHub Issue 본문 구성 (v3.0)
    
    디자인 변경:
    - 🔍 AI 심층 분석
    - 🏹 공격 벡터 상세 → 🏹 AI 예상 공격 시나리오 순서
    - 🛡️ AI 권고 대응 방안
    - 🛡️ AI 생성 탐지 룰
    - 위협 인텔리전스 (PoC, VulnCheck KEV, Nuclei) 추가
    """
    # CVSS 배지 색상
    score = cve_data['cvss']
    if score >= 9.0: color = "FF0000"
    elif score >= 7.0: color = "FD7E14"
    elif score >= 4.0: color = "FFC107"
    elif score > 0: color = "28A745"
    else: color = "CCCCCC"
    
    kev_color = "FF0000" if cve_data['is_kev'] else "CCCCCC"
    
    badges = f"![CVSS](https://img.shields.io/badge/CVSS-{score}-{color}) ![EPSS](https://img.shields.io/badge/EPSS-{cve_data['epss']*100:.2f}%25-blue) ![KEV](https://img.shields.io/badge/KEV-{'YES' if cve_data['is_kev'] else 'No'}-{kev_color})"
    
    # PoC 배지
    if cve_data.get('has_poc'):
        badges += f" ![PoC](https://img.shields.io/badge/PoC-{cve_data.get('poc_count', 0)}건_공개-FF4500)"
    
    # VulnCheck KEV 배지
    if cve_data.get('is_vulncheck_kev') and not cve_data['is_kev']:
        badges += " ![VulnCheck](https://img.shields.io/badge/VulnCheck_KEV-YES-FF6600)"
    
    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    
    # 영향받는 자산 테이블
    affected_rows = ""
    for item in cve_data.get('affected', []):
        patch = item.get('patch_version', '-') or '-'
        affected_rows += f"| {item['vendor']} | {item['product']} | {item['versions']} | {patch} |\n"
    if not affected_rows:
        affected_rows = "| - | - | - | - |"
    
    # 대응 방안
    mitigation_list = "\n".join([f"- {m}" for m in analysis.get('mitigation', [])])
    
    # 참고 자료
    ref_list = "\n".join([f"- {r}" for r in cve_data['references']])
    
    # CVSS 벡터 해석
    vector_details = parse_cvss_vector(cve_data.get('cvss_vector', 'N/A'))
    
    # AI 분석 결과 테이블 안전화
    root_cause = _sanitize_for_table(analysis.get('root_cause', '-'))
    impact = _sanitize_for_table(analysis.get('impact', '-'))
    scenario = analysis.get('scenario', '정보 없음').replace('\n', '<br>')
    vector_details_safe = _sanitize_for_table(vector_details)
    
    # 룰 섹션 — 항상 3가지 모두 표시
    skip_reasons = rules.get('skip_reasons', {})
    
    rules_section = "## 🛡️ AI 생성 탐지 룰\n\n"
    
    has_any_ai = any([
        rules.get('sigma') and not rules['sigma'].get('verified'),
        any(r for r in rules.get('network', []) if not r.get('verified')),
        rules.get('yara') and not rules['yara'].get('verified')
    ])
    if has_any_ai and not has_official:
        rules_section += "> ⚠️ **주의:** AI 생성 룰은 실제 배포 전 보안 전문가의 검토가 필요합니다.\n\n"
    
    # Sigma
    if rules.get('sigma'):
        is_verified = rules['sigma'].get('verified')
        badge = "🟢 **공식 검증**" if is_verified else "🔶 **AI 생성 - 검토 필요**"
        indicator_info = ""
        if not is_verified and rules['sigma'].get('indicators'):
            indicator_info = f"\n> **Based on:** {', '.join(rules['sigma']['indicators'])}\n"
        rules_section += f"### Sigma Rule ({rules['sigma']['source']}) {badge}\n{indicator_info}```yaml\n{rules['sigma']['code']}\n```\n\n"
    else:
        skip_reason = skip_reasons.get('sigma', '공개 룰 미발견, AI 생성 실패')
        rules_section += f"### Sigma Rule ❌ 미생성\n> **사유:** {skip_reason}\n\n"
    
    # Snort/Suricata
    if rules.get('network'):
        for idx, net_rule in enumerate(rules['network'], 1):
            is_verified = net_rule.get('verified')
            badge = "🟢 **공식 검증**" if is_verified else "🔶 **AI 생성 - 검토 필요**"
            engine_name = net_rule.get('engine', 'unknown').upper()
            indicator_info = ""
            if not is_verified and net_rule.get('indicators'):
                indicator_info = f"\n> **Based on:** {', '.join(net_rule['indicators'])}\n"
            rules_section += f"### Snort/Suricata Rule #{idx} ({net_rule['source']} - {engine_name}) {badge}\n{indicator_info}```bash\n{net_rule['code']}\n```\n\n"
    else:
        skip_reason = skip_reasons.get('network', '공개 룰 미발견, AI 생성 실패')
        rules_section += f"### Snort/Suricata Rule ❌ 미생성\n> **사유:** {skip_reason}\n\n"
    
    # Yara
    if rules.get('yara'):
        is_verified = rules['yara'].get('verified')
        badge = "🟢 **공식 검증**" if is_verified else "🔶 **AI 생성 - 검토 필요**"
        indicator_info = ""
        if not is_verified and rules['yara'].get('indicators'):
            indicator_info = f"\n> **Based on:** {', '.join(rules['yara']['indicators'])}\n"
        rules_section += f"### Yara Rule ({rules['yara']['source']}) {badge}\n{indicator_info}```yara\n{rules['yara']['code']}\n```\n\n"
    else:
        skip_reason = skip_reasons.get('yara', '공개 룰 미발견, AI 생성 실패')
        rules_section += f"### Yara Rule ❌ 미생성\n> **사유:** {skip_reason}\n\n"
    
    # Nuclei Template (있으면 표시)
    if rules.get('nuclei'):
        rules_section += f"### Nuclei Template ({rules['nuclei']['source']}) 🟢 **공식 검증**\n```yaml\n{rules['nuclei']['code']}\n```\n\n"
    
    # 위협 인텔리전스 섹션 (PoC, Advisory 등)
    threat_intel_section = ""
    
    # PoC 정보
    if cve_data.get('has_poc'):
        poc_urls = cve_data.get('poc_urls', [])
        poc_links = "\n".join([f"- {url}" for url in poc_urls[:3]]) if poc_urls else "- (링크 없음)"
        threat_intel_section += f"""### 🔥 공개 PoC ({cve_data.get('poc_count', 0)}건)
{poc_links}

"""
    
    # GitHub Advisory 패키지 정보
    advisory = cve_data.get('github_advisory', {})
    if advisory.get('has_advisory') and advisory.get('packages'):
        pkg_lines = []
        for pkg in advisory['packages'][:5]:
            patched = pkg.get('patched', '')
            patch_info = f" → 패치: {patched}" if patched else ""
            pkg_lines.append(f"| {pkg['ecosystem']} | {pkg['name']} | {pkg.get('vulnerable_range', 'N/A')} | {patched or '-'} |")
        advisory_rows = "\n".join(pkg_lines)
        threat_intel_section += f"""### 📦 영향받는 패키지 (GitHub Advisory: {advisory.get('ghsa_id', '')})
| 생태계 | 패키지 | 취약 범위 | 패치 버전 |
| :--- | :--- | :--- | :--- |
{advisory_rows}

"""
    
    # 위협 인텔 섹션이 있으면 헤더 추가
    if threat_intel_section:
        threat_intel_section = f"## 🔎 위협 인텔리전스\n\n{threat_intel_section}"
    
    now_kst = datetime.datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S (KST)')
    
    body = f"""# 🛡️ {cve_data['title_ko']}

> **탐지 일시:** {now_kst}
> **탐지 사유:** {reason}

{badges}
**취약점 유형 (CWE):** {cwe_str}

## 📦 영향 받는 자산
| 벤더 | 제품 | 영향 버전 | 패치 버전 |
| :--- | :--- | :--- | :--- |
{affected_rows}

## 🔍 AI 심층 분석
| 항목 | 내용 |
| :--- | :--- |
| **기술적 원인** | {root_cause} |
| **비즈니스 영향** | {impact} |

### 🏹 공격 벡터 상세
| 항목 | 내용 |
| :--- | :--- |
| **공식 벡터** | `{cve_data.get('cvss_vector', 'N/A')}` |
| **상세 분석** | {vector_details_safe} |

### 🏹 AI 예상 공격 시나리오
> {scenario}

## 🛡️ AI 권고 대응 방안
{mitigation_list}

{threat_intel_section}
{rules_section}

## 🔗 참고 자료
{ref_list}
"""
    return body.strip()

def update_github_issue_with_official_rules(issue_url: str, cve_id: str, rules: Dict) -> bool:
    """
    GitHub Issue에 공식 룰 발견 댓글 추가
    
    이전에 AI 룰로 보고된 Issue에 공식 룰이 발견되면
    댓글을 추가해서 팀원들에게 알립니다.
    
    Args:
        issue_url: GitHub Issue URL
        cve_id: CVE ID
        rules: 룰 정보
    
    Returns:
        성공 여부
    """
    comment = f"""## ✅ 공식 탐지 룰 발견

{cve_id}에 대한 **공식 검증된 탐지 룰**이 발견되었습니다. AI 생성 룰을 이것으로 교체하시기 바랍니다.

"""
    
    # Sigma
    if rules.get('sigma') and rules['sigma'].get('verified'):
        comment += f"### Sigma Rule ({rules['sigma']['source']})\n```yaml\n{rules['sigma']['code']}\n```\n\n"
    
    # Network (여러 개 가능)
    if rules.get('network'):
        for idx, net_rule in enumerate(rules['network'], 1):
            if net_rule.get('verified'):
                engine = net_rule.get('engine', 'unknown').upper()
                comment += f"### Snort/Suricata Rule #{idx} ({net_rule['source']} - {engine})\n```bash\n{net_rule['code']}\n```\n\n"
    
    # Yara
    if rules.get('yara') and rules['yara'].get('verified'):
        comment += f"### Yara Rule ({rules['yara']['source']})\n```yara\n{rules['yara']['code']}\n```\n\n"
    
    notifier = SlackNotifier()
    return notifier.update_github_issue(issue_url, comment)

# ==============================================================================
# [4] CVE 처리 (단일)
# ==============================================================================

def process_single_cve(cve_id: str, collector: Collector, db: ArgusDB, notifier: SlackNotifier) -> Optional[Dict]:
    """
    단일 CVE 처리
    
    이 함수는 병렬 처리에서 각 워커가 실행합니다.
    하나의 CVE를 처음부터 끝까지 처리해요.
    
    과정:
    1. CVE 상세 정보 수집
    2. 자산 필터링 (감시 대상인지 확인)
    3. 알림 필요성 판단 (신규 또는 상태 변화)
    4. High Risk면 GitHub Issue 생성
    5. Slack 알림 전송
    6. DB에 저장
    
    Args:
        cve_id: CVE ID
        collector: Collector 인스턴스
        db: Database 인스턴스
        notifier: Notifier 인스턴스
    
    Returns:
        처리 결과 또는 None
    
    왜 try-except로 감싸나요?
    - 한 CVE가 실패해도 다른 CVE 처리는 계속되어야 해요
    - 에러는 로깅하고, None을 반환해서 "이 CVE는 건너뛰기"를 표시
    """
    try:
        # Step 1: CVE 상세 정보 수집
        raw_data = collector.enrich_cve(cve_id)
        
        if raw_data.get('state') != 'PUBLISHED':
            logger.debug(f"{cve_id}: PUBLISHED 상태 아님, 건너뜀")
            return None
        
        # Step 2: 자산 필터링
        is_target, match_info = is_target_asset(raw_data['description'], cve_id)
        if not is_target:
            logger.debug(f"{cve_id}: 감시 대상 아님, 건너뜀")
            return None
        
        # Step 3: 현재 상태 구성
        current_state = {
            "id": cve_id,
            "title": raw_data['title'],
            "cvss": raw_data['cvss'],
            "cvss_vector": raw_data['cvss_vector'],
            "is_kev": cve_id in collector.kev_set,
            "epss": collector.epss_cache.get(cve_id, 0.0),
            "description": raw_data['description'],
            "cwe": raw_data['cwe'],
            "references": raw_data['references'],
            "affected": raw_data['affected']
        }
        
        # Step 3.5: 추가 위협 인텔리전스 수집 (NVD, PoC, VulnCheck, Advisory)
        current_state = collector.enrich_threat_intel(current_state)
        
        # VulnCheck KEV도 is_kev 판단에 반영
        if current_state.get('is_vulncheck_kev') and not current_state['is_kev']:
            logger.info(f"  📋 {cve_id}: VulnCheck KEV 등재 (CISA KEV 미등재)")
        
        # Step 4: 알림 필요성 판단
        last_record = db.get_cve(cve_id)
        last_state = last_record.get('last_alert_state') if last_record else None
        
        should_alert, alert_reason, is_high_risk = _should_send_alert(
            current_state, last_state
        )
        
        if not should_alert:
            # 알림 불필요, DB만 업데이트
            db.upsert_cve({
                "id": cve_id,
                "updated_at": datetime.datetime.now(KST).isoformat()
            })
            return None
        
        # Step 5: 한국어 번역
        logger.info(f"알림 발송 준비: {cve_id} (HighRisk: {is_high_risk})")
        title_ko, desc_ko = generate_korean_summary(current_state)
        current_state['title_ko'] = title_ko
        current_state['desc_ko'] = desc_ko
        
        # Step 6: High Risk면 GitHub Issue 생성
        report_url = None
        rules_info = None
        if is_high_risk:
            report_url, rules_info = create_github_issue(current_state, alert_reason)
        
        # Step 7: Slack 알림
        notifier.send_alert(current_state, alert_reason, report_url)
        
        # Step 8: DB 저장
        db_data = {
            "id": cve_id,
            "cvss_score": current_state['cvss'],
            "epss_score": current_state['epss'],
            "is_kev": current_state['is_kev'],
            "last_alert_at": datetime.datetime.now(KST).isoformat(),
            "last_alert_state": current_state,
            "report_url": report_url,
            "updated_at": datetime.datetime.now(KST).isoformat()
        }
        
        if rules_info:
            db_data["has_official_rules"] = rules_info.get('has_official', False)
            db_data["rules_snapshot"] = rules_info.get('rules')
            db_data["last_rule_check_at"] = datetime.datetime.now(KST).isoformat()
        
        db.upsert_cve(db_data)
        
        return {"cve_id": cve_id, "status": "success"}
        
    except Exception as e:
        logger.error(f"{cve_id} 처리 실패: {e}", exc_info=True)
        return None

def _should_send_alert(current: Dict, last: Optional[Dict]) -> Tuple[bool, str, bool]:
    """
    알림 필요성 판단
    
    상태 변화 기반 트리거:
    1. 신규 CVE
    2. KEV 등재 (최우선)
    3. EPSS 급증 (>10% AND 이전 대비 +5%p)
    4. CVSS 점수 상향 (7.0+ 진입)
    
    Returns:
        (알림 필요 여부, 알림 사유, High Risk 여부)
    """
    is_high_risk = current['cvss'] >= 7.0 or current['is_kev'] or current.get('is_vulncheck_kev', False)
    
    # 신규 CVE
    if last is None:
        return True, "신규 취약점", is_high_risk
    
    # KEV 등재
    if current['is_kev'] and not last.get('is_kev'):
        return True, "🚨 KEV 등재", True
    
    # VulnCheck KEV 등재 (CISA보다 넓은 커버리지)
    if current.get('is_vulncheck_kev') and not last.get('is_vulncheck_kev'):
        return True, "📋 VulnCheck KEV 등재", True
    
    # PoC 공개
    if current.get('has_poc') and not last.get('has_poc'):
        return True, "🔥 PoC 공개", True
    
    # EPSS 급증
    if current['epss'] >= 0.1 and (current['epss'] - last.get('epss', 0)) > 0.05:
        return True, "📈 EPSS 급증", True
    
    # CVSS 상향
    if current['cvss'] >= 7.0 and last.get('cvss', 0) < 7.0:
        return True, "🔺 CVSS 위험도 상향", True
    
    return False, "", is_high_risk

# ==============================================================================
# [5] 공식 룰 재발견
# ==============================================================================

def check_for_official_rules() -> None:
    """
    AI 생성 룰 CVE의 공식 룰 재발견 (v2.0)
    
    v2.0 변경사항:
    - search_public_only() 사용 → Groq API 소모 없음
    - CVSS 기반 재확인 주기 (DB에서 필터링)
    - 체크 후 last_rule_check_at 항상 갱신 (중복 체크 방지)
    """
    try:
        logger.info("=== 공식 룰 재발견 체크 시작 ===")
        
        db = ArgusDB()
        notifier = SlackNotifier()
        rule_manager = RuleManager()
        
        ai_cves = db.get_ai_generated_cves()
        
        if not ai_cves:
            logger.info("재확인 대상 없음")
            return
        
        logger.info(f"재확인 대상: {len(ai_cves)}건")
        
        for record in ai_cves:
            cve_id = record['id']
            
            try:
                # 공개 룰만 검색 (AI 생성 없음 → Groq API 소모 0)
                rules = rule_manager.search_public_only(cve_id)
                
                # 공식 룰 존재 확인
                has_official = any([
                    rules.get('sigma') and rules['sigma'].get('verified'),
                    any(r.get('verified') for r in rules.get('network', [])),
                    rules.get('yara') and rules['yara'].get('verified'),
                    rules.get('nuclei') and rules['nuclei'].get('verified')
                ])
                
                now_iso = datetime.datetime.now(KST).isoformat()
                
                if has_official:
                    logger.info(f"✅ {cve_id}: 공식 룰 발견!")
                    
                    # Slack 알림
                    title_ko = record.get('last_alert_state', {}).get('title_ko', cve_id)
                    notifier.send_official_rule_update(
                        cve_id=cve_id,
                        title=title_ko,
                        rules_info=rules,
                        original_report_url=record.get('report_url')
                    )
                    
                    # GitHub Issue 업데이트
                    if record.get('report_url'):
                        update_github_issue_with_official_rules(
                            record['report_url'],
                            cve_id,
                            rules
                        )
                    
                    # DB 업데이트 — 공식 룰 발견
                    db.upsert_cve({
                        "id": cve_id,
                        "has_official_rules": True,
                        "rules_snapshot": rules,
                        "last_rule_check_at": now_iso,
                        "updated_at": now_iso
                    })
                else:
                    # 공식 룰 미발견 — last_rule_check_at만 갱신 (다음 7일간 스킵)
                    db.upsert_cve({
                        "id": cve_id,
                        "last_rule_check_at": now_iso,
                        "updated_at": now_iso
                    })
                
            except Exception as e:
                logger.error(f"{cve_id} 공식 룰 체크 실패: {e}")
                continue
        
        logger.info("=== 공식 룰 재발견 체크 완료 ===")
        
    except Exception as e:
        logger.error(f"공식 룰 체크 프로세스 실패: {e}")

# ==============================================================================
# [6] 메인 실행 로직
# ==============================================================================

def main():
    """
    Argus 메인 실행 함수
    
    전체 흐름:
    1. 헬스체크 (시스템 상태 확인)
    2. 공식 룰 재발견 체크
    3. 최신 CVE 수집
    4. 병렬 처리로 CVE 분석
    5. 결과 요약
    
    왜 병렬 처리?
    - 순차 처리: CVE 100개 × 30초 = 50분
    - 병렬 처리: CVE 100개 / 3 워커 = 약 17분
    - 3배 빠름!
    
    ThreadPoolExecutor란?
    - 여러 작업을 동시에 실행하는 도구예요
    - max_workers=3이면 3개 CVE를 동시에 처리
    - 마치 3명의 직원이 동시에 일하는 것과 같아요
    """
    start_time = time.time()
    logger.info("=" * 60)
    logger.info(f"Argus Phase 1 시작 (Model: {config.MODEL_PHASE_1})")
    logger.info("=" * 60)
    
    # Step 1: 헬스체크
    health = config.health_check()
    if not all(health.values()):
        logger.error(f"헬스체크 실패: {health}")
        return
    logger.info(f"✅ 헬스체크 통과: {health}")
    
    # Step 2: 모듈 초기화
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()
    
    # Step 3: 공식 룰 재발견
    check_for_official_rules()
    
    # Step 4: KEV 및 최신 CVE 수집
    collector.fetch_kev()
    collector.fetch_vulncheck_kev()
    target_cve_ids = collector.fetch_recent_cves(hours=config.PERFORMANCE["cve_fetch_hours"])
    
    if not target_cve_ids:
        logger.info("처리할 CVE 없음")
        return
    
    # Step 5: EPSS 수집
    collector.fetch_epss(target_cve_ids)
    
    logger.info(f"분석 대상: {len(target_cve_ids)}건")
    
    # Step 6: 병렬 처리로 CVE 분석
    results = []
    max_workers = config.PERFORMANCE["max_workers"]
    
    logger.info(f"병렬 처리 시작 (워커: {max_workers}명)")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 각 CVE에 대해 process_single_cve 함수를 비동기 실행
        future_to_cve = {
            executor.submit(process_single_cve, cve_id, collector, db, notifier): cve_id
            for cve_id in target_cve_ids
        }
        
        # 완료된 작업부터 결과 수집
        for future in as_completed(future_to_cve):
            cve_id = future_to_cve[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"{cve_id} 처리 중 예외 발생: {e}")
    
    # Step 7: 결과 요약
    elapsed = time.time() - start_time
    logger.info("=" * 60)
    logger.info(f"처리 완료: {len(results)}/{len(target_cve_ids)}건 성공")
    logger.info(f"소요 시간: {elapsed:.1f}초")
    logger.info("=" * 60)
    
    rate_limit_manager.print_summary()

if __name__ == "__main__":
    main()