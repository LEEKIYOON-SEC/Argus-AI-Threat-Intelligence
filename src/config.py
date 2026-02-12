import json
import os

# [1] AI 모델 설정
MODEL_PHASE_0 = "gemma-3-27b-it"
MODEL_PHASE_1 = "openai/gpt-oss-120b"

# [Phase 1] Groq High Reasoning 파라미터
GROQ_PARAMS = {
    "temperature": 0.6,
    "top_p": 0.95,
    "max_completion_tokens": 4096,
    "reasoning_effort": "high",
    "response_format": {"type": "json_object"}
}

# [2] 컨테이너 기반 검증 설정 (GitHub Actions Runner용)
DOCKER_CONFIG = {
    "enabled": True,
    "snort_image": "snort/snort3", # 사전에 docker pull 필요
    "timeout": 20
}

# [3] 감시 대상 로드
def load_assets():
    file_path = "assets.json"
    default_rules = [{"vendor": "*", "product": "*"}]
    if not os.path.exists(file_path):
        return default_rules
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("active_rules", default_rules)
    except:
        return default_rules

TARGET_ASSETS = load_assets()