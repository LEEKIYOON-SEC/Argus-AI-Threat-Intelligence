import json
import os

# [1] AI 모델 설정 (고정)
MODEL_PHASE_0 = "gemma-3-27b-it"  # 리포트/번역용
MODEL_PHASE_1 = "openai/gpt-oss-120b"  # 룰 생성용

# [2] 감시 대상 로드 (assets.json)
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