from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Tuple

# GitHub Actions에서 미리 pull 해둔 이미지:
# - jasonish/suricata:8.0
# - linton/docker-snort:latest
# - ciscotalos/snort3:latest
#
# 로컬 테스트도 docker만 있으면 동일하게 동작.


@dataclass
class ValidationResult:
    ok: bool
    engine: str
    details: str


def _run(cmd: list[str], timeout: int = 120) -> Tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        return (p.returncode == 0), out.strip()
    except Exception as e:
        return False, f"Exception: {e}"


def validate_sigma(rule_text: str) -> ValidationResult:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "rule.yml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(rule_text.strip() + "\n")
        ok, out = _run(["sigma", "validate", path], timeout=60)
        return ValidationResult(ok=ok, engine="sigma", details=out)


def validate_yara(rule_text: str) -> ValidationResult:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "rule.yar")
        with open(path, "w", encoding="utf-8") as f:
            f.write(rule_text.strip() + "\n")
        # compile only
        ok, out = _run(["yara", "-C", path], timeout=60)
        return ValidationResult(ok=ok, engine="yara", details=out)


def validate_suricata(rule_text: str) -> ValidationResult:
    """
    Suricata -T로 syntax/로드 검증.
    """
    with tempfile.TemporaryDirectory() as td:
        rule_path = os.path.join(td, "test.rules")
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(rule_text.strip() + "\n")

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{td}:/rules",
            "jasonish/suricata:8.0",
            "suricata", "-T",
            "-c", "/etc/suricata/suricata.yaml",
            "-S", "/rules/test.rules",
            "-l", "/tmp"
        ]
        ok, out = _run(cmd, timeout=120)
        return ValidationResult(ok=ok, engine="suricata", details=out)


def validate_snort2(rule_text: str) -> ValidationResult:
    """
    Snort2 -T로 config + rule 로드 검증.
    - minimal snort.conf 생성 후 include
    """
    with tempfile.TemporaryDirectory() as td:
        rule_path = os.path.join(td, "test.rules")
        conf_path = os.path.join(td, "snort.conf")
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(rule_text.strip() + "\n")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(
                "ipvar HOME_NET any\n"
                "ipvar EXTERNAL_NET any\n"
                "var RULE_PATH /rules\n"
                "include $RULE_PATH/test.rules\n"
            )

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{td}:/rules",
            "linton/docker-snort:latest",
            "snort", "-T", "-c", "/rules/snort.conf"
        ]
        ok, out = _run(cmd, timeout=120)
        return ValidationResult(ok=ok, engine="snort2", details=out)


def validate_snort3(rule_text: str) -> ValidationResult:
    """
    Snort3 -T로 엔진 구성 + rules 로드 검증.
    - snort.lua 기본 경로를 이미지에 내장된 것으로 사용
    - -R로 단일 rules 파일 로드
    """
    with tempfile.TemporaryDirectory() as td:
        rule_path = os.path.join(td, "test.rules")
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(rule_text.strip() + "\n")

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{td}:/rules",
            "ciscotalos/snort3:latest",
            "snort", "-T",
            "-c", "/usr/local/etc/snort/snort.lua",
            "-R", "/rules/test.rules"
        ]
        ok, out = _run(cmd, timeout=120)
        return ValidationResult(ok=ok, engine="snort3", details=out)


def validate_by_engine(engine: str, rule_text: str) -> ValidationResult:
    """
    엔진 문자열을 받아 적절한 validator 실행.
    """
    e = (engine or "").strip().lower()
    if e == "sigma":
        return validate_sigma(rule_text)
    if e == "yara":
        return validate_yara(rule_text)
    if e == "suricata":
        return validate_suricata(rule_text)
    if e == "snort2":
        return validate_snort2(rule_text)
    if e == "snort3":
        return validate_snort3(rule_text)
    return ValidationResult(ok=False, engine=e or "unknown", details="Unknown engine")
