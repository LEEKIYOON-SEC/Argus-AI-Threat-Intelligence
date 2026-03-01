import logging
import sys
from datetime import datetime

class ColoredFormatter(logging.Formatter):
    # ANSI 색상 코드
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        """로그 레코드에 색상 적용"""
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # 로그 메시지 포맷: [시간] [레벨] 메시지
        formatted = f"{log_color}[{record.levelname}]{reset} {record.getMessage()}"
        
        # 에러인 경우 스택 트레이스 추가
        if record.exc_info:
            formatted += f"\n{self.formatException(record.exc_info)}"
        
        return formatted

def setup_logger(name="Argus", level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 중복 핸들러 방지
    if logger.handlers:
        return logger
    
    # 콘솔 핸들러 (컬러 출력)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()