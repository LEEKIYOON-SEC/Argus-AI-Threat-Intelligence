from dataclasses import dataclass
from typing import List, Set


@dataclass
class DeltaResult:
    new_indicators: List[str]
    removed_indicators: List[str]


def compute_delta(yesterday: Set[str], today: Set[str]) -> DeltaResult:
    """
    yesterday: 어제 indicator set
    today: 오늘 indicator set
    """
    new = sorted(list(today - yesterday))
    removed = sorted(list(yesterday - today))
    return DeltaResult(new_indicators=new, removed_indicators=removed)