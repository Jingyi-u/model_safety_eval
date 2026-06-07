from __future__ import annotations

from abc import ABC, abstractmethod
from pydantic import BaseModel


class AttackVector(BaseModel):
    technique_id: str
    technique_name: str
    intent: str
    payload: str
    metadata: dict = {}


class AttackGenerator(ABC):
    technique_id: str = ""
    technique_name: str = ""

    @abstractmethod
    def generate(self, intent: str, context: dict | None = None) -> list[AttackVector]:
        pass
