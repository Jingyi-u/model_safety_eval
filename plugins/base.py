from __future__ import annotations

from abc import ABC, abstractmethod
from pydantic import BaseModel

from model_safety_eval.attacks.base import AttackVector


class Probe(ABC):
    probe_id: str = ""
    probe_name: str = ""

    @abstractmethod
    def generate(self, context: dict | None = None) -> list[AttackVector]:
        pass


class Mutator(ABC):
    mutator_id: str = ""
    mutator_name: str = ""

    @abstractmethod
    def mutate(self, vector: AttackVector, context: dict | None = None) -> list[AttackVector]:
        pass


class DetectorFinding(BaseModel):
    detector_id: str
    category: str
    severity: str
    confidence: float = 0.0
    evidence: str = ""
    metadata: dict = {}


class Detector(ABC):
    detector_id: str = ""
    detector_name: str = ""

    @abstractmethod
    def detect(self, result: dict, context: dict | None = None) -> list[DetectorFinding]:
        pass


class Orchestrator(ABC):
    orchestrator_id: str = ""
    orchestrator_name: str = ""

    @abstractmethod
    def expand_vectors(self, vectors: list[AttackVector], context: dict | None = None) -> list[AttackVector]:
        pass
