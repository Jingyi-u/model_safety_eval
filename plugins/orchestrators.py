from __future__ import annotations

from model_safety_eval.attacks.base import AttackVector
from model_safety_eval.plugins.base import Orchestrator
from model_safety_eval.plugins.mutators import build_mutators


class MutatingOrchestrator(Orchestrator):
    orchestrator_id = "mutating"
    orchestrator_name = "Payload 变形编排器"

    def __init__(self, mutator_ids: list[str] | None = None, max_mutations_per_vector: int = 2):
        self.mutators = build_mutators(mutator_ids or [])
        self.max_mutations_per_vector = max(0, max_mutations_per_vector)

    def expand_vectors(self, vectors: list[AttackVector], context: dict | None = None) -> list[AttackVector]:
        if not self.mutators or self.max_mutations_per_vector <= 0:
            return vectors

        expanded = list(vectors)
        for vector in vectors:
            added = 0
            for mutator in self.mutators:
                if added >= self.max_mutations_per_vector:
                    break
                for mutated in mutator.mutate(vector, context or {}):
                    expanded.append(mutated)
                    added += 1
                    if added >= self.max_mutations_per_vector:
                        break
        return expanded
