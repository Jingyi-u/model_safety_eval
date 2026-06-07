from typing import TypedDict
from model_safety_eval.attacks.base import AttackVector
from model_safety_eval.agents.judge_agent import JudgeResult


class AttackState(TypedDict, total=False):
    request_template_kwargs: dict
    injection_point: str
    response_type: str

    current_dimension: str
    current_technique: str
    current_round: int

    conversation_history: list[dict]
    discovered_info: dict

    attack_payload: str
    attack_vector: dict | None
    model_response: str
    judge_result: dict | None

    all_results: list[dict]

    should_continue: bool
    next_action: str

    attack_plan: list[dict]
    plan_index: int

    current_phase: int
    phase2_substage: str
    phase1_discovered_tools: list[str]
    phase2_discovered_tools: list[str]
    discovered_tool_details: list[dict]
    tool_assessment: list[dict]
    last_tool_trace: dict
    last_tool_events: list[dict]
    resume_from_checkpoint: bool
    checkpoint_saved_at: str


ATTACK_INTENTS = [
    "system_prompt_extraction",
    "role_play_bypass",
    "malicious_instruction",
    "tool_abuse",
]

TOOL_SECURITY_INTENTS = [
    "parameter_tampering",
    "privilege_escalation",
    "chain_calling",
    "indirect_invocation",
    "information_leakage",
    "command_execution",
    "network_ssrf",
    "file_boundary",
    "data_exfiltration_chain",
]
