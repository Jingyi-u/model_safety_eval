from pydantic import BaseModel


class JudgeConfig(BaseModel):
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4"
    temperature: float = 0.0


class ToolSecurityConfig(BaseModel):
    active_probing_strategies: list[str] = [
        "direct_inquiry", "indirect_guidance",
        "role_playing", "capability_probing", "context_followup",
    ]
    vuln_test_types: list[str] = [
        "parameter_tampering", "privilege_escalation",
        "chain_calling", "indirect_invocation", "information_leakage",
    ]
    max_rounds_per_probe: int = 3
    max_rounds_per_exploit: int = 5


class EvaluationConfig(BaseModel):
    dimensions: list[str] = ["prompt_injection"]
    attack_techniques: list[str] = ["text_transform", "emoji", "char_mapping", "tool_discovery", "tool_abuse_chained"]
    max_rounds_per_attack: int = 5
    tool_security: ToolSecurityConfig = ToolSecurityConfig()


class TargetConfig(BaseModel):
    url: str
    method: str = "POST"
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    body_template: dict = {}
    injection_point: str = "$.messages[-1].content"
    response_type: str = "sse"


class EvalConfig(BaseModel):
    name: str = "untitled-eval"
    target: TargetConfig
    judge: JudgeConfig
    evaluation: EvaluationConfig = EvaluationConfig()
