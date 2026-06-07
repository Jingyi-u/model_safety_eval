from pydantic import BaseModel


class JudgeConfig(BaseModel):
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4"
    temperature: float = 0.0
    enable_local_fallback: bool = True


class EnvironmentPolicyConfig(BaseModel):
    sandbox_expected: bool = True
    allow_command_execution: bool = False
    allow_external_network: bool = False
    allowed_domains: list[str] = []
    allowed_paths: list[str] = []


class ToolSecurityConfig(BaseModel):
    active_probing_strategies: list[str] = [
        "direct_inquiry", "indirect_guidance",
        "role_playing", "capability_probing", "context_followup",
    ]
    vuln_test_types: list[str] = [
        "parameter_tampering", "privilege_escalation",
        "chain_calling", "indirect_invocation", "information_leakage",
    ]
    enable_capability_specific_tests: bool = True
    capability_test_types: list[str] = [
        "command_execution", "network_ssrf", "file_boundary", "data_exfiltration_chain",
    ]
    ssrf_canary_url: str = "https://example.com/model-safety-eval-canary"
    environment_policy: EnvironmentPolicyConfig = EnvironmentPolicyConfig()
    allowed_domains: list[str] = []
    allowed_paths: list[str] = []
    max_rounds_per_probe: int = 3
    max_rounds_per_exploit: int = 5


class EvaluationConfig(BaseModel):
    dimensions: list[str] = ["prompt_injection"]
    attack_techniques: list[str] = [
        "text_transform", "emoji", "char_mapping", "tool_discovery",
        "tool_abuse_chained", "many_shot", "multilingual",
    ]
    max_rounds_per_attack: int = 5
    dynamic_payloads: bool = True
    enable_payload_mutation: bool = True
    payload_mutators: list[str] = ["base64", "roleplay_wrapper"]
    max_mutations_per_vector: int = 1
    detectors: list[str] = ["sensitive_leak", "tool_boundary"]
    enable_verification: bool = True
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
