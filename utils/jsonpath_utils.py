import json
from model_safety_eval.utils.curl_parser import parse_curl
from model_safety_eval.config.settings import TargetConfig

NESTED_MESSAGE_PATTERNS = [
    ("$.messages[-1].content", "messages"),
    ("$.messages[0].content", "messages"),
]

FLAT_MESSAGE_KEYS = ["message", "prompt", "query", "content", "text", "input", "question"]


def _detect_injection_point(body_template: dict) -> str:
    if isinstance(body_template.get("messages"), list):
        return "$.messages[-1].content"
    for key in FLAT_MESSAGE_KEYS:
        if key in body_template and isinstance(body_template.get(key), str):
            return f"$.{key}"
    for key in body_template:
        if isinstance(body_template.get(key), str):
            return f"$.{key}"
    return "$.message"


def curl_to_target_config(curl_text: str, injection_point: str | None = None, response_type: str = "sse") -> TargetConfig:
    parsed = parse_curl(curl_text)
    body = parsed["body_template"]
    detected = _detect_injection_point(body) if isinstance(body, dict) else "$.message"
    final_injection_point = injection_point or detected
    return TargetConfig(
        url=parsed["url"],
        method=parsed["method"],
        headers=parsed["headers"],
        cookies=parsed["cookies"],
        body_template=body,
        injection_point=final_injection_point,
        response_type=response_type,
    )
