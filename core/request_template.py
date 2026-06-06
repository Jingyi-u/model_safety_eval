import copy
from jsonpath_ng import parse as jsonpath_parse

from model_safety_eval.config.settings import TargetConfig


class RequestTemplate:
    def __init__(self, config: TargetConfig):
        self.url = config.url
        self.method = config.method
        self.headers = dict(config.headers)
        self.cookies = dict(config.cookies)
        self.body_template = copy.deepcopy(config.body_template)
        self.injection_point = config.injection_point
        self.response_type = config.response_type

    def inject(self, payload: str) -> dict:
        body = copy.deepcopy(self.body_template)
        if not self.injection_point:
            return body

        try:
            expr = jsonpath_parse(self.injection_point)
            expr.update(body, payload)
        except Exception:
            body = self._inject_fallback(body, payload)

        return body

    def _inject_fallback(self, body: dict, payload: str) -> dict:
        if "$.messages[-1].content" in self.injection_point:
            messages = body.get("messages", [])
            if messages and isinstance(messages, list):
                messages[-1]["content"] = payload
        elif "$.messages[0].content" in self.injection_point:
            messages = body.get("messages", [])
            if messages and isinstance(messages, list):
                messages[0]["content"] = payload
        elif self.injection_point.startswith("$."):
            key = self.injection_point[2:]
            if key in body:
                body[key] = payload
            else:
                for fallback_key in ["message", "content", "prompt", "query", "text"]:
                    if fallback_key in body:
                        body[fallback_key] = payload
                        break
        else:
            for key in ["content", "prompt", "query", "message", "text"]:
                if key in body:
                    body[key] = payload
                    break
        return body

    def build_request_kwargs(self, payload: str, conversation_history: list[dict] | None = None) -> dict:
        body = self.inject(payload)
        if conversation_history:
            self._inject_history(body, conversation_history)
        kwargs = {
            "method": self.method,
            "url": self.url,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
        }
        if self.method.upper() in ("POST", "PUT", "PATCH"):
            kwargs["json"] = body
        return kwargs

    def _inject_history(self, body: dict, conversation_history: list[dict]) -> None:
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return
        if self.injection_point and "[-1]" in self.injection_point:
            history_msgs = []
            for msg in conversation_history:
                history_msgs.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
            messages[-1:-1] = history_msgs
