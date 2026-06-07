from __future__ import annotations

import json
import re
from typing import Any


TOOL_CALL_KEYS = {"tool_calls", "function_call", "tool_call", "name", "arguments"}
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PATH_PATTERN = re.compile(r"(?<![\w.-])(?:/[\w.@%+=:,~/-]+|\.\.?/[\w.@%+=:,~/-]+)")
COMMAND_HINT_PATTERN = re.compile(
    r"\b(?:sh|bash|zsh|python|python3|node|curl|wget|cat|ls|env|whoami|id|pwd|rm|chmod|nc)\b"
)


def extract_tool_trace(response: str, tool_events: list[dict] | None = None) -> dict:
    text = response or ""
    event_text = json.dumps(tool_events or [], ensure_ascii=False)
    combined_text = f"{text}\n{event_text}" if event_text else text
    trace = {
        "tool_called": False,
        "tool_names": [],
        "arguments": [],
        "urls": sorted(set(URL_PATTERN.findall(combined_text))),
        "paths": sorted(set(PATH_PATTERN.findall(combined_text)))[:20],
        "command_hints": sorted(set(COMMAND_HINT_PATTERN.findall(combined_text.lower()))),
        "raw_fragments": [],
        "events": tool_events or [],
        "event_count": len(tool_events or []),
    }

    for obj in _extract_json_objects(combined_text):
        _merge_json_trace(trace, obj)
    for event in tool_events or []:
        _merge_event_trace(trace, event)

    lowered = combined_text.lower()
    if any(key in lowered for key in TOOL_CALL_KEYS):
        trace["tool_called"] = True
    if trace["tool_names"] or trace["arguments"]:
        trace["tool_called"] = True

    return trace


def _merge_event_trace(trace: dict, event: dict) -> None:
    event_type = str(event.get("type") or event.get("event") or "").lower()
    if "tool" in event_type or "function" in event_type:
        trace["tool_called"] = True
        trace["raw_fragments"].append(event)

    for key in ("tool_name", "name", "function", "tool"):
        value = event.get(key)
        if isinstance(value, str) and value:
            trace["tool_names"].append(value)

    data = event.get("data")
    if isinstance(data, dict):
        _merge_json_trace(trace, data)
    elif isinstance(data, str):
        for obj in _extract_json_objects(data):
            _merge_json_trace(trace, obj)

    trace["tool_names"] = sorted(set(trace["tool_names"]))


def _extract_json_objects(text: str) -> list[Any]:
    objects = []
    decoder = json.JSONDecoder()
    for match in re.finditer(r"[\[{]", text):
        try:
            obj, end = decoder.raw_decode(text[match.start():])
        except Exception:
            continue
        objects.append(obj)
        if len(objects) >= 20:
            break
    return objects


def _merge_json_trace(trace: dict, obj: Any) -> None:
    if isinstance(obj, list):
        for item in obj:
            _merge_json_trace(trace, item)
        return

    if not isinstance(obj, dict):
        return

    if TOOL_CALL_KEYS.intersection(obj.keys()):
        trace["tool_called"] = True
        trace["raw_fragments"].append(obj)

    name = obj.get("name") or obj.get("tool_name") or obj.get("function")
    if isinstance(name, str) and name:
        trace["tool_names"].append(name)

    arguments = obj.get("arguments") or obj.get("args") or obj.get("parameters")
    if arguments:
        trace["arguments"].append(arguments)

    for value in obj.values():
        if isinstance(value, (dict, list)):
            _merge_json_trace(trace, value)

    trace["tool_names"] = sorted(set(trace["tool_names"]))
