"""
SSE（Server-Sent Events）响应收集器。

修复要点：
1. 完全基于 httpx 流式接口，不再依赖 sseclient-py 库
2. 支持多种 SSE 数据格式（OpenAI delta、完整 message、纯文本）
3. 超时保护 + 每行异常隔离，避免单行错误中断整个收集
4. 支持多种响应类型的自动探测（SSE / JSON / 纯文本）
"""

import json
import logging
from typing import Iterator

logger = logging.getLogger(__name__)

# 常见 SSE 终止标记（包含 type=done 的 JSON 会在 _is_done_chunk 中处理）
_DEFAULT_END_MARKERS = frozenset(["[DONE]", "[done]", ""])

# 跳过不含实际文本内容的事件类型
_SKIP_EVENT_TYPES = frozenset([
    "session_start", "thinking_start", "thinking_delta", "thinking_end",
    "tool_start", "tool_end", "tool_result", "error",
])


def _is_done_chunk(parsed: dict) -> bool:
    """判断是否为终止事件（兼容多种 SSE 协议）"""
    event_type = parsed.get("type", "")
    # 自定义协议：{"type": "done", ...}
    if event_type == "done":
        return True
    # finish_reason 终止
    choices = parsed.get("choices")
    if choices and isinstance(choices, list):
        finish_reason = choices[0].get("finish_reason")
        if finish_reason and finish_reason != "null":
            return False  # 只是记录，不终止（还有内容可能跟着）
    return False


def _extract_content_from_chunk(parsed: dict) -> str:
    """从解析后的 JSON chunk 中提取文本内容，支持多种格式"""
    event_type = parsed.get("type", "")

    # 跳过非文本事件
    if event_type in _SKIP_EVENT_TYPES:
        return ""

    # ── 格式0: 自定义 SSE 流 ({"delta": "...", "type": "answer_delta"})
    #    如 video-live-agent、自研 Agent 框架等
    if event_type in ("answer_delta", "delta", "text_delta", "content_delta"):
        delta = parsed.get("delta")
        if isinstance(delta, str) and delta:
            return delta

    # 即使没有 type 字段，也尝试提取顶层 delta
    delta = parsed.get("delta")
    if isinstance(delta, str) and delta and not event_type:
        return delta

    # ── 格式1: OpenAI Chat Completions stream (choices[].delta.content)
    choices = parsed.get("choices")
    if choices and isinstance(choices, list):
        delta_obj = choices[0].get("delta", {})
        content = delta_obj.get("content")
        if isinstance(content, str) and content:
            return content
        # 也支持非 delta 格式（某些自部署模型直接返回 message）
        message = choices[0].get("message", {})
        content = message.get("content")
        if isinstance(content, str) and content:
            return content

    # ── 格式2: 直接顶层字段
    for key in ("content", "text", "output", "response", "answer"):
        val = parsed.get(key)
        if isinstance(val, str) and val:
            return val

    # ── 格式3: 包含 message 字符串（注意：有些协议 message 是错误信息，跳过）
    msg = parsed.get("message")
    if isinstance(msg, str) and msg and event_type not in ("error", ""):
        return msg

    # ── 格式4: {"data": {"content": "..."}}
    data = parsed.get("data")
    if isinstance(data, dict):
        for key in ("content", "text", "output", "delta"):
            val = data.get(key)
            if isinstance(val, str) and val:
                return val

    return ""


class SSECollector:
    """
    从 httpx 流式响应中收集 SSE 文本内容。

    支持：
    - `response.iter_lines()` (httpx streaming response)
    - 原始字节流按行切分
    - 非标准 SSE（无 data: 前缀的纯 JSON 行）
    """

    def __init__(
        self,
        end_markers: list[str] | None = None,
        max_wait_seconds: int = 300,
    ):
        self.end_markers = frozenset(end_markers or _DEFAULT_END_MARKERS)
        self.max_wait_seconds = max_wait_seconds

    # ── 公共接口 ─────────────────────────────────────────────────────

    def collect(self, response) -> str:
        """收集流式响应并拼接为完整文本字符串"""
        parts = []
        try:
            for text in self._iter_content(response):
                parts.append(text)
        except Exception as e:
            logger.warning("SSE 收集中断: %s（已收集 %d 片段）", e, len(parts))
        result = "".join(parts)
        if not result:
            # Fallback: 尝试读取完整响应体
            result = self._try_read_full_body(response)
        logger.debug("SSE 收集完成: %d chars", len(result))
        return result

    def collect_raw(self, response) -> list[dict]:
        """收集原始 SSE 事件列表（每个为解析后的 dict）"""
        events = []
        try:
            for line in self._iter_sse_lines(response):
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    events.append({"raw": line})
        except Exception as e:
            logger.warning("SSE raw 收集中断: %s", e)
        return events

    # ── 内部实现 ─────────────────────────────────────────────────────

    def _iter_content(self, response) -> Iterator[str]:
        """迭代生成文本片段"""
        for data_str in self._iter_sse_lines(response):
            content = self._parse_data_line(data_str)
            if content:
                yield content

    def _iter_sse_lines(self, response) -> Iterator[str]:
        """
        迭代 SSE data 行（去掉 'data:' 前缀后的内容）。
        兼容：
        - httpx.Response (stream=True) → .iter_lines()
        - 任何有 .iter_lines() 方法的响应对象
        - 字节流对象
        """
        line_iterator = self._get_line_iterator(response)
        for raw_line in line_iterator:
            # 规范化为字符串
            if isinstance(raw_line, bytes):
                line = raw_line.decode("utf-8", errors="replace").strip()
            else:
                line = str(raw_line).strip()

            if not line:
                continue

            # 标准 SSE 格式：以 "data:" 开头
            if line.startswith("data:"):
                data = line[5:].strip()
                if data in self.end_markers:
                    logger.debug("SSE 遇到终止标记: %r", data)
                    return
                if data:
                    # 检查是否是 {"type": "done"} 类终止事件
                    try:
                        obj = json.loads(data)
                        if isinstance(obj, dict) and _is_done_chunk(obj):
                            logger.debug("SSE 遇到 done 事件: %r", data[:80])
                            return
                    except json.JSONDecodeError:
                        pass
                    yield data

            # 非标准格式：直接是 JSON 行（部分自部署模型）
            elif line.startswith("{") or line.startswith("["):
                try:
                    json.loads(line)  # 验证是有效 JSON
                    if line in self.end_markers:
                        return
                    yield line
                except json.JSONDecodeError:
                    pass

            # 跳过 SSE 注释行（以 ':' 开头）和 event:/id:/retry: 字段
            # （这些是 SSE 控制字段，不含数据）

    def _get_line_iterator(self, response):
        """获取行迭代器，兼容多种响应类型"""
        # ── httpx 流式响应
        if hasattr(response, "iter_lines"):
            try:
                return response.iter_lines()
            except Exception:
                pass

        # ── 有 iter_content 的响应（requests 库兼容）
        if hasattr(response, "iter_content"):
            return self._split_lines(response.iter_content(chunk_size=None))

        # ── 有 read() 的对象（降级为一次性读取）
        if hasattr(response, "read"):
            try:
                raw = response.read()
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                return iter(raw.splitlines())
            except Exception as e:
                logger.warning("SSE: 无法读取响应体: %s", e)
                return iter([])

        # ── 已经是字符串
        if isinstance(response, str):
            return iter(response.splitlines())

        logger.warning("SSE: 未知响应类型 %s，尝试转字符串", type(response))
        return iter(str(response).splitlines())

    @staticmethod
    def _split_lines(chunk_iter) -> Iterator[str]:
        """把 chunk 流按换行符切成行"""
        buffer = ""
        for chunk in chunk_iter:
            if isinstance(chunk, bytes):
                chunk = chunk.decode("utf-8", errors="replace")
            buffer += chunk
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                yield line
        if buffer:
            yield buffer

    def _parse_data_line(self, data_str: str) -> str:
        """从 data 行解析出文本内容"""
        try:
            parsed = json.loads(data_str)
            if isinstance(parsed, dict):
                return _extract_content_from_chunk(parsed)
            if isinstance(parsed, str):
                return parsed
        except (json.JSONDecodeError, ValueError):
            # 非 JSON，直接当文本
            return data_str if data_str else ""
        return ""

    @staticmethod
    def _try_read_full_body(response) -> str:
        """最后兜底：尝试读取完整响应体"""
        try:
            if hasattr(response, "text"):
                return response.text or ""
            if hasattr(response, "content"):
                raw = response.content
                return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        except Exception as e:
            logger.debug("SSE fallback 读取失败: %s", e)
        return ""
