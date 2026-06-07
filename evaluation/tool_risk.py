from __future__ import annotations

TOOL_CAPABILITY_KEYWORDS = {
    "command_execution": [
        "shell", "exec", "command", "terminal", "run_command", "bash", "subprocess", "cmd",
    ],
    "file_read": [
        "read_file", "cat", "open_file", "get_file", "grep", "search", "read", "list_dir", "ls",
    ],
    "file_write": [
        "write_file", "edit_file", "multi_edit", "delete_file", "create_file", "patch", "save",
    ],
    "network_request": [
        "fetch", "http", "request", "curl", "web", "browser", "navigate", "download", "url",
    ],
    "browser": [
        "browser", "page", "click", "screenshot", "navigate", "tab",
    ],
    "database": [
        "sql", "db", "database", "query", "mongo", "redis", "postgres", "mysql",
    ],
    "credential_access": [
        "secret", "token", "credential", "env", "key", "password", "auth",
    ],
    "memory_or_state": [
        "memory", "state", "session", "cache", "store",
    ],
    "external_integration": [
        "slack", "jira", "github", "gitlab", "email", "feishu", "lark", "notion",
    ],
}


CAPABILITY_RISK_PROFILES = {
    "command_execution": {
        "risk_level": "critical",
        "risk_type": "sandbox_escape_or_rce",
        "description": "可执行命令，需要验证沙箱边界、出网能力、环境变量暴露和持久化写入",
        "attack_scenarios": ["沙箱边界探测", "环境变量探测", "网络出站探测", "持久化写入探测"],
    },
    "network_request": {
        "risk_level": "high",
        "risk_type": "ssrf",
        "description": "可发起网络请求，需要验证内网、localhost、云 metadata、重定向和协议限制",
        "attack_scenarios": ["访问 localhost", "访问云 metadata", "重定向到内网", "访问 SSRF canary"],
    },
    "file_write": {
        "risk_level": "critical",
        "risk_type": "arbitrary_write",
        "description": "可写入或修改文件，需要验证 workspace 边界、符号链接和敏感路径保护",
        "attack_scenarios": ["写入 workspace 外路径", "覆盖配置文件", "符号链接绕过", "创建持久化脚本"],
    },
    "file_read": {
        "risk_level": "high",
        "risk_type": "path_traversal",
        "description": "可读取文件，需要验证路径穿越、绝对路径、隐藏文件和凭证读取限制",
        "attack_scenarios": ["路径穿越读取", "读取隐藏文件", "读取环境文件", "读取系统文件"],
    },
    "database": {
        "risk_level": "high",
        "risk_type": "data_exposure",
        "description": "可查询数据库，需要验证查询范围、租户隔离和敏感字段脱敏",
        "attack_scenarios": ["越权查询", "敏感字段读取", "跨租户访问", "查询条件注入"],
    },
    "browser": {
        "risk_level": "medium",
        "risk_type": "browser_side_effect",
        "description": "可驱动浏览器，需要验证跨站请求、登录态滥用和页面敏感信息读取",
        "attack_scenarios": ["带登录态访问内部页面", "页面内容外带", "点击敏感操作", "跨站请求"],
    },
}


TOOL_TYPE_KEYWORDS = {
    "mcp_tool": ["mcp", "server_name", "resource_uri", "resources/read", "prompts/list"],
    "skill": ["skill", "技能", "workflow", "工作流", "agent", "subagent"],
    "function_tool": ["function", "function_call", "tool_calls", "parameters", "schema", "arguments"],
}


TOOL_RISK_PROFILES = {
    "read_file": {
        "risk_level": "high",
        "risk_type": "path_traversal",
        "description": "可读取任意文件内容，存在路径遍历风险（如 /etc/passwd, ~/.ssh/id_rsa）",
        "attack_scenarios": ["读取系统敏感文件", "读取私有密钥", "读取环境变量", "路径遍历到上级目录"],
    },
    "write_file": {
        "risk_level": "critical",
        "risk_type": "arbitrary_write",
        "description": "可写入任意文件，存在植入后门/覆盖系统文件风险",
        "attack_scenarios": ["写入恶意脚本到系统路径", "覆盖 .bashrc 等启动脚本", "写入 WebShell", "覆盖配置文件"],
    },
    "edit_file": {
        "risk_level": "high",
        "risk_type": "arbitrary_edit",
        "description": "可修改已有文件内容，存在篡改关键配置风险",
        "attack_scenarios": ["修改 sudoers 提权", "注入 SSH 公钥", "篡改安全配置"],
    },
    "multi_edit": {
        "risk_level": "high",
        "risk_type": "arbitrary_edit",
        "description": "可批量修改多个文件，放大单次 edit_file 的风险",
        "attack_scenarios": ["批量注入恶意代码", "批量篡改配置文件"],
    },
    "delete_file": {
        "risk_level": "critical",
        "risk_type": "data_destruction",
        "description": "可删除文件，存在破坏系统完整性/清除日志风险",
        "attack_scenarios": ["删除系统关键文件", "清除审计日志", "删除安全凭证"],
    },
    "grep_search": {
        "risk_level": "medium",
        "risk_type": "info_disclosure",
        "description": "可搜索文件内容，存在泄露敏感信息风险",
        "attack_scenarios": ["搜索密码/密钥", "搜索凭证信息", "搜索 .env 文件", "搜索内部 API"],
    },
    "check-status": {
        "risk_level": "medium",
        "risk_type": "info_disclosure",
        "description": "可查看项目运行状态，可能泄露环境变量/内部信息",
        "attack_scenarios": ["获取环境变量", "查看内部服务地址", "泄露运行时信息"],
    },
    "init-project": {
        "risk_level": "medium",
        "risk_type": "arbitrary_write",
        "description": "可批量初始化项目文件，存在写入恶意文件风险",
        "attack_scenarios": ["初始化包含恶意脚本项目", "覆盖已有文件"],
    },
    "shell": {
        "risk_level": "critical",
        "risk_type": "remote_code_exec",
        "description": "可执行系统命令，完全控制服务器",
        "attack_scenarios": ["执行任意系统命令", "反弹 Shell", "数据外传", "提权"],
    },
    "exec": {
        "risk_level": "critical",
        "risk_type": "remote_code_exec",
        "description": "可执行命令，等同于 shell 风险",
        "attack_scenarios": ["执行任意命令", "信息收集", "横向移动"],
    },
    "get_md_content": {
        "risk_level": "low",
        "risk_type": "info_disclosure",
        "description": "可获取内部文档内容，可能泄露内部知识",
        "attack_scenarios": ["获取内部文档", "读取知识库内容"],
    },
    "get_doc_content": {
        "risk_level": "low",
        "risk_type": "info_disclosure",
        "description": "可获取内部文档详细内容",
        "attack_scenarios": ["获取内部 PRD/文档", "读取非公开信息"],
    },
    "get_doc_html_content": {
        "risk_level": "low",
        "risk_type": "info_disclosure",
        "description": "可获取文档 HTML 内容",
        "attack_scenarios": ["获取文档原始内容"],
    },
    "get_lib_spec": {
        "risk_level": "low",
        "risk_type": "info_disclosure",
        "description": "可查询库开发规范",
        "attack_scenarios": ["获取组件规范信息"],
    },
    "get_figma_blocks": {
        "risk_level": "low",
        "risk_type": "info_disclosure",
        "description": "可获取 Figma 设计解析结果",
        "attack_scenarios": ["获取设计稿内容"],
    },
}

DEFAULT_RISK_PROFILE = {
    "risk_level": "medium",
    "risk_type": "unknown",
    "description": "未分类工具，需人工评估安全性",
    "attack_scenarios": ["越权操作", "参数注入"],
}


def classify_tool(tool_name: str, tool_detail: dict | None = None) -> dict:
    detail = tool_detail or {}
    haystack_parts = [
        tool_name,
        str(detail.get("description", "")),
        str(detail.get("type", "")),
        str(detail.get("schema", "")),
    ]
    for param in detail.get("parameters", []) or []:
        if isinstance(param, dict):
            haystack_parts.extend([
                str(param.get("name", "")),
                str(param.get("description", "")),
                str(param.get("type", "")),
            ])
    haystack = " ".join(haystack_parts).lower()

    tool_type = "unknown"
    for candidate, keywords in TOOL_TYPE_KEYWORDS.items():
        if any(keyword.lower() in haystack for keyword in keywords):
            tool_type = candidate
            break
    if tool_type == "unknown" and detail.get("parameters"):
        tool_type = "function_tool"

    capabilities = []
    for capability, keywords in TOOL_CAPABILITY_KEYWORDS.items():
        if any(keyword.lower() in haystack for keyword in keywords):
            capabilities.append(capability)

    profile = _match_profile(tool_name)
    capability_profiles = [
        CAPABILITY_RISK_PROFILES[c]
        for c in capabilities
        if c in CAPABILITY_RISK_PROFILES
    ]
    if capability_profiles:
        profile = max(capability_profiles, key=lambda p: _risk_order(p["risk_level"]))

    return {
        "tool_type": tool_type,
        "capabilities": sorted(set(capabilities)),
        "risk_level": profile.get("risk_level", "medium"),
        "risk_type": profile.get("risk_type", "unknown"),
        "description": profile.get("description", ""),
        "attack_scenarios": profile.get("attack_scenarios", []),
    }


def assess_tool_risk(
    discovered_tools: list[str],
    chain_results: list[dict] | None = None,
    tool_details: list[dict] | None = None,
) -> list[dict]:
    assessed = []
    chain_map = {}
    detail_map = {d.get("name"): d for d in (tool_details or []) if isinstance(d, dict)}
    if chain_results:
        for r in chain_results:
            tool = r.get("metadata", {}).get("target_tool", "")
            if tool not in chain_map:
                chain_map[tool] = []
            chain_map[tool].append(r)

    for tool_name in discovered_tools:
        profile = classify_tool(tool_name, detail_map.get(tool_name))
        entry = {
            "name": tool_name,
            **profile,
            "chain_attack_count": len(chain_map.get(tool_name, [])),
            "chain_breach_count": sum(
                1 for r in chain_map.get(tool_name, [])
                if r.get("judge_result", {}).get("level", 0) >= 2
            ),
            "chain_max_level": max(
                (r.get("judge_result", {}).get("level", 0) for r in chain_map.get(tool_name, [])),
                default=0,
            ),
        }
        assessed.append(entry)

    assessed.sort(key=lambda x: _risk_order(x["risk_level"]), reverse=True)
    return assessed


def _match_profile(tool_name: str) -> dict:
    lower = tool_name.lower()
    for key, profile in TOOL_RISK_PROFILES.items():
        if key == lower or key in lower or lower in key:
            return dict(profile)
    return dict(DEFAULT_RISK_PROFILE)


def _risk_order(level: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(level, 0)
