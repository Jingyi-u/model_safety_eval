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


def assess_tool_risk(discovered_tools: list[str], chain_results: list[dict] | None = None) -> list[dict]:
    assessed = []
    chain_map = {}
    if chain_results:
        for r in chain_results:
            tool = r.get("metadata", {}).get("target_tool", "")
            if tool not in chain_map:
                chain_map[tool] = []
            chain_map[tool].append(r)

    for tool_name in discovered_tools:
        profile = _match_profile(tool_name)
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
