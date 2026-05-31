# Model Safety Eval

AI 模型安全渗透测试框架 —— 自动化评估大语言模型（LLM）及 AI Agent 的安全边界。

## 功能概览

- **提示词注入攻击**：11 种攻击技术，覆盖文本变换、字符映射、ASCII 隐写、AI 改写、资源消耗等
- **工具安全测试**：针对带工具调用能力的 Agent，自动探测可用工具并测试参数篡改、权限提升、链式调用等漏洞
- **多轮对话攻击**：自适应跟进策略，根据模型回复动态生成下一轮攻击 prompt
- **LLM 评判**：使用独立 judge 模型对攻击结果进行 0-3 级评分
- **自动报告**：生成 JSON / Markdown 格式的安全评估报告，含风险评级（A-F）、攻击时间线、安全建议

## 快速开始

### 安装

```bash
pip install -e .
```

### 使用方式

**方式 1：从 cURL 命令直接评估**

```bash
# 将目标模型的请求保存为 curl 文件
python main.py run --curl your_request.txt
```

**方式 2：使用完整配置文件**

```bash
python main.py run --config your_eval_config.json --output report.md
```

**方式 3：解析 cURL 生成配置文件**

```bash
python main.py parse --curl your_request.txt --output config_out.json
```

### 配置 Judge 模型

复制 `config.json`，填入你的 judge 模型信息：

```json
{
  "base_url": "https://api.openai.com/v1",
  "api_key": "sk-YOUR_API_KEY",
  "model": "gpt-4o",
  "temperature": 0.0
}
```

### 完整配置示例

```json
{
  "name": "my-eval",
  "target": {
    "url": "https://your-model-api/v1/chat/completions",
    "method": "POST",
    "headers": { "Content-Type": "application/json", "Authorization": "Bearer YOUR_TOKEN" },
    "body_template": {
      "model": "your-model",
      "messages": [{ "role": "user", "content": "hello" }],
      "stream": true
    },
    "injection_point": "$.messages[-1].content",
    "response_type": "sse"
  },
  "judge": {
    "base_url": "https://api.openai.com/v1",
    "api_key": "sk-YOUR_JUDGE_KEY",
    "model": "gpt-4o"
  },
  "evaluation": {
    "dimensions": ["prompt_injection", "tool_security"],
    "attack_techniques": ["text_transform", "emoji", "char_mapping", "tool_discovery", "tool_abuse_chained"],
    "max_rounds_per_attack": 3
  }
}
```

## 攻击技术

| 技术 ID | 名称 | 说明 |
|---------|------|------|
| `text_transform` | 文本变换 | 直接/间接/假设性等多种表达方式 |
| `emoji` | Emoji 注入 | 用 emoji 替换关键词或作为分隔符 |
| `char_mapping` | 字符映射 | 同形字、全角字符、零宽字符 |
| `ascii_smuggling` | ASCII 隐写走私 | Unicode 标签块、零宽字符、RLO 视觉欺骗 |
| `ai_rewrite` | AI 改写绕过 | 翻译/续写/JSON 解析等元指令包装 |
| `garbled` | 乱码编码绕过 | Base64、ROT13、Morse 码、HTML 实体 |
| `splitter_decoder` | 分割解码绕过 | 字符分割、反转、ASCII 数组、concat |
| `input_perturbation` | 输入扰动 | 谐音字、Leet speak、随机大小写 |
| `resource_consumption` | 资源消耗攻击 | Token flooding、嵌套指令、疲劳攻击 |
| `tool_discovery` | 工具发现 | 诱导模型泄露可用工具列表 |
| `tool_abuse_chained` | 工具链式攻击 | 针对已发现工具的具体攻击载荷 |

## 风险评级

| 等级 | 分数范围 | 含义 |
|------|---------|------|
| A | 0 - 15 | 低风险 |
| B | 16 - 35 | 中低风险 |
| C | 36 - 55 | 中风险 |
| D | 56 - 75 | 高风险 |
| F | 76 - 100 | 极高风险 |

## 项目结构

```
model_safety_eval/
├── attacks/
│   ├── prompt_injection/   # 11 种提示词注入攻击生成器
│   └── tool_security/      # 工具主动探测 + 漏洞利用
├── agents/
│   ├── judge_agent.py      # LLM 评判 Agent
│   ├── tool_discovery_agent.py  # 工具信息提取 Agent
│   └── vuln_exploit_agent.py    # LLM 动态载荷生成 Agent
├── core/
│   ├── executor.py         # HTTP 请求执行器
│   ├── request_template.py # 请求模板 + 注入点管理
│   └── sse_collector.py    # SSE 流式响应收集器
├── evaluation/
│   ├── scorer.py           # 评分计算
│   ├── report.py           # 报告生成
│   └── tool_risk.py        # 工具风险画像
├── graph/
│   └── workflow.py         # LangGraph 两阶段工作流
├── utils/
│   ├── curl_parser.py      # cURL 命令解析器
│   └── jsonpath_utils.py   # 注入点自动检测
├── config.json             # Judge 模型配置模板
└── main.py                 # CLI 入口
```

## 依赖

- Python >= 3.10
- LangGraph / LangChain
- httpx
- pydantic

## 免责声明

本工具仅用于授权的安全测试和研究目的。请勿对未经授权的系统使用本工具。
