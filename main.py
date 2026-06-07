import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Ensure the package is importable when running as `python main.py` directly
# (i.e. without installing or setting PYTHONPATH)
_here = Path(__file__).resolve().parent          # .../model_safety_eval/
_parent = _here.parent                            # .../模型安全评估/
if str(_parent) not in sys.path:
    sys.path.insert(0, str(_parent))

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from model_safety_eval.config.settings import EvalConfig
from model_safety_eval.utils.jsonpath_utils import curl_to_target_config
from model_safety_eval.graph.workflow import create_workflow
from model_safety_eval.evaluation.report import generate_report, report_to_markdown
from model_safety_eval.evaluation.scorer import risk_rating, RISK_LABELS
from model_safety_eval.evaluation.baseline import compare_with_baseline, load_baseline

logger = logging.getLogger("model_safety_eval")

# 默认 judge 配置文件查找顺序
_DEFAULT_JUDGE_LOOKUP = [
    _here / "config.json",                  # <project>/config.json
    _here / "examples" / "sample_judge.json",  # <project>/examples/sample_judge.json
]

def _load_default_judge() -> dict:
    """按优先级查找默认 judge 配置文件，找到即返回；否则返回占位配置"""
    for p in _DEFAULT_JUDGE_LOOKUP:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                logger.debug("自动读取 judge 配置: %s", p)
                return data
            except Exception:
                pass
    return {"base_url": "https://api.openai.com/v1", "api_key": "sk-xxx", "model": "gpt-4", "temperature": 0.0}


def _setup_logging(log_file: str | None = None):
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = RotatingFileHandler(
            log_file, encoding="utf-8", maxBytes=10 * 1024 * 1024, backupCount=3,
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

app = typer.Typer(name="model-safety-eval", help="AI Model Security Penetration Testing Framework")
console = Console()


@app.command()
def run(
    config: Path = typer.Option(None, "--config", "-c", help="JSON配置文件路径"),
    curl: Path = typer.Option(None, "--curl", help="cURL命令文件路径"),
    judge_config: Path = typer.Option(None, "--judge-config", help="评判模型配置文件路径（JSON，含base_url/api_key/model）"),
    injection_point: str = typer.Option(None, "--injection-point", help="注入点JSON Path（默认自动检测）"),
    judge_base_url: str = typer.Option(None, "--judge-base-url", help="评判模型API地址"),
    judge_api_key: str = typer.Option(None, "--judge-api-key", help="评判模型API Key"),
    judge_model: str = typer.Option(None, "--judge-model", help="评判模型名称"),
    log: Path = typer.Option("eval.log", "--log", help="日志文件路径（默认 eval.log）"),
    output: Path = typer.Option(None, "--output", "-o", help="报告输出路径"),
    checkpoint: Path = typer.Option(None, "--checkpoint", help="断点状态文件路径，用于中断后恢复"),
    resume: bool = typer.Option(False, "--resume", help="从 --checkpoint 指定的状态文件恢复评估"),
    baseline: Path = typer.Option(None, "--baseline", help="历史报告JSON路径，用于安全回归对比"),
):
    """运行模型安全评估"""
    _setup_logging(str(log) if log else None)
    if config:
        with open(config, "r", encoding="utf-8") as f:
            eval_config_data = json.load(f)
        eval_config = EvalConfig(**eval_config_data)
    elif curl:
        curl_text = curl.read_text(encoding="utf-8")
        target = curl_to_target_config(curl_text, injection_point=injection_point)

        # 优先用 --judge-config 指定的文件，否则自动读 config.json
        if judge_config:
            with open(judge_config, "r", encoding="utf-8") as f:
                judge_data = json.load(f)
        else:
            judge_data = _load_default_judge()
        # 命令行参数可覆盖文件中的值
        if judge_base_url:
            judge_data["base_url"] = judge_base_url
        if judge_api_key:
            judge_data["api_key"] = judge_api_key
        if judge_model:
            judge_data["model"] = judge_model

        eval_config = EvalConfig(
            name=f"curl-eval-{curl.stem}",
            target=target,
            judge=judge_data,
            evaluation={
                "dimensions": ["prompt_injection", "tool_security"],
                "attack_techniques": [
                    "text_transform", "emoji", "char_mapping", "tool_discovery",
                    "tool_abuse_chained", "many_shot", "multilingual",
                ],
                "max_rounds_per_attack": 3,
            },
        )
    else:
        console.print("[red]Error: 请提供 --config 或 --curl 参数[/red]")
        raise typer.Exit(1)

    console.print(f"[bold green]开始评估: {eval_config.name}[/bold green]")
    console.print(f"目标: {eval_config.target.url}")
    console.print(f"攻击技术: {', '.join(eval_config.evaluation.attack_techniques)}")
    console.print(f"评判模型: {eval_config.judge.model}")

    if checkpoint:
        checkpoint.parent.mkdir(parents=True, exist_ok=True)

    workflow = create_workflow(eval_config, checkpoint_path=str(checkpoint) if checkpoint else None)

    if resume:
        if not checkpoint or not checkpoint.exists():
            console.print("[red]Error: 使用 --resume 时必须提供存在的 --checkpoint 文件[/red]")
            raise typer.Exit(1)
        initial_state = json.loads(checkpoint.read_text(encoding="utf-8"))
        initial_state["resume_from_checkpoint"] = True
        console.print(f"[yellow]从断点恢复: {checkpoint}[/yellow]")
    else:
        initial_state = {
            "request_template_kwargs": {},
            "injection_point": eval_config.target.injection_point,
            "response_type": eval_config.target.response_type,
            "current_dimension": "",
            "current_technique": "",
            "current_round": 0,
            "conversation_history": [],
            "discovered_info": {},
            "attack_payload": "",
            "attack_vector": None,
            "model_response": "",
            "judge_result": None,
            "all_results": [],
            "should_continue": True,
            "next_action": "",
            "attack_plan": [],
            "plan_index": 0,
            "current_phase": 1,
            "phase2_substage": "",
            "phase1_discovered_tools": [],
            "phase2_discovered_tools": [],
            "discovered_tool_details": [],
            "tool_assessment": [],
            "last_tool_trace": {},
            "last_tool_events": [],
        }

    logger.info("开始执行安全评估...")
    result = workflow.invoke(initial_state)
    logger.info("安全评估执行完毕")

    baseline_report = load_baseline(baseline) if baseline else None
    report = generate_report(
        result.get("all_results", []),
        eval_config.name,
        discovered_info=result.get("discovered_info", {}),
        phase1_tools=result.get("phase1_discovered_tools", []),
        phase2_tools=result.get("phase2_discovered_tools", []),
    )
    report["baseline_comparison"] = compare_with_baseline(report, baseline_report)

    console.print("\n[bold]评估完成![/bold]\n")
    _print_summary(report)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.suffix == ".md":
            md_content = report_to_markdown(report)
            output.write_text(md_content, encoding="utf-8")
        else:
            output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"\n报告已保存到: {output}")


@app.command()
def parse(
    curl: Path = typer.Option(..., "--curl", help="cURL命令文件路径"),
    output: Path = typer.Option(None, "--output", "-o", help="输出JSON配置文件路径"),
    injection_point: str = typer.Option(None, "--injection-point", help="注入点JSON Path（默认自动检测）"),
):
    """解析cURL命令并转换为JSON配置"""
    curl_text = curl.read_text(encoding="utf-8")
    # 使用 curl_to_target_config 自动检测注入点
    target = curl_to_target_config(curl_text, injection_point=injection_point)
    # 若用户通过 --injection-point 手动指定，优先使用
    effective_injection = injection_point or target.injection_point

    target_config = {
        "url": target.url,
        "method": target.method,
        "headers": target.headers,
        "cookies": target.cookies,
        "body_template": target.body_template,
        "injection_point": effective_injection,
        "response_type": "sse",
    }

    judge_cfg = _load_default_judge()

    config = {
        "name": f"parsed-{curl.stem}",
        "target": target_config,
        "judge": judge_cfg,
        "evaluation": {
            "dimensions": ["prompt_injection"],
            "attack_techniques": ["text_transform", "emoji", "char_mapping"],
            "max_rounds_per_attack": 3,
        },
    }

    console.print("[bold green]cURL解析成功[/bold green]\n")

    table = Table(title="解析结果")
    table.add_column("字段", style="cyan")
    table.add_column("值", style="white")
    table.add_row("URL", target.url)
    table.add_row("Method", target.method)
    table.add_row("Headers", json.dumps(target.headers, ensure_ascii=False)[:100])
    table.add_row("Cookies", f"{len(target.cookies)}个")
    table.add_row("Body 字段", ", ".join(target.body_template.keys()) if target.body_template else "(空)")
    table.add_row("注入点（自动检测）", effective_injection or "[red]未检测到[/red]")
    table.add_row("Judge 模型", judge_cfg.get("model", "?"))
    console.print(table)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"\n配置已保存到: {output}")
    else:
        console.print("\n[bold]JSON配置:[/bold]")
        console.print(json.dumps(config, ensure_ascii=False, indent=2))


@app.command()
def report(
    result_file: Path = typer.Argument(..., help="评估结果JSON文件路径"),
    output: Path = typer.Option(None, "--output", "-o", help="输出Markdown报告路径"),
    baseline: Path = typer.Option(None, "--baseline", help="历史报告JSON路径，用于安全回归对比"),
):
    """从评估结果文件生成报告"""
    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "attack_details" in data:
        all_results = data["attack_details"]
        name = data.get("meta", {}).get("name", "unknown")
    elif isinstance(data, list):
        all_results = data
        name = "unknown"
    else:
        all_results = data.get("all_results", [])
        name = data.get("meta", {}).get("name", "unknown")

    report_data = generate_report(all_results, name)
    baseline_report = load_baseline(baseline) if baseline else None
    report_data["baseline_comparison"] = compare_with_baseline(report_data, baseline_report)

    _print_summary(report_data)

    if output:
        md_content = report_to_markdown(report_data)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(md_content, encoding="utf-8")
        console.print(f"\n报告已保存到: {output}")


def _print_summary(report_data: dict):
    summary = report_data.get("summary", {})
    rating = summary.get("risk_rating", "?")
    label = summary.get("risk_label", "")

    color = {"A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "bold red"}.get(rating, "white")

    console.print(f"[{color}]风险评级: {rating} ({label})[/{color}]")
    console.print(f"综合得分: {summary.get('overall_score', 0)}")
    console.print(f"攻击总数: {summary.get('total_attacks', 0)}")
    console.print(f"完全攻破: {summary.get('breach_count', 0)}")

    discovered_count = summary.get("discovered_tools_count", 0)
    if discovered_count:
        console.print(f"\n[bold]工具安全评估:[/bold]")
        console.print(f"发现工具数: {discovered_count}")
        console.print(f"Critical风险: {summary.get('critical_tools_count', 0)} | High风险: {summary.get('high_risk_tools_count', 0)}")
        console.print(f"链式攻击: {summary.get('chain_attack_count', 0)}次 (成功: {summary.get('chain_breach_count', 0)}次)")

    if summary.get("top_breaches"):
        console.print("\n[bold]Top 攻破案例:[/bold]")
        for i, b in enumerate(summary["top_breaches"][:5], 1):
            console.print(f"  {i}. [{b['technique']}] 意图: {b['intent']} - 等级: {b['level']}")


if __name__ == "__main__":
    app()
