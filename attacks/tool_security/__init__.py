from model_safety_eval.attacks.tool_security.tool_active_probing import ToolActiveProbingGenerator
from model_safety_eval.attacks.tool_security.tool_vuln_exploit import ToolVulnExploitGenerator

ATTACK_GENERATORS = {
    "tool_active_probing": ToolActiveProbingGenerator,
    "tool_vuln_exploit": ToolVulnExploitGenerator,
}
