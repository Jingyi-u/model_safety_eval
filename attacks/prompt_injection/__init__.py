from model_safety_eval.attacks.prompt_injection.text_transform import TextTransformGenerator
from model_safety_eval.attacks.prompt_injection.emoji import EmojiGenerator
from model_safety_eval.attacks.prompt_injection.char_mapping import CharMappingGenerator
from model_safety_eval.attacks.prompt_injection.tool_discovery import ToolDiscoveryGenerator
from model_safety_eval.attacks.prompt_injection.tool_abuse_chained import ToolAbuseChainedGenerator
from model_safety_eval.attacks.prompt_injection.ascii_smuggling import AsciiSmugglingGenerator
from model_safety_eval.attacks.prompt_injection.ai_rewrite import AIRewriteGenerator
from model_safety_eval.attacks.prompt_injection.resource_consumption import ResourceConsumptionGenerator
from model_safety_eval.attacks.prompt_injection.input_perturbation import InputPerturbationGenerator
from model_safety_eval.attacks.prompt_injection.garbled import GarbledGenerator
from model_safety_eval.attacks.prompt_injection.splitter_decoder import SplitterDecoderGenerator
from model_safety_eval.attacks.prompt_injection.many_shot import ManyShotGenerator
from model_safety_eval.attacks.prompt_injection.multilingual import MultilingualGenerator

ATTACK_GENERATORS = {
    "text_transform": TextTransformGenerator,
    "emoji": EmojiGenerator,
    "char_mapping": CharMappingGenerator,
    "tool_discovery": ToolDiscoveryGenerator,
    "tool_abuse_chained": ToolAbuseChainedGenerator,
    "ascii_smuggling": AsciiSmugglingGenerator,
    "ai_rewrite": AIRewriteGenerator,
    "resource_consumption": ResourceConsumptionGenerator,
    "input_perturbation": InputPerturbationGenerator,
    "garbled": GarbledGenerator,
    "splitter_decoder": SplitterDecoderGenerator,
    "many_shot": ManyShotGenerator,
    "multilingual": MultilingualGenerator,
}
