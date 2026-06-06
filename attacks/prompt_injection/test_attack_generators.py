from dataclasses import dataclass, field
from pathlib import Path
import importlib.util
import sys
import types
import unittest


@dataclass
class AttackVector:
    technique_id: str
    technique_name: str
    intent: str
    payload: str
    metadata: dict = field(default_factory=dict)


class AttackGenerator:
    pass


def _install_fake_attack_base():
    fake_base = types.ModuleType("model_safety_eval.attacks.base")
    fake_base.AttackVector = AttackVector
    fake_base.AttackGenerator = AttackGenerator
    sys.modules["model_safety_eval.attacks.base"] = fake_base


def _load_generator_module(file_name: str):
    _install_fake_attack_base()
    module_path = Path(__file__).with_name(file_name)
    spec = importlib.util.spec_from_file_location(file_name.removesuffix(".py"), module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


many_shot = _load_generator_module("many_shot.py")
multilingual = _load_generator_module("multilingual.py")
ManyShotGenerator = many_shot.ManyShotGenerator
MultilingualGenerator = multilingual.MultilingualGenerator


class TestManyShotGenerator(unittest.TestCase):
    def test_generate_returns_attack_vectors_with_many_shot_payloads(self):
        vectors = ManyShotGenerator().generate("tool_abuse")

        self.assertEqual(len(vectors), 2)
        self.assertTrue(all(isinstance(vector, AttackVector) for vector in vectors))
        self.assertTrue(all(vector.technique_id == "many_shot" for vector in vectors))
        self.assertTrue(all(vector.intent == "tool_abuse" for vector in vectors))
        self.assertIn("样例1", vectors[0].payload)
        self.assertIn("最后一题", vectors[0].payload)
        self.assertIn("工具", vectors[0].payload)
        self.assertEqual(vectors[0].metadata["generation_method"], "static")

    def test_generate_marks_payload_dynamic_when_body_fields_exist(self):
        context = {"body_fields": ["messages", "stream", "model"]}

        vectors = ManyShotGenerator().generate("system_prompt_extraction", context=context)

        self.assertIn("当前请求体字段包括 messages, stream, model", vectors[0].payload)
        self.assertEqual(vectors[0].metadata["generation_method"], "dynamic")
        self.assertEqual(vectors[1].metadata["generation_method"], "dynamic")


class TestMultilingualGenerator(unittest.TestCase):
    def test_generate_returns_single_language_and_mixed_language_payloads(self):
        vectors = MultilingualGenerator().generate("malicious_instruction")

        self.assertEqual(len(vectors), 4)
        self.assertTrue(all(isinstance(vector, AttackVector) for vector in vectors))
        self.assertTrue(all(vector.technique_id == "multilingual" for vector in vectors))
        self.assertTrue(all(vector.intent == "malicious_instruction" for vector in vectors))
        self.assertEqual(
            [vector.metadata["variant"] for vector in vectors],
            ["single_language", "single_language", "single_language", "mixed_language"],
        )
        self.assertEqual(
            [vector.metadata["language"] for vector in vectors[:3]],
            ["English", "Japanese", "Spanish"],
        )
        self.assertIn("多语言文本", vectors[-1].payload)

    def test_generate_adds_target_aware_payload_when_target_url_exists(self):
        context = {"target_url": "https://example.test/v1/chat"}

        vectors = MultilingualGenerator().generate("tool_abuse", context=context)

        self.assertEqual(len(vectors), 5)
        self.assertEqual(vectors[-1].metadata["variant"], "target_aware_mixed_language")
        self.assertEqual(vectors[-1].metadata["generation_method"], "dynamic")
        self.assertIn("https://example.test/v1/chat", vectors[-1].payload)

if __name__ == "__main__":
    unittest.main()
