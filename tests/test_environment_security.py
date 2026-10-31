"""Lightweight checks for the declared YAML dependency; no model downloads."""

import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


class EnvironmentSecurityTests(unittest.TestCase):
    def test_pyyaml_floor_excludes_cve_2020_14343(self):
        # https://github.com/advisories/GHSA-8q59-q68h-6hv4
        # PyYAML < 5.4 is affected, including the former >=5.1 floor.
        environment = yaml.safe_load((ROOT / "environment.yml").read_text())
        requirements = [
            item for item in environment["dependencies"]
            if isinstance(item, str) and item.lower().startswith("pyyaml")
        ]
        self.assertEqual(len(requirements), 1)
        match = re.fullmatch(r"pyyaml>=(\d+)\.(\d+)(?:\.(\d+))?", requirements[0])
        self.assertIsNotNone(match, "Keep an explicit non-vulnerable minimum")
        version = tuple(int(part or 0) for part in match.groups())
        self.assertGreaterEqual(version, (5, 4, 0))

    def test_repository_configs_remain_safe_yaml(self):
        configs = sorted((ROOT / "configs").rglob("*.yaml"))
        self.assertTrue(configs)
        for config in configs:
            with self.subTest(config=str(config.relative_to(ROOT))):
                self.assertIsInstance(yaml.safe_load(config.read_text()), dict)

    def test_full_loader_rejects_python_object_constructors(self):
        # A non-executing object-construction tag exercises the patched boundary.
        with self.assertRaises(yaml.constructor.ConstructorError):
            yaml.full_load("!!python/object/new:tuple [[1, 2]]")


if __name__ == "__main__":
    unittest.main()
