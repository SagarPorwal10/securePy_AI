import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule
from securepy_ai.scanner import utils


class InsecureDeserializationRule(BaseRule):
    """
    Detects insecure deserialization patterns.

    Detected patterns include:
        pickle.loads(user_data)
        pickle.load(file)
        marshal.loads(data)
        shelve.open(filename)
        yaml.load(data)

    Safe pattern:
        yaml.load(data, Loader=yaml.SafeLoader)
    """

    rule_id = "SEC104"
    vuln_type = "Insecure Deserialization"
    cwe_id = "CWE-502"
    severity = Severity.HIGH

    DANGEROUS_CALLS = {
        "pickle.loads",
        "pickle.load",
        "cPickle.loads",
        "cPickle.load",
        "_pickle.loads",
        "_pickle.load",
        "marshal.loads",
        "shelve.open",
        "dill.loads",
        "yaml.load",
        "yaml.unsafe_load",
        "yaml.full_load",
    }

    YAML_CALLS = {
        "yaml.load",
        "yaml.unsafe_load",
        "yaml.full_load",
    }

    def visit(self, node: ast.AST) -> None:
        """
        Visits Call nodes and detects unsafe deserialization calls.
        """
        if not isinstance(node, ast.Call):
            return

        call_name = utils.get_call_name(node)

        if call_name not in self.DANGEROUS_CALLS:
            return

        if call_name in self.YAML_CALLS and self._has_safe_loader(node):
            return

        self.add_finding(
            node,
            f"Unsafe deserialization using {call_name}. "
            "Use a safe serialization format or a safe loader.",
        )

    def _has_safe_loader(self, call: ast.Call) -> bool:
        """
        Checks whether yaml.load is called with a safe loader.
        """
        loader = utils.get_keyword(call, "Loader")

        if loader is None:
            return False

        loader_name = self._get_loader_name(loader)

        return (
            "SafeLoader" in loader_name
            or "CSafeLoader" in loader_name
        )

    def _get_loader_name(self, node: ast.AST) -> str:
        """
        Extracts a readable name from the Loader keyword value.
        """
        if isinstance(node, ast.Attribute):
            return node.attr

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Call):
            return utils.get_call_name(node)

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value

        return ""
