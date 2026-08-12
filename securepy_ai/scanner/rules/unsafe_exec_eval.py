import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule
from securepy_ai.scanner import utils


class UnsafeExecEvalRule(BaseRule):
    """
    Detects unsafe dynamic code execution.

    Detected patterns include:
        eval(user_input)
        exec(user_code)
        compile(user_code, filename, mode)
    """

    rule_id = "SEC105"
    vuln_type = "Unsafe Dynamic Execution"
    cwe_id = "CWE-95"
    severity = Severity.HIGH

    DANGEROUS_CALLS = {
        "eval",
        "exec",
        "compile",
    }

    def visit(self, node: ast.AST) -> None:
        """
        Visits Call nodes and detects eval/exec/compile usage.
        """
        if not isinstance(node, ast.Call):
            return

        if not node.args:
            return

        call_name = utils.get_call_name(node)

        if call_name not in self.DANGEROUS_CALLS:
            return

        first_argument = node.args[0]

        if utils.is_dynamic_expression(first_argument):
            self.add_finding(
                node,
                f"Dynamic code execution using {call_name}(). "
                "Avoid executing untrusted or dynamically constructed code.",
            )
