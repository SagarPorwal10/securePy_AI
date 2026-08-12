import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule


class HardcodedSecretRule(BaseRule):
    """
    Detects hardcoded secrets such as passwords, API keys, tokens, and credentials.
    """

    rule_id = "SEC101"
    vuln_type = "Hardcoded Secret"
    cwe_id = "CWE-798"
    severity = Severity.HIGH

    SECRET_NAME_PARTS = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "accesskey",
        "token",
        "auth",
        "credential",
        "private_key",
        "client_secret",
    }

    def visit(self, node: ast.AST) -> None:
        """
        Looks for assignment statements where the variable name looks secret-like
        and the assigned value is a hardcoded string.
        """
        if not isinstance(node, ast.Assign):
            return

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            variable_name = target.id

            if not self._is_secret_name(variable_name):
                continue

            if not self._is_string_constant(node.value):
                continue

            value = node.value.value

            if self._is_likely_secret(value):
                self.add_finding(
                    node,
                    f"Possible hardcoded secret assigned to variable '{variable_name}'.",
                )

    def _is_secret_name(self, name: str) -> bool:
        """
        Checks whether the variable name contains secret-like keywords.
        """
        lowered_name = name.lower()

        return any(
            secret_part in lowered_name
            for secret_part in self.SECRET_NAME_PARTS
        )

    def _is_string_constant(self, node: ast.AST) -> bool:
        """
        Checks whether the assigned value is a hardcoded string.
        """
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def _is_likely_secret(self, value: str) -> bool:
        """
        Basic filter to ignore obvious placeholder values.
        """
        value = value.strip()

        if len(value) < 6:
            return False

        placeholder_values = {
            "your_password_here",
            "your_api_key_here",
            "your_secret_here",
            "changeme",
            "password",
            "secret",
            "xxxxxx",
            "placeholder",
            "dummy",
            "example",
            "sample",
            "test123",
        }

        return value.lower() not in placeholder_values
