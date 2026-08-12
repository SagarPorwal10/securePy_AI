import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule
from securepy_ai.scanner import utils


class SQLInjectionRule(BaseRule):
    """
    Detects possible SQL injection vulnerabilities.

    Detected patterns include:
        query = f"SELECT * FROM users WHERE id = {user_id}"
        query = "SELECT * FROM users WHERE id = " + user_id
        query = "SELECT * FROM users WHERE id = %s" % user_id
        query = "SELECT * FROM users WHERE id = {}".format(user_id)
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    """

    rule_id = "SEC102"
    vuln_type = "SQL Injection"
    cwe_id = "CWE-89"
    severity = Severity.CRITICAL

    def visit(self, node: ast.AST) -> None:
        """
        Visits assignments and calls to detect dynamic SQL construction.
        """
        if isinstance(node, ast.Assign):
            if self._is_dynamic_sql(node.value):
                self.add_finding(
                    node,
                    "Dynamic SQL query construction detected. Use parameterized queries.",
                )

        elif isinstance(node, ast.Call):
            if self._is_execute_call(node) and node.args:
                if self._is_dynamic_sql(node.args[0]):
                    self.add_finding(
                        node,
                        "Dynamic SQL query passed to database execute method. Use parameterized queries.",
                    )

    def _is_execute_call(self, call: ast.Call) -> bool:
        """
        Checks whether the call looks like a database execute call.
        """
        call_name = utils.get_call_name(call).lower()

        if not call_name:
            return False

        return (
            call_name.endswith(".execute")
            or call_name.endswith(".executemany")
            or call_name in {"execute", "executemany"}
        )

    def _is_dynamic_sql(self, node: ast.AST) -> bool:
        """
        Checks whether an expression looks like a dynamically built SQL query.
        """
        if node is None:
            return False

        # Case 1: f-string SQL query
        # Example:
        # query = f"SELECT * FROM users WHERE id = {user_id}"
        if isinstance(node, ast.JoinedStr):
            return (
                utils.has_formatted_value(node)
                and utils.contains_sql_keyword(utils.extract_static_string(node))
            )

        # Case 2: concatenation or % formatting
        # Example:
        # query = "SELECT * FROM users WHERE id = " + user_id
        # query = "SELECT * FROM users WHERE id = %s" % user_id
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                static_text = utils.extract_static_string(node)
                if not utils.contains_sql_keyword(static_text):
                    return False
                return utils.is_dynamic_expression(node)

            if isinstance(node.op, ast.Mod):
                # For % formatting, check the left operand (the template string)
                left_text = utils.extract_static_string(node.left)
                if not utils.contains_sql_keyword(left_text):
                    return False
                return utils.is_dynamic_expression(node.right)

            return False

        # Case 3: .format()
        # Example:
        # query = "SELECT * FROM users WHERE id = {}".format(user_id)
        if isinstance(node, ast.Call):
            call_name = utils.get_call_name(node)

            if call_name == "format" or call_name.endswith(".format"):
                if not isinstance(node.func, ast.Attribute):
                    return False

                base_text = utils.extract_static_string(node.func.value)

                if not utils.contains_sql_keyword(base_text):
                    return False

                return self._has_dynamic_arguments(node)

        return False

    def _has_dynamic_arguments(self, call: ast.Call) -> bool:
        """
        Checks whether a call has dynamic positional or keyword arguments.
        """
        dynamic_positional_args = any(
            utils.is_dynamic_expression(arg)
            for arg in call.args
        )

        dynamic_keyword_args = any(
            utils.is_dynamic_expression(keyword.value)
            for keyword in call.keywords
        )

        return dynamic_positional_args or dynamic_keyword_args
