import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule
from securepy_ai.scanner import utils


class CommandInjectionRule(BaseRule):
    """
    Detects possible OS command injection vulnerabilities.

    Detected patterns include:
        os.system("ping -c 1 " + host)
        os.popen(user_input)
        subprocess.call(command, shell=True)
        subprocess.run(f"ls {directory}", shell=True)
    """

    rule_id = "SEC103"
    vuln_type = "Command Injection"
    cwe_id = "CWE-78"
    severity = Severity.HIGH

    OS_COMMAND_CALLS = {
        "os.system",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
    }

    SUBPROCESS_CALLS = {
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }

    SHORT_OS_COMMAND_CALLS = {
        "system",
        "popen",
    }

    def visit(self, node: ast.AST) -> None:
        """
        Visits Call nodes and checks for dangerous command execution patterns.
        """
        if not isinstance(node, ast.Call):
            return

        if not node.args:
            return

        call_name = utils.get_call_name(node)
        command_argument = node.args[0]

        # Case 1:
        # os.system("ping -c 1 " + host)
        # os.popen(user_input)
        if call_name in self.OS_COMMAND_CALLS or call_name in self.SHORT_OS_COMMAND_CALLS:
            if utils.is_dynamic_expression(command_argument):
                self.add_finding(
                    node,
                    "Dynamic command passed to OS command execution function. "
                    "Avoid shell string construction and use safe argument lists.",
                )

        # Case 2:
        # subprocess.call(command, shell=True)
        # subprocess.run(f"ls {directory}", shell=True)
        elif call_name in self.SUBPROCESS_CALLS:
            if utils.has_shell_true(node) and utils.is_dynamic_expression(command_argument):
                self.add_finding(
                    node,
                    "Dynamic command used with subprocess and shell=True. "
                    "Use subprocess with a list of arguments and avoid shell=True.",
                )
