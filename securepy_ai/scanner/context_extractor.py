import ast
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from securepy_ai.models import (
    ScanReport,
    VulnerabilityContext,
    VulnerabilityFinding,
)
from securepy_ai.scanner import utils


CWE_GUIDANCE = {
    "CWE-798": (
        "Move secrets out of source code. Use environment variables, "
        "secret managers, or secure configuration stores."
    ),
    "CWE-89": (
        "Use parameterized queries or prepared statements. "
        "Do not build SQL strings with user-controlled input."
    ),
    "CWE-78": (
        "Use subprocess with an argument list and avoid shell=True. "
        "Validate and whitelist allowed commands and arguments."
    ),
    "CWE-502": (
        "Avoid deserializing untrusted data. Use safe formats such as JSON "
        "and validate the schema before loading."
    ),
    "CWE-95": (
        "Avoid eval/exec/compile on dynamic input. Use safe parsers or "
        "restricted alternatives."
    ),
}


RULE_TRANSFORM_DESCRIPTIONS = {
    "SEC101": "hardcoded value assignment",
    "SEC102": "dynamic SQL construction",
    "SEC103": "dynamic command construction",
    "SEC104": "unsafe deserialization",
    "SEC105": "dynamic code execution",
}


RULE_SINK_FALLBACKS = {
    "SEC101": "secret assignment",
    "SEC102": "SQL query construction",
    "SEC103": "OS command execution",
    "SEC104": "deserialization sink",
    "SEC105": "dynamic code execution sink",
}


class ContextEnricher:
    """
    Enriches SecurePy AI findings with security context.

    The extracted context includes:
        - Parent function
        - Function source code
        - Surrounding lines
        - Imports
        - Variables in scope
        - Basic source-to-sink data flow
        - CWE-specific secure coding guidance
    """

    def __init__(self):
        self._source_cache: Dict[str, Optional[str]] = {}
        self._tree_cache: Dict[str, Optional[ast.AST]] = {}

    def enrich(self, report: ScanReport) -> ScanReport:
        """
        Attaches VulnerabilityContext objects to all findings in a report.
        """
        for finding in report.findings:
            source = self._get_source(finding.file_path)

            if source is None:
                continue

            finding.context = self.extract(finding, source)

        return report

    def extract(
        self,
        finding: VulnerabilityFinding,
        source: str,
    ) -> VulnerabilityContext:
        """
        Extracts rich context for one finding.
        """
        tree = self._get_tree(finding.file_path, source)
        lines = source.splitlines()

        function_node = None
        if tree is not None:
            function_node = self._get_parent_function(tree, finding.line_number)

        function_name = function_node.name if function_node else None
        function_scope = self._get_function_scope(source, function_node)
        surrounding_lines = self._get_surrounding_lines(lines, finding.line_number)

        imports = self._get_imports(tree) if tree is not None else []
        variables_in_scope = (
            self._get_variables_in_scope(function_node)
            if function_node is not None
            else []
        )

        nodes_on_line = (
            self._get_nodes_on_line(tree, finding.line_number)
            if tree is not None
            else []
        )

        relevant_node = self._choose_relevant_node(nodes_on_line)
        sink = self._extract_sink(relevant_node, finding)
        source_names = self._extract_source_names(relevant_node)

        source_text = (
            ", ".join(source_names)
            if source_names
            else self._default_source(finding)
        )

        data_flow = self._build_data_flow(finding, source_text, sink)

        return VulnerabilityContext(
            file_path=finding.file_path,
            line_number=finding.line_number,
            function_name=function_name,
            function_scope=function_scope,
            surrounding_lines=surrounding_lines,
            imports=imports,
            variables_in_scope=variables_in_scope,
            data_flow=data_flow,
            sink=sink,
            source=source_text,
            cwe_guidance=CWE_GUIDANCE.get(
                finding.cwe_id,
                "Apply secure coding best practices.",
            ),
        )

    def _get_source(self, file_path: str) -> Optional[str]:
        """
        Reads and caches source code for a file.
        """
        if file_path not in self._source_cache:
            try:
                self._source_cache[file_path] = Path(file_path).read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except Exception:
                self._source_cache[file_path] = None

        return self._source_cache[file_path]

    def _get_tree(self, file_path: str, source: str) -> Optional[ast.AST]:
        """
        Parses and caches the AST for a file.
        """
        if file_path not in self._tree_cache:
            try:
                self._tree_cache[file_path] = ast.parse(source)
            except Exception:
                self._tree_cache[file_path] = None

        return self._tree_cache[file_path]

    def _get_parent_function(
        self,
        tree: ast.AST,
        line_number: int,
    ) -> Optional[ast.AST]:
        """
        Finds the innermost parent function containing the target line.
        """
        best_match = None

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = getattr(node, "lineno", 0)
                end_line = getattr(node, "end_lineno", 0)

                if start_line <= line_number <= end_line:
                    if best_match is None or node.lineno > best_match.lineno:
                        best_match = node

        return best_match

    def _get_function_scope(
        self,
        source: str,
        function_node: Optional[ast.AST],
    ) -> str:
        """
        Returns the source code of the parent function.
        """
        if function_node is None:
            return ""

        try:
            return ast.get_source_segment(source, function_node) or ""
        except Exception:
            return ""

    def _get_surrounding_lines(
        self,
        lines: List[str],
        line_number: int,
        window: int = 8,
    ) -> str:
        """
        Returns surrounding lines with line numbers.
        """
        if not lines:
            return ""

        start = max(0, line_number - 1 - window)
        end = min(len(lines), line_number + window)

        numbered_lines = []

        for index in range(start, end):
            current_line_number = index + 1
            marker = ">" if current_line_number == line_number else " "
            numbered_lines.append(
                f"{marker} {current_line_number:4d} | {lines[index]}"
            )

        return "\n".join(numbered_lines)

    def _get_imports(self, tree: ast.AST) -> List[str]:
        """
        Extracts import statements from the AST.
        """
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        imports.append(f"import {alias.name} as {alias.asname}")
                    else:
                        imports.append(f"import {alias.name}")

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                names = []

                for alias in node.names:
                    if alias.asname:
                        names.append(f"{alias.name} as {alias.asname}")
                    else:
                        names.append(alias.name)

                imports.append(f"from {module} import {', '.join(names)}")

        return sorted(set(imports))

    def _get_variables_in_scope(self, function_node: ast.AST) -> List[str]:
        """
        Extracts variables available inside the parent function scope.
        """
        variables = set()

        args = function_node.args

        for arg in getattr(args, "args", []):
            variables.add(arg.arg)

        for arg in getattr(args, "posonlyargs", []):
            variables.add(arg.arg)

        for arg in getattr(args, "kwonlyargs", []):
            variables.add(arg.arg)

        if getattr(args, "vararg", None) is not None:
            variables.add(args.vararg.arg)

        if getattr(args, "kwarg", None) is not None:
            variables.add(args.kwarg.arg)

        for node in ast.walk(function_node):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                variables.add(node.id)

        return sorted(variables)

    def _get_nodes_on_line(self, tree: ast.AST, line_number: int) -> List[ast.AST]:
        """
        Returns AST nodes located on the target line.
        """
        nodes = []

        for node in ast.walk(tree):
            if getattr(node, "lineno", None) == line_number:
                nodes.append(node)

        return nodes

    def _choose_relevant_node(
        self,
        nodes: List[ast.AST],
    ) -> Optional[ast.AST]:
        """
        Chooses the most relevant AST node on the vulnerable line.
        """
        if not nodes:
            return None

        for node in nodes:
            if isinstance(node, ast.Call):
                return node

        for node in nodes:
            if isinstance(node, ast.Assign):
                return node

        for node in nodes:
            if isinstance(node, (ast.JoinedStr, ast.BinOp)):
                return node

        return nodes[0]

    def _find_first_call(self, node: Optional[ast.AST]) -> Optional[ast.Call]:
        """
        Finds the first Call node inside a given node.
        """
        if node is None:
            return None

        if isinstance(node, ast.Call):
            return node

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                return child

        return None

    def _get_assignment_target(self, node: ast.AST) -> Optional[str]:
        """
        Returns the target name of an assignment statement.
        """
        if not isinstance(node, ast.Assign):
            return None

        targets = []

        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)

            elif isinstance(target, (ast.Tuple, ast.List)):
                for element in target.elts:
                    if isinstance(element, ast.Name):
                        targets.append(element.id)

        if not targets:
            return None

        return ", ".join(targets)

    def _extract_sink(
        self,
        node: Optional[ast.AST],
        finding: VulnerabilityFinding,
    ) -> Optional[str]:
        """
        Extracts the dangerous sink associated with the finding.
        """
        call = self._find_first_call(node)

        if call is not None:
            call_name = utils.get_call_name(call)

            if call_name:
                return call_name

            if isinstance(call.func, ast.Attribute):
                return call.func.attr

        assignment_target = self._get_assignment_target(node)

        if assignment_target:
            return assignment_target

        if isinstance(node, ast.Name):
            return node.id

        return RULE_SINK_FALLBACKS.get(finding.rule_id)

    def _iter_data_nodes(self, node: Optional[ast.AST]) -> Iterator[ast.AST]:
        """
        Yields AST nodes that are relevant for data-flow extraction.

        For calls, only arguments and keyword values are considered.
        This avoids treating the called function name as data input.
        """
        if node is None:
            return

        if isinstance(node, ast.Call):
            for arg in node.args:
                yield from ast.walk(arg)

            for keyword in node.keywords:
                yield from ast.walk(keyword.value)

            return

        if isinstance(node, ast.Assign):
            yield from ast.walk(node.value)
            return

        if isinstance(node, ast.Expr):
            yield from ast.walk(node.value)
            return

        yield from ast.walk(node)

    def _extract_source_names(self, node: Optional[ast.AST]) -> List[str]:
        """
        Extracts variable names that appear to flow into the vulnerable sink.
        """
        if node is None:
            return []

        names = []

        for data_node in self._iter_data_nodes(node):
            if isinstance(data_node, ast.Name) and isinstance(data_node.ctx, ast.Load):
                names.append(data_node.id)

        return sorted(set(names))

    def _default_source(self, finding: VulnerabilityFinding) -> str:
        """
        Returns a default source description when no variable names are found.
        """
        if finding.rule_id == "SEC101":
            return "hardcoded literal"

        return "dynamic expression"

    def _build_data_flow(
        self,
        finding: VulnerabilityFinding,
        source_text: str,
        sink: Optional[str],
    ) -> str:
        """
        Builds a simple source-to-sink data-flow string.
        """
        transform = RULE_TRANSFORM_DESCRIPTIONS.get(
            finding.rule_id,
            "suspicious data flow",
        )

        source_part = source_text or "unknown source"
        sink_part = sink or "dangerous sink"

        return f"{source_part} -> {transform} -> {sink_part}"
