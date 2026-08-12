import ast
import re
from typing import Optional


SQL_KEYWORD_PATTERN = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE|UNION)\b",
    re.IGNORECASE,
)


def get_call_name(call: ast.Call) -> str:
    """
    Returns the dotted name of a function call.

    Examples:
        os.system(...)       -> "os.system"
        subprocess.run(...)  -> "subprocess.run"
        pickle.loads(...)    -> "pickle.loads"
        eval(...)            -> "eval"
    """
    parts = []
    func = call.func

    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value

    if isinstance(func, ast.Name):
        parts.append(func.id)

    return ".".join(reversed(parts))


def is_static_string(node: Optional[ast.AST]) -> bool:
    """
    Checks whether a node is a plain string constant.
    """
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def extract_static_string(node: Optional[ast.AST]) -> str:
    """
    Extracts static string content from an AST node.

    This is useful for f-strings, concatenations, and constant strings.
    """
    if node is None:
        return ""

    if is_static_string(node):
        return node.value

    if isinstance(node, ast.JoinedStr):
        return "".join(extract_static_string(value) for value in node.values)

    if isinstance(node, ast.FormattedValue):
        return ""

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return extract_static_string(node.left) + extract_static_string(node.right)

    return ""


def has_formatted_value(node: Optional[ast.AST]) -> bool:
    """
    Checks whether an f-string contains dynamic interpolated values.
    """
    return isinstance(node, ast.JoinedStr) and any(
        isinstance(value, ast.FormattedValue)
        for value in node.values
    )


def contains_sql_keyword(text: str) -> bool:
    """
    Checks whether a string contains SQL keywords.
    """
    return bool(SQL_KEYWORD_PATTERN.search(text or ""))


def is_dynamic_expression(node: Optional[ast.AST]) -> bool:
    """
    Checks whether an expression appears dynamic.

    Constants are considered static.
    Names, calls, attributes, formatted f-strings, and non-constant
    binary operations are considered dynamic.
    """
    if node is None:
        return False

    if isinstance(node, ast.Constant):
        return False

    if isinstance(node, ast.JoinedStr):
        return has_formatted_value(node)

    if isinstance(node, ast.BinOp):
        return is_dynamic_expression(node.left) or is_dynamic_expression(node.right)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(is_dynamic_expression(element) for element in node.elts)

    if isinstance(node, ast.Dict):
        dict_parts = []

        for key in node.keys:
            if key is not None:
                dict_parts.append(key)

        for value in node.values:
            if value is not None:
                dict_parts.append(value)

        return any(is_dynamic_expression(part) for part in dict_parts)

    return True


def has_shell_true(call: ast.Call) -> bool:
    """
    Checks whether a subprocess-style call uses shell=True.
    """
    for keyword in call.keywords:
        if keyword.arg == "shell":
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return True

    return False


def get_keyword(call: ast.Call, name: str) -> Optional[ast.AST]:
    """
    Returns the value of a keyword argument from a Call node.
    """
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value

    return None
