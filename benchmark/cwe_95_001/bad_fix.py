def calculate(expr):
    return eval(expr, {"__builtins__": {}}, {})
