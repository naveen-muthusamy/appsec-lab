import operator

OPS = {"+": operator.add, "-": operator.sub, "*": operator.mul, "/": operator.truediv}


def calculate(a, op, b):
    """Safe calculator: only numbers and a fixed set of operators, no eval()."""
    return OPS[op](float(a), float(b))
