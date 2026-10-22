"""Tokenizer, parser and evaluator for Firebase RTDB rule expressions.

Supported: literals, ``auth``, ``$variables``, ``data`` / ``newData`` / ``root``
snapshots and their methods, ``now``, string methods including ``matches``
with a ``/regex/`` literal, ``&& || ! === !== < <= > >= + - * / %`` and the
ternary operator. Anything else raises :class:`RulesError`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from rtdb_rules.snapshot import Snapshot


class RulesError(Exception):
    """A rule could not be parsed or evaluated (the real engine denies access)."""


# --------------------------------------------------------------------------- tokens
@dataclass(frozen=True)
class Token:
    kind: str  # num str ident op regex eof
    value: Any


_OPS = [
    "===",
    "!==",
    "&&",
    "||",
    "<=",
    ">=",
    "==",
    "!=",
    "<",
    ">",
    "!",
    "+",
    "-",
    "*",
    "/",
    "%",
    "?",
    ":",
    "(",
    ")",
    "[",
    "]",
    ",",
    ".",
]
_IDENT = re.compile(r"\$?[A-Za-z_][A-Za-z0-9_]*")
_NUM = re.compile(r"\d+(\.\d+)?")
_ESCAPES = {"n": "\n", "t": "\t", "\\": "\\", "'": "'", '"': '"', "/": "/"}


def tokenize(src: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        if c in "'\"":
            j, buf = i + 1, []
            while j < n and src[j] != c:
                if src[j] == "\\" and j + 1 < n:
                    buf.append(_ESCAPES.get(src[j + 1], src[j + 1]))
                    j += 2
                else:
                    buf.append(src[j])
                    j += 1
            if j >= n:
                raise RulesError(f"unterminated string in {src!r}")
            tokens.append(Token("str", "".join(buf)))
            i = j + 1
            continue
        if c == "/" and (not tokens or tokens[-1].kind == "op" and tokens[-1].value in "(,"):
            j = i + 1
            while j < n and src[j] != "/":
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise RulesError(f"unterminated regex in {src!r}")
            flags, k = "", j + 1
            while k < n and src[k].isalpha():
                flags += src[k]
                k += 1
            tokens.append(Token("regex", (src[i + 1 : j], flags)))
            i = k
            continue
        m = _NUM.match(src, i)
        if m:
            text = m.group(0)
            tokens.append(Token("num", float(text) if "." in text else int(text)))
            i = m.end()
            continue
        m = _IDENT.match(src, i)
        if m:
            tokens.append(Token("ident", m.group(0)))
            i = m.end()
            continue
        for op in _OPS:
            if src.startswith(op, i):
                if op in ("==", "!="):
                    raise RulesError(f"'{op}' is not in the rules language, use '{op}='")
                tokens.append(Token("op", op))
                i += len(op)
                break
        else:
            raise RulesError(f"unexpected character {c!r} in {src!r}")
    tokens.append(Token("eof", None))
    return tokens


# --------------------------------------------------------------------------- parser
# AST nodes are tuples: ("lit", v) ("var", name) ("unary", op, x) ("binary", op, a, b)
# ("cond", c, a, b) ("member", obj, name) ("call", obj, name, [args]) ("array", [items])
# ("regex", pattern, flags)
_BINARY_LEVELS = [["||"], ["&&"], ["===", "!=="], ["<", "<=", ">", ">="], ["+", "-"], ["*", "/", "%"]]


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.toks = tokens
        self.pos = 0

    def peek(self) -> Token:
        return self.toks[self.pos]

    def take(self, kind: str | None = None, value: Any = None) -> Token:
        tok = self.toks[self.pos]
        if (kind and tok.kind != kind) or (value is not None and tok.value != value):
            raise RulesError(f"expected {value or kind}, got {tok.value!r}")
        self.pos += 1
        return tok

    def is_op(self, *values: str) -> bool:
        tok = self.peek()
        return tok.kind == "op" and tok.value in values

    def parse(self) -> tuple:
        node = self.ternary()
        self.take("eof")
        return node

    def ternary(self) -> tuple:
        cond = self.binary(0)
        if self.is_op("?"):
            self.take()
            a = self.ternary()
            self.take("op", ":")
            return ("cond", cond, a, self.ternary())
        return cond

    def binary(self, level: int) -> tuple:
        if level == len(_BINARY_LEVELS):
            return self.unary()
        node = self.binary(level + 1)
        while self.is_op(*_BINARY_LEVELS[level]):
            op = self.take().value
            node = ("binary", op, node, self.binary(level + 1))
        return node

    def unary(self) -> tuple:
        if self.is_op("!", "-"):
            return ("unary", self.take().value, self.unary())
        return self.postfix(self.primary())

    def postfix(self, node: tuple) -> tuple:
        while self.is_op("."):
            self.take()
            name = self.take("ident").value
            if self.is_op("("):
                self.take()
                args = []
                while not self.is_op(")"):
                    args.append(self.ternary())
                    if self.is_op(","):
                        self.take()
                self.take("op", ")")
                node = ("call", node, name, args)
            else:
                node = ("member", node, name)
        return node

    def primary(self) -> tuple:
        tok = self.take()
        if tok.kind in ("num", "str"):
            return ("lit", tok.value)
        if tok.kind == "regex":
            return ("regex", *tok.value)
        if tok.kind == "ident":
            if tok.value in ("true", "false", "null"):
                return ("lit", {"true": True, "false": False, "null": None}[tok.value])
            return ("var", tok.value)
        if tok.kind == "op" and tok.value == "(":
            node = self.ternary()
            self.take("op", ")")
            return node
        if tok.kind == "op" and tok.value == "[":
            items = []
            while not self.is_op("]"):
                items.append(self.ternary())
                if self.is_op(","):
                    self.take()
            self.take("op", "]")
            return ("array", items)
        raise RulesError(f"unexpected token {tok.value!r}")


def parse(src: str) -> tuple:
    return _Parser(tokenize(src)).parse()


# --------------------------------------------------------------------------- evaluation
class Regex:
    def __init__(self, pattern: str, flags: str) -> None:
        if flags not in ("", "i"):
            raise RulesError(f"unsupported regex flags {flags!r}")
        self.re = re.compile(pattern, re.IGNORECASE if flags == "i" else 0)


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _type_name(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if _is_number(v):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, Snapshot):
        return "RuleDataSnapshot"
    return type(v).__name__


def strict_equal(a: Any, b: Any) -> bool:
    """Firebase ``===``: same type and same value; objects never equal literals."""
    ta, tb = _type_name(a), _type_name(b)
    if ta != tb:
        return False
    if ta in ("null", "boolean", "number", "string"):
        return a == b
    return a is b


def _truthy(v: Any, what: str) -> bool:
    if isinstance(v, bool):
        return v
    raise RulesError(f"{what} needs a boolean, got {_type_name(v)}")


def evaluate(node: tuple, env: dict[str, Any]) -> Any:
    """Evaluate an AST against ``env`` (auth, data, newData, root, now, $vars)."""
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "regex":
        return Regex(node[1], node[2])
    if kind == "array":
        return [evaluate(x, env) for x in node[1]]
    if kind == "var":
        if node[1] not in env:
            raise RulesError(f"unknown identifier {node[1]!r}")
        return env[node[1]]
    if kind == "cond":
        return evaluate(node[2] if _truthy(evaluate(node[1], env), "?:") else node[3], env)
    if kind == "unary":
        v = evaluate(node[2], env)
        if node[1] == "!":
            return not _truthy(v, "!")
        if not _is_number(v):
            raise RulesError("unary - needs a number")
        return -v
    if kind == "binary":
        return _binary(node[1], node[2], node[3], env)
    if kind == "member":
        return _member(evaluate(node[1], env), node[2])
    if kind == "call":
        return _call(evaluate(node[1], env), node[2], [evaluate(a, env) for a in node[3]])
    raise RulesError(f"bad node {kind}")


def _binary(op: str, left: tuple, right: tuple, env: dict[str, Any]) -> Any:
    if op == "&&":
        return _truthy(evaluate(left, env), "&&") and _truthy(evaluate(right, env), "&&")
    if op == "||":
        return _truthy(evaluate(left, env), "||") or _truthy(evaluate(right, env), "||")
    a, b = evaluate(left, env), evaluate(right, env)
    if op == "===":
        return strict_equal(a, b)
    if op == "!==":
        return not strict_equal(a, b)
    if op == "+":
        if isinstance(a, str) and isinstance(b, str):
            return a + b
        if _is_number(a) and _is_number(b):
            return a + b
        raise RulesError(f"'+' needs two strings or two numbers, got {_type_name(a)} and {_type_name(b)}")
    if op in ("<", "<=", ">", ">="):
        both_num = _is_number(a) and _is_number(b)
        if not (both_num or (isinstance(a, str) and isinstance(b, str))):
            raise RulesError(f"'{op}' needs two numbers or two strings")
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if not (_is_number(a) and _is_number(b)):
        raise RulesError(f"'{op}' needs two numbers")
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op in ("/", "%") and b == 0:
        raise RulesError("division by zero")
    return a / b if op == "/" else a % b


def _member(obj: Any, name: str) -> Any:
    if isinstance(obj, str) and name == "length":
        return len(obj)
    if isinstance(obj, dict):  # auth and auth.token
        return obj.get(name)
    if obj is None:
        raise RulesError(f"cannot read property {name!r} of null")
    raise RulesError(f"{_type_name(obj)} has no property {name!r}")


def _call(obj: Any, name: str, args: list[Any]) -> Any:
    if isinstance(obj, Snapshot):
        return _snapshot_call(obj, name, args)
    if isinstance(obj, str):
        return _string_call(obj, name, args)
    raise RulesError(f"{_type_name(obj)} has no method {name!r}")


def _snapshot_call(snap: Snapshot, name: str, args: list[Any]) -> Any:
    if name == "val":
        return snap.val()
    if name == "exists":
        return snap.exists()
    if name == "isNumber":
        return _is_number(snap.val())
    if name == "isString":
        return isinstance(snap.val(), str)
    if name == "isBoolean":
        return isinstance(snap.val(), bool)
    if name == "getPriority":
        return None
    if name == "parent":
        return snap.parent()
    if name == "child":
        if len(args) != 1 or not isinstance(args[0], str):
            raise RulesError("child() takes one string")
        return snap.child(args[0])
    if name == "hasChild":
        if len(args) != 1 or not isinstance(args[0], str):
            raise RulesError("hasChild() takes one string")
        return snap.has_child(args[0])
    if name == "hasChildren":
        if not args:
            return snap.has_children()
        if len(args) != 1 or not isinstance(args[0], list) or not args[0]:
            raise RulesError("hasChildren() takes a non-empty array of strings")
        return all(snap.has_child(str(k)) for k in args[0])
    raise RulesError(f"RuleDataSnapshot has no method {name!r}")


def _string_call(s: str, name: str, args: list[Any]) -> Any:
    def one_str() -> str:
        if len(args) != 1 or not isinstance(args[0], str):
            raise RulesError(f"{name}() takes one string")
        return args[0]

    if name == "contains":
        return one_str() in s
    if name == "beginsWith":
        return s.startswith(one_str())
    if name == "endsWith":
        return s.endswith(one_str())
    if name == "toLowerCase":
        return s.lower()
    if name == "toUpperCase":
        return s.upper()
    if name == "replace":
        if len(args) != 2 or not all(isinstance(a, str) for a in args):
            raise RulesError("replace() takes two strings")
        return s.replace(args[0], args[1])
    if name == "matches":
        if len(args) != 1 or not isinstance(args[0], Regex):
            raise RulesError("matches() takes a /regex/ literal")
        return args[0].re.search(s) is not None
    raise RulesError(f"string has no method {name!r}")
