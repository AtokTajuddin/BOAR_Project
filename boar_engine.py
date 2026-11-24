"""Rule-driven static memory-safety analysis for BOAR.

The engine reports *potential* issues only. It does not execute the target and
it does not prove exploitability. Rules live in ``boar_rules.json`` and use a
small, Nuclei-style matcher schema so the rule set can grow without editing the
engine.

Supported matchers:
    unsafe_call, unbounded_copy, format_copy, scanf_width, bounded_copy,
    format_string, variable_size_alloc, alloc_arithmetic, double_free,
    use_after_free, bounded_string_copy, input_read_length, sizeof_pointer,
    stack_return
"""

import bisect
import json
import os
import re
from datetime import datetime
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".ino")
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "build", "dist", "vendor", "__pycache__"}

MATCHERS = {}

_TYPE_PREFIX_RE = re.compile(
    r"\b(?:void|int|char|short|long|float|double|size_t|ssize_t|ptrdiff_t|"
    r"unsigned|signed|struct|enum|union|const|static|inline|extern|_Bool|bool|"
    r"wchar_t|u?int(?:8|16|32|64)_t|FILE|va_list)\s+\**\s*$"
)
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_STRING_ONLY_RE = re.compile(
    r'^(?:\s*(?:u8|u|U|L)?"(?:\\.|[^"\\])*"\s*)+$', re.S
)
_STRING_TOKEN_RE = re.compile(r'(?:u8|u|U|L)?"((?:\\.|[^"\\])*)"', re.S)
_CONVERSION_RE = re.compile(
    r"%(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|L|j|z|t)?([diouxXeEfFgGaAcspn\[%])"
)
_SCANF_CONV_RE = re.compile(
    r"%(\*)?(\d+)?(?:hh|h|ll|l|L|j|z|t)?(\[(?:\^?\]?[^\]]*)\]|[diouxXeEfFgGaAcspn%])"
)

_ELEM_BYTES = {
    "char": 1,
    "unsigned char": 1,
    "signed char": 1,
    "int8_t": 1,
    "uint8_t": 1,
    "short": 2,
    "unsigned short": 2,
    "signed short": 2,
    "int16_t": 2,
    "uint16_t": 2,
    "int": 4,
    "unsigned int": 4,
    "signed int": 4,
    "unsigned": 4,
    "signed": 4,
    "int32_t": 4,
    "uint32_t": 4,
    "wchar_t": 4,
    "long long": 8,
    "unsigned long long": 8,
    "signed long long": 8,
    "int64_t": 8,
    "uint64_t": 8,
}

_BUFFER_DECL_RE = re.compile(
    r"\b(?P<storage>(?:(?:static|const|volatile|register)\s+)*)"
    r"(?P<type>"
    r"(?:unsigned|signed)\s+long\s+long|"
    r"(?:unsigned|signed)\s+(?:char|short|int)|"
    r"long\s+long|char|short|int|wchar_t|"
    r"u?int(?:8|16|32|64)_t"
    r")\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<size>[^\]\n;]+?)\s*\]"
)

_DEFINE_CONST_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+([^\n]+)",
    re.M,
)
_TYPED_CONST_RE = re.compile(
    r"\b(?:static\s+)?const\s+(?:unsigned\s+|signed\s+)?"
    r"(?:size_t|ssize_t|int|long|short|u?int(?:8|16|32|64)_t)\s+"
    r"([A-Za-z_]\w*)\s*=\s*([^;,\n]+)"
)
_ENUM_BLOCK_RE = re.compile(r"\benum(?:\s+[A-Za-z_]\w*)?\s*\{([^}]*)\}", re.S)
_ENUM_ITEM_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:=\s*([^,\n}]+))?")

_PTR_DECL_RE = re.compile(
    r"\b(?:const\s+|volatile\s+|static\s+|register\s+)*"
    r"(?:(?:struct|union|enum)\s+[A-Za-z_]\w*|"
    r"(?:unsigned|signed)\s+(?:char|short|int|long(?:\s+long)?)|"
    r"void|char|short|int|long(?:\s+long)?|float|double|wchar_t|"
    r"size_t|ssize_t|u?int(?:8|16|32|64)_t|FILE)"
    r"\s*\*+\s*(?:const\s+|volatile\s+|restrict\s+)*([A-Za-z_]\w*)\s*(?=[,;=\)])"
)
_SIGNED_DECL_RE = re.compile(
    r"\b(?:const\s+|volatile\s+|register\s+)*"
    r"(?:signed\s+(?:char|short|int|long(?:\s+long)?)|"
    r"short|int|long(?:\s+long)?|ssize_t|ptrdiff_t|int(?:8|16|32|64)_t)"
    r"\s+([A-Za-z_]\w*)\s*(?=[,;=\)])"
)
_LOCAL_SCALAR_DECL_RE = re.compile(
    r"\b(?P<storage>(?:(?:static|const|volatile|register)\s+)*)"
    r"(?:(?:struct|union|enum)\s+[A-Za-z_]\w*|"
    r"(?:unsigned|signed)\s+(?:char|short|int|long(?:\s+long)?)|"
    r"char|short|int|long(?:\s+long)?|float|double|wchar_t|bool|_Bool|"
    r"size_t|ssize_t|u?int(?:8|16|32|64)_t)"
    r"\s+(?P<name>[A-Za-z_]\w*)\s*(?=[;=,])"
)
_FUNC_PARAM_ARRAY_RE = re.compile(
    r"\b(?:const\s+|volatile\s+)*"
    r"(?:(?:unsigned|signed)\s+(?:char|short|int|long(?:\s+long)?)|"
    r"char|short|int|long(?:\s+long)?|wchar_t|u?int(?:8|16|32|64)_t)"
    r"\s+([A-Za-z_]\w*)\s*\[[^\]]*\]"
)
_SIZEOF_IDENT_RE = re.compile(
    r"\bsizeof\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*)\b)"
)
_RETURN_STMT_RE = re.compile(r"\breturn\s+([^;]+);")
_TERMINATOR_RE = re.compile(
    r"\b(?:return|goto|break|continue)\b|\b(?:exit|_Exit|abort|longjmp)\s*\("
)
_NULL_VALUES = {"NULL", "0", "nullptr"}


def load_rules(paths=None):
    """Load the built-in rules plus any custom JSON rule files/directories."""
    files = [Path(__file__).with_name("boar_rules.json")]
    for item in paths or []:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        else:
            files.append(path)

    rules = []
    index = {}
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError("cannot read rule file '{}': {}".format(path, exc))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON in rule file '{}': {}".format(path, exc))

        raw_rules = data.get("rules", []) if isinstance(data, dict) else data
        if not isinstance(raw_rules, list):
            raise ValueError("rule file '{}' must contain a 'rules' list".format(path))

        for raw in raw_rules:
            rule = _validate_rule(raw, path)
            if rule["id"] in index:
                rules[index[rule["id"]]] = rule
            else:
                index[rule["id"]] = len(rules)
                rules.append(rule)
    return rules


def _validate_rule(raw, path):
    if not isinstance(raw, dict):
        raise ValueError("rule in '{}' is not an object".format(path))
    for key in ("id", "name", "severity", "matcher"):
        if not raw.get(key):
            raise ValueError("rule in '{}' is missing '{}'".format(path, key))

    rule = dict(raw)
    rule["severity"] = str(rule["severity"]).lower()
    rule["confidence"] = str(rule.get("confidence", "medium")).lower()
    if rule["severity"] not in SEVERITY_ORDER:
        raise ValueError("rule '{}' has unknown severity '{}'".format(rule["id"], rule["severity"]))
    if rule["confidence"] not in SEVERITY_ORDER:
        raise ValueError("rule '{}' has unknown confidence '{}'".format(rule["id"], rule["confidence"]))
    if rule["matcher"] not in MATCHERS:
        raise ValueError("rule '{}' has unknown matcher '{}'".format(rule["id"], rule["matcher"]))
    if not isinstance(rule.get("functions", []), list):
        raise ValueError("rule '{}' has a non-list 'functions' field".format(rule["id"]))
    if not isinstance(rule.get("format_arg", {}), dict):
        raise ValueError("rule '{}' has a non-object 'format_arg' field".format(rule["id"]))
    rule.setdefault("functions", [])
    rule.setdefault("cwe", [])
    rule.setdefault("references", [])
    rule.setdefault("description", "")
    rule.setdefault("remediation", "")
    return rule


def severity_rank(severity):
    return SEVERITY_ORDER.get(str(severity).lower(), len(SEVERITIES))


def mask_noncode(source):
    """Blank comments and string/char literals while preserving offsets and newlines."""
    out = list(source)
    i = 0
    size = len(source)
    while i < size:
        char = source[i]
        if char == "/" and i + 1 < size and source[i + 1] == "/":
            out[i] = out[i + 1] = " "
            i += 2
            while i < size and source[i] != "\n":
                out[i] = " "
                i += 1
        elif char == "/" and i + 1 < size and source[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < size:
                if source[i] == "*" and i + 1 < size and source[i + 1] == "/":
                    out[i] = out[i + 1] = " "
                    i += 2
                    break
                if source[i] != "\n":
                    out[i] = " "
                i += 1
        elif char in ('"', "'"):
            quote = char
            out[i] = " "
            i += 1
            while i < size:
                if source[i] == "\\":
                    out[i] = " "
                    if i + 1 < size:
                        out[i + 1] = " "
                    i += 2
                    continue
                if source[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if source[i] != "\n":
                    out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def split_args(text):
    if not text.strip():
        return []
    args = []
    depth = 0
    start = 0
    i = 0
    while i < len(text):
        char = text[i]
        if char in ('"', "'"):
            quote = char
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    args.append(text[start:].strip())
    return args


def extract_calls(source, masked):
    calls = []
    for match in _CALL_RE.finditer(masked):
        name = match.group(1)
        start = match.start(1)
        before = masked[:start].rstrip()
        if before.endswith(".") or before.endswith("->"):
            continue
        prefix = masked[max(0, start - 100):start]
        if _TYPE_PREFIX_RE.search(prefix):
            continue
        line_start = masked.rfind("\n", 0, start) + 1
        if masked[line_start:start].lstrip().startswith("#"):
            continue

        open_paren = match.end() - 1
        depth = 1
        cursor = open_paren + 1
        while cursor < len(masked) and depth:
            if masked[cursor] == "(":
                depth += 1
            elif masked[cursor] == ")":
                depth -= 1
            cursor += 1
        if depth:
            continue

        call = {
            "name": name,
            "offset": start,
            "end": cursor,
            "args": split_args(source[open_paren + 1:cursor - 1]),
        }
        calls.append(call)
    return calls


def find_brace_pairs(masked):
    pairs = []
    stack = []
    for offset, char in enumerate(masked):
        if char == "{":
            stack.append(offset)
        elif char == "}" and stack:
            pairs.append((stack.pop(), offset))
    return pairs


def numeric_value(expression):
    text = re.sub(r"(?i)(?:u|l)+$", "", expression.strip())
    if not re.fullmatch(r"[+-]?(?:0x[0-9a-fA-F]+|0[0-7]*|[1-9]\d*)", text):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


_EXPR_TOKEN_RE = re.compile(
    r"\s*(?:(<<|>>|[+\-*/()])|(0x[0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)|([A-Za-z_]\w*))"
)


def eval_int_expr(expression, constants=None):
    """Safely evaluate simple integer constant expressions (+, -, *, /, <<, >>, ())."""
    if not expression:
        return None
    direct = numeric_value(expression)
    if direct is not None:
        return direct

    constants = constants or {}
    tokens = []
    pos = 0
    stripped = expression.strip()
    if not stripped:
        return None
    while pos < len(stripped):
        match = _EXPR_TOKEN_RE.match(stripped, pos)
        if not match:
            return None
        op, num, ident = match.groups()
        if op:
            tokens.append(("op", op))
        elif num:
            val = numeric_value(num)
            if val is None:
                return None
            tokens.append(("num", val))
        elif ident:
            if ident not in constants:
                return None
            tokens.append(("num", constants[ident]))
        pos = match.end()

    cursor = [0]

    def peek():
        return tokens[cursor[0]] if cursor[0] < len(tokens) else None

    def consume():
        tok = tokens[cursor[0]]
        cursor[0] += 1
        return tok

    def parse_shift():
        left = parse_add()
        if left is None:
            return None
        while True:
            tok = peek()
            if tok and tok[0] == "op" and tok[1] in ("<<", ">>"):
                op = consume()[1]
                right = parse_add()
                if right is None or right < 0 or right > 63:
                    return None
                left = (left << right) if op == "<<" else (left >> right)
            else:
                break
        return left

    def parse_add():
        left = parse_mul()
        if left is None:
            return None
        while True:
            tok = peek()
            if tok and tok[0] == "op" and tok[1] in ("+", "-"):
                op = consume()[1]
                right = parse_mul()
                if right is None:
                    return None
                left = (left + right) if op == "+" else (left - right)
            else:
                break
        return left

    def parse_mul():
        left = parse_unary()
        if left is None:
            return None
        while True:
            tok = peek()
            if tok and tok[0] == "op" and tok[1] in ("*", "/"):
                op = consume()[1]
                right = parse_unary()
                if right is None:
                    return None
                if op == "/":
                    if right == 0:
                        return None
                    left = int(left / right)
                else:
                    left = left * right
            else:
                break
        return left

    def parse_unary():
        tok = peek()
        if not tok:
            return None
        if tok[0] == "op" and tok[1] in ("+", "-"):
            op = consume()[1]
            val = parse_unary()
            if val is None:
                return None
            return val if op == "+" else -val
        if tok[0] == "op" and tok[1] == "(":
            consume()
            val = parse_shift()
            end_tok = peek()
            if val is None or not end_tok or end_tok != ("op", ")"):
                return None
            consume()
            return val
        if tok[0] == "num":
            return consume()[1]
        return None

    value = parse_shift()
    if value is None or cursor[0] != len(tokens):
        return None
    return value


def collect_constants(masked):
    """Collect simple #define, enum, and const integer values in a translation unit."""
    constants = {}
    raw_defs = []

    for match in _DEFINE_CONST_RE.finditer(masked):
        name, expr = match.group(1), match.group(2).strip()
        # Exclude function-like macros (#define FOO(x) ...): check no '(' immediately after name.
        after_name = match.start(1) + len(name)
        if after_name < len(masked) and masked[after_name] == "(":
            continue
        raw_defs.append((name, expr))

    for match in _TYPED_CONST_RE.finditer(masked):
        raw_defs.append((match.group(1), match.group(2).strip()))

    for enum_match in _ENUM_BLOCK_RE.finditer(masked):
        next_val = 0
        body = enum_match.group(1)
        for item in body.split(","):
            part = item.strip()
            if not part:
                continue
            item_match = _ENUM_ITEM_RE.match(part)
            if not item_match:
                continue
            ident, explicit = item_match.groups()
            if explicit is not None:
                resolved = eval_int_expr(explicit, constants)
                if resolved is None:
                    next_val = None
                    continue
                next_val = resolved
            if next_val is not None:
                constants[ident] = next_val
                next_val += 1

    # Multi-pass resolution so `#define B (A + 1)` works regardless of simple ordering.
    for _ in range(3):
        progressed = False
        for name, expr in raw_defs:
            val = eval_int_expr(expr, constants)
            if val is not None and constants.get(name) != val:
                constants[name] = val
                progressed = True
        if not progressed:
            break

    return constants


def _enclosing_scope(brace_pairs, offset, total_len):
    best = None
    for start, end in brace_pairs:
        if start < offset < end and (best is None or (end - start) < (best[1] - best[0])):
            best = (start, end)
    return best if best is not None else (0, total_len)


def _function_scopes(masked, brace_pairs):
    """Return top-level function body (start, end, param_span) tuples."""
    outer = []
    for start, end in sorted(brace_pairs, key=lambda pair: (pair[0], -(pair[1] - pair[0]))):
        if any(prev_s < start and end < prev_e for prev_s, prev_e, _ in outer):
            continue
        # Check if preceded by a parameter list `(...)` rather than struct/enum/namespace.
        before = masked[:start].rstrip()
        if not before.endswith(")"):
            continue
        close_paren = len(before) - 1
        depth = 1
        cursor = close_paren - 1
        while cursor >= 0 and depth:
            if before[cursor] == ")":
                depth += 1
            elif before[cursor] == "(":
                depth -= 1
            cursor -= 1
        param_span = (cursor + 1, close_paren) if depth == 0 else None
        outer.append((start, end, param_span))
    return outer


def _normalize_type_spaces(type_text):
    return " ".join(type_text.split())


def collect_scoped_buffers(masked, brace_pairs, constants, func_scopes):
    """Collect fixed-size array declarations with their enclosing brace scope."""
    param_ranges = [span for _, _, span in func_scopes if span is not None]
    decls = []

    for match in _BUFFER_DECL_RE.finditer(masked):
        offset = match.start("name")
        # Array syntax inside a function parameter list `void f(char buf[64])`
        # decays to a pointer in C, NOT a 64-byte array!
        if any(p_start <= offset <= p_end for p_start, p_end in param_ranges):
            continue
        count = eval_int_expr(match.group("size"), constants)
        if count is None or count <= 0:
            continue
        elem_type = _normalize_type_spaces(match.group("type"))
        elem_bytes = _ELEM_BYTES.get(elem_type, 1)
        storage = match.group("storage") or ""
        is_static = bool(re.search(r"\bstatic\b", storage))
        scope_start, scope_end = _enclosing_scope(brace_pairs, offset, len(masked))
        decls.append({
            "name": match.group("name"),
            "elements": count,
            "bytes": count * elem_bytes,
            "elem_bytes": elem_bytes,
            "offset": offset,
            "scope_start": scope_start,
            "scope_end": scope_end,
            "is_static": is_static,
        })
    return decls


def collect_buffer_sizes(masked):
    """Legacy helper returning unambiguous file-wide byte capacities."""
    pairs = find_brace_pairs(masked)
    constants = collect_constants(masked)
    funcs = _function_scopes(masked, pairs)
    decls = collect_scoped_buffers(masked, pairs, constants, funcs)
    by_name = {}
    for item in decls:
        by_name.setdefault(item["name"], set()).add(item["bytes"])
    return {name: next(iter(values)) for name, values in by_name.items() if len(values) == 1}


def collect_scoped_symbols(masked, brace_pairs, func_scopes):
    """Collect pointer variables, decayed array parameters, signed ints, and stack locals."""
    pointers = []
    signed_vars = []
    stack_locals = []

    def param_owner_scope(offset):
        for f_start, f_end, span in func_scopes:
            if span and span[0] <= offset <= span[1]:
                return (f_start, f_end, True)
        s_start, s_end = _enclosing_scope(brace_pairs, offset, len(masked))
        return (s_start, s_end, False)

    for match in _PTR_DECL_RE.finditer(masked):
        offset = match.start(1)
        s_start, s_end, is_param = param_owner_scope(offset)
        pointers.append({
            "name": match.group(1),
            "offset": s_start if is_param else offset,
            "scope_start": s_start,
            "scope_end": s_end,
            "kind": "pointer",
        })

    for _, f_end, span in func_scopes:
        if not span:
            continue
        f_start = next(fs for fs, fe, sp in func_scopes if fe == f_end and sp == span)
        param_text = masked[span[0]:span[1]]
        for match in _FUNC_PARAM_ARRAY_RE.finditer(param_text):
            pointers.append({
                "name": match.group(1),
                "offset": f_start,
                "scope_start": f_start,
                "scope_end": f_end,
                "kind": "decayed_array_param",
            })

    for match in _SIGNED_DECL_RE.finditer(masked):
        offset = match.start(1)
        s_start, s_end, is_param = param_owner_scope(offset)
        signed_vars.append({
            "name": match.group(1),
            "offset": s_start if is_param else offset,
            "scope_start": s_start,
            "scope_end": s_end,
        })

    for match in _LOCAL_SCALAR_DECL_RE.finditer(masked):
        offset = match.start("name")
        s_start, s_end, is_param = param_owner_scope(offset)
        if s_start == 0 and s_end == len(masked):
            continue  # global variable, not stack-allocated
        storage = match.group("storage") or ""
        if re.search(r"\bstatic\b", storage):
            continue
        stack_locals.append({
            "name": match.group("name"),
            "offset": s_start if is_param else offset,
            "scope_start": s_start,
            "scope_end": s_end,
            "is_param": is_param,
        })

    return pointers, signed_vars, stack_locals


class SourceContext(object):
    def __init__(self, source):
        self.source = source
        self.masked = mask_noncode(source)
        self.lines = source.splitlines()
        self.line_starts = [0]
        for match in re.finditer(r"\n", source):
            self.line_starts.append(match.end())
        self.calls = extract_calls(source, self.masked)
        self.brace_pairs = find_brace_pairs(self.masked)
        self.constants = collect_constants(self.masked)
        self.func_scopes = _function_scopes(self.masked, self.brace_pairs)
        self.buffer_decls = collect_scoped_buffers(
            self.masked, self.brace_pairs, self.constants, self.func_scopes
        )
        self.pointers, self.signed_vars, self.stack_locals = collect_scoped_symbols(
            self.masked, self.brace_pairs, self.func_scopes
        )
        by_name = {}
        for item in self.buffer_decls:
            by_name.setdefault(item["name"], set()).add(item["bytes"])
        self.buffers = {
            name: next(iter(vals)) for name, vals in by_name.items() if len(vals) == 1
        }

    def position(self, offset):
        index = bisect.bisect_right(self.line_starts, offset) - 1
        return index + 1, offset - self.line_starts[index] + 1

    def line_text(self, line):
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()
        return ""

    def eval_int(self, expression):
        return eval_int_expr(expression, self.constants)

    def buffer_decl_at(self, name, offset):
        if not name:
            return None
        # If shadowed by a pointer or decayed parameter in a narrower scope, do not return outer array!
        ptr = self.pointer_at(name, offset)
        candidates = [
            decl for decl in self.buffer_decls
            if decl["name"] == name
            and decl["scope_start"] <= offset <= decl["scope_end"]
            and (decl["offset"] <= offset or decl["scope_start"] == 0)
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda d: (d["scope_end"] - d["scope_start"], -d["offset"]))
        best = candidates[0]
        if ptr is not None:
            ptr_span = ptr["scope_end"] - ptr["scope_start"]
            buf_span = best["scope_end"] - best["scope_start"]
            if ptr_span < buf_span or (ptr_span == buf_span and ptr["offset"] > best["offset"]):
                return None
        return best

    def buffer_capacity(self, name, offset, in_elements=False):
        decl = self.buffer_decl_at(name, offset)
        if decl is None:
            return None
        return decl["elements"] if in_elements else decl["bytes"]

    def pointer_at(self, name, offset):
        if not name:
            return None
        candidates = [
            item for item in self.pointers
            if item["name"] == name
            and item["scope_start"] <= offset <= item["scope_end"]
            and item["offset"] <= offset
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda d: (d["scope_end"] - d["scope_start"], -d["offset"]))
        # Check if shadowed by an inner local array with the same name
        best = candidates[0]
        inner_arrays = [
            decl for decl in self.buffer_decls
            if decl["name"] == name
            and decl["scope_start"] <= offset <= decl["scope_end"]
            and decl["offset"] <= offset
            and (decl["scope_end"] - decl["scope_start"]) < (best["scope_end"] - best["scope_start"])
        ]
        if inner_arrays:
            return None
        return best

    def is_signed_var(self, name, offset):
        if not name:
            return False
        return any(
            item["name"] == name
            and item["scope_start"] <= offset <= item["scope_end"]
            and item["offset"] <= offset
            for item in self.signed_vars
        )

    def function_scope_for(self, offset):
        for f_start, f_end, _ in self.func_scopes:
            if f_start <= offset <= f_end:
                return (f_start, f_end)
        return None


def _decoded_c_string_length(raw):
    """Compute byte length of C string literal contents (excluding NUL)."""
    length = 0
    i = 0
    while i < len(raw):
        if raw[i] == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == "x":
                i += 2
                while i < len(raw) and raw[i] in "0123456789abcdefABCDEF":
                    i += 1
                length += 1
                continue
            if nxt in "01234567":
                end = min(len(raw), i + 4)
                i += 2
                while i < end and raw[i] in "01234567":
                    i += 1
                length += 1
                continue
            i += 2
            length += 1
            continue
        i += 1
        length += 1
    return length


def literal_text(argument):
    if not argument or not _STRING_ONLY_RE.match(argument.strip()):
        return None
    return "".join(_STRING_TOKEN_RE.findall(argument))


def literal_byte_length(argument):
    if not argument or not _STRING_ONLY_RE.match(argument.strip()):
        return None
    return sum(_decoded_c_string_length(part) for part in _STRING_TOKEN_RE.findall(argument))


def base_identifier(expression):
    text = expression.strip()
    while True:
        cast = re.match(
            r"^\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?"
            r"(?:(?:struct|union|enum)\s+)?[A-Za-z_]\w*(?:\s*\*)*\s*\)\s*",
            text,
        )
        if not cast:
            break
        text = text[cast.end():]
    match = re.match(r"&?\s*([A-Za-z_]\w*)", text)
    return match.group(1) if match else None


def _sizeof_target(expression):
    match = _SIZEOF_IDENT_RE.fullmatch(expression.strip())
    if not match:
        return None
    return match.group(1) or match.group(2)


def _sizeof_minus_one_target(expression):
    match = re.fullmatch(
        r"\s*sizeof\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))\s*-\s*1[uUlL]*\s*",
        expression,
    )
    if not match:
        return None
    return match.group(1) or match.group(2)


def _resolve_bound_bytes(expression, context, offset, in_elements=False):
    val = context.eval_int(expression)
    if val is not None:
        return val
    ident = _sizeof_target(expression)
    if ident:
        return context.buffer_capacity(ident, offset, in_elements=in_elements)
    ident_m1 = _sizeof_minus_one_target(expression)
    if ident_m1:
        cap = context.buffer_capacity(ident_m1, offset, in_elements=in_elements)
        return (cap - 1) if cap is not None else None
    return None


def _format_argument(rule, call):
    index = rule.get("format_arg", {}).get(call["name"])
    if index is None:
        index = 1
    if index >= len(call["args"]):
        return None
    return call["args"][index]


def _string_conversions(format_text, require_unbounded=False):
    risky = []
    for match in _CONVERSION_RE.finditer(format_text):
        width, precision, conversion = match.groups()
        if conversion in ("s", "["):
            if not require_unbounded or (not width and not precision):
                risky.append(match.group(0))
    return risky


def _m_unsafe_call(rule, call, context):
    return rule.get("confidence", "high")


def _m_unbounded_copy(rule, call, context):
    if len(call["args"]) < 2:
        return None
    destination, source = call["args"][0], call["args"][1]
    in_elements = call["name"].startswith("wcs")
    dest_name = base_identifier(destination)
    capacity = context.buffer_capacity(dest_name, call["offset"], in_elements=in_elements)
    lit_len = literal_byte_length(source)
    if lit_len is None:
        return "high"
    needed = lit_len + 1
    is_cat = call["name"] in ("strcat", "wcscat")
    if capacity is not None:
        if needed > capacity:
            return (
                "high",
                "literal requires {} units (including NUL) but '{}' holds {}".format(
                    needed, dest_name, capacity
                ),
            )
        if not is_cat:
            return None
        return "low"
    return "medium"


def _m_format_copy(rule, call, context):
    format_text = _format_argument(rule, call)
    if format_text is None:
        return None
    literal = literal_text(format_text)
    if literal is None:
        return "high"
    dest_name = base_identifier(call["args"][0]) if call["args"] else None
    capacity = context.buffer_capacity(dest_name, call["offset"])
    if capacity is not None:
        # Compute conservative minimum formatted length by replacing conversions with 1 byte.
        static_part = _CONVERSION_RE.sub(
            lambda m: "%" if m.group(3) == "%" else ("X" if m.group(3) != "n" else ""),
            literal,
        )
        min_needed = _decoded_c_string_length(static_part) + 1
        if min_needed > capacity:
            return (
                "high",
                "format string writes at least {} bytes (including NUL) into '{}' ({} bytes)".format(
                    min_needed, dest_name, capacity
                ),
            )
    if not _string_conversions(literal):
        return None
    return "medium"


def _m_scanf_width(rule, call, context):
    index = rule.get("format_arg", {}).get(call["name"], 0)
    if index >= len(call["args"]):
        return None
    format_text = call["args"][index]
    literal = literal_text(format_text)
    if literal is None:
        return "medium"

    is_va_list = call["name"].startswith("v")
    arg_cursor = index + 1

    for match in _SCANF_CONV_RE.finditer(literal):
        suppressed, width_text, spec = match.groups()
        if spec == "%":
            continue
        if suppressed == "*":
            # Assignment-suppressed conversions (%*s, %*d) neither consume an arg nor write memory.
            continue

        dest_expr = (
            call["args"][arg_cursor]
            if (not is_va_list and arg_cursor < len(call["args"]))
            else None
        )
        arg_cursor += 1

        is_string_spec = spec == "s" or spec.startswith("[")
        if is_string_spec:
            if not width_text:
                return (
                    "high",
                    "unbounded '{}' conversion can overflow destination".format(match.group(0)),
                )
            if dest_expr is not None:
                dest_name = base_identifier(dest_expr)
                capacity = context.buffer_capacity(dest_name, call["offset"])
                needed = int(width_text) + 1
                if capacity is not None and needed > capacity:
                    return (
                        "high",
                        "conversion '{}' writes up to {} bytes (including NUL) into '{}' ({} bytes)".format(
                            match.group(0), needed, dest_name, capacity
                        ),
                    )
        elif spec == "c" and width_text and dest_expr is not None:
            dest_name = base_identifier(dest_expr)
            capacity = context.buffer_capacity(dest_name, call["offset"])
            needed = int(width_text)
            if capacity is not None and needed > capacity:
                return (
                    "high",
                    "conversion '{}' writes {} bytes into '{}' ({} bytes)".format(
                        match.group(0), needed, dest_name, capacity
                    ),
                )
    return None


def _m_bounded_copy(rule, call, context):
    if len(call["args"]) < 3:
        return None
    length_expression = call["args"][2]
    in_elements = call["name"].startswith("w")
    destination = call["args"][1] if call["name"] == "bcopy" else call["args"][0]
    dest_name = base_identifier(destination)
    capacity = context.buffer_capacity(dest_name, call["offset"], in_elements=in_elements)

    if re.search(r"\bsizeof\b", length_expression):
        sizeof_ident = _sizeof_target(length_expression)
        if sizeof_ident and context.pointer_at(sizeof_ident, call["offset"]) is not None:
            # Handled specifically by sizeof_pointer (BOAR-MEM-013); skip duplicate medium alert.
            return None
        if sizeof_ident and capacity is not None and sizeof_ident != dest_name:
            other_cap = context.buffer_capacity(
                sizeof_ident, call["offset"], in_elements=in_elements
            )
            if other_cap is not None and other_cap > capacity:
                return (
                    "high",
                    "sizeof({}) ({} bytes) exceeds destination '{}' ({} bytes)".format(
                        sizeof_ident, other_cap, dest_name, capacity
                    ),
                )
        return None

    length = context.eval_int(length_expression)
    if length is not None:
        if length < 0:
            return ("high", "negative length wraps around when converted to size_t")
        if capacity is None:
            return "low"
        if length > capacity:
            return (
                "high",
                "copy length {} exceeds '{}' capacity ({})".format(length, dest_name, capacity),
            )
        return None
    return "medium"


def _m_format_string(rule, call, context):
    format_text = _format_argument(rule, call)
    if format_text is None:
        return None
    return None if literal_text(format_text) is not None else "high"


def _m_variable_size_alloc(rule, call, context):
    if not call["args"]:
        return None
    if re.search(r"\bsizeof\b", call["args"][0]) and "*" not in call["args"][0]:
        return "low"
    return "low" if context.eval_int(call["args"][0]) is not None else "high"


def _m_alloc_arithmetic(rule, call, context):
    size_idx = 1 if call["name"] == "realloc" else 0
    if len(call["args"]) <= size_idx:
        return None
    expr = call["args"][size_idx]
    if "*" not in expr and "+" not in expr:
        return None
    if context.eval_int(expr) is not None:
        return None
    # Allow pure sizeof(T) + constant when no runtime variable participates
    if "*" not in expr:
        parts = [part.strip() for part in expr.split("+")]
        if all(
            context.eval_int(p) is not None or _sizeof_target(p) is not None
            for p in parts
        ):
            return None
    return "medium"


def _has_explicit_null_termination(context, dest_name, after_offset):
    if not dest_name:
        return False
    scope_start, scope_end = _enclosing_scope(
        context.brace_pairs, after_offset, len(context.masked)
    )
    tail = context.source[after_offset:scope_end]
    pattern = re.compile(
        r"\b" + re.escape(dest_name) + r"\s*\[[^\]]+\]\s*=\s*(?:'\\0'|0|L'\\0')\s*;"
    )
    return bool(pattern.search(tail))


def _m_bounded_string_copy(rule, call, context):
    if len(call["args"]) < 3:
        return None
    dest_expr, _, len_expr = call["args"][0], call["args"][1], call["args"][2]
    dest_name = base_identifier(dest_expr)
    in_elements = call["name"].startswith("wcs")
    is_cat = call["name"] in ("strncat", "wcsncat")
    capacity = context.buffer_capacity(dest_name, call["offset"], in_elements=in_elements)

    sizeof_ident = _sizeof_target(len_expr)
    if sizeof_ident and context.pointer_at(sizeof_ident, call["offset"]) is not None:
        return None  # Covered by BOAR-MEM-013 (sizeof_pointer)

    bound = _resolve_bound_bytes(len_expr, context, call["offset"], in_elements=in_elements)

    if is_cat:
        # Classic CWE-193: strncat(dst, src, sizeof(dst)) writes up to strlen(dst) + sizeof(dst) + 1!
        if sizeof_ident and sizeof_ident == dest_name:
            return (
                "high",
                "{0}() passed sizeof({1}) instead of remaining space (sizeof({1}) - strlen({1}) - 1)".format(
                    call["name"], dest_name
                ),
            )
        if capacity is not None and bound is not None:
            if bound >= capacity:
                return (
                    "high",
                    "{}() bound {} writes up to {} units (including NUL) into '{}' ({} units)".format(
                        call["name"], bound, bound + 1, dest_name, capacity
                    ),
                )
        return None

    # strncpy / wcsncpy
    if sizeof_ident and dest_name and sizeof_ident != dest_name:
        other_cap = context.buffer_capacity(sizeof_ident, call["offset"], in_elements=in_elements)
        if capacity is not None and other_cap is not None and other_cap > capacity:
            return (
                "high",
                "sizeof({}) ({}) exceeds destination '{}' ({})".format(
                    sizeof_ident, other_cap, dest_name, capacity
                ),
            )
        src_name = base_identifier(call["args"][1])
        if sizeof_ident == src_name:
            return (
                "high",
                "{}() bound uses source size sizeof({}) instead of destination capacity".format(
                    call["name"], src_name
                ),
            )

    if capacity is not None and bound is not None:
        if bound > capacity:
            return (
                "high",
                "{}() bound {} exceeds '{}' capacity ({})".format(
                    call["name"], bound, dest_name, capacity
                ),
            )
        if bound == capacity and not _has_explicit_null_termination(context, dest_name, call["end"]):
            return (
                "medium",
                "{}() with full capacity ({}) leaves '{}' unterminated when source length >= {}".format(
                    call["name"], capacity, dest_name, capacity
                ),
            )
    elif sizeof_ident and sizeof_ident == dest_name:
        if not _has_explicit_null_termination(context, dest_name, call["end"]):
            return (
                "medium",
                "{}() with sizeof({}) may leave '{}' without a NUL terminator".format(
                    call["name"], dest_name, dest_name
                ),
            )
    return None


def _m_input_read_length(rule, call, context):
    name = call["name"]
    args = call["args"]
    if name in ("fgets", "fgets_unlocked"):
        if len(args) < 3:
            return None
        buf_expr, len_expr = args[0], args[1]
    elif name in ("read", "pread", "recv", "recvfrom"):
        if len(args) < 3:
            return None
        buf_expr, len_expr = args[1], args[2]
    elif name == "fread":
        if len(args) < 4:
            return None
        buf_expr = args[0]
        len_expr = "({}) * ({})".format(args[1], args[2])
    else:
        return None

    dest_name = base_identifier(buf_expr)
    capacity = context.buffer_capacity(dest_name, call["offset"])

    sizeof_ident = _sizeof_target(len_expr)
    if sizeof_ident and context.pointer_at(sizeof_ident, call["offset"]) is not None:
        return None  # Covered by BOAR-MEM-013

    if re.search(r"\bsizeof\b", len_expr):
        if capacity is not None:
            bound = _resolve_bound_bytes(len_expr, context, call["offset"])
            if bound is not None and bound > capacity:
                return (
                    "high",
                    "{}() size {} exceeds '{}' capacity ({} bytes)".format(
                        name, bound, dest_name, capacity
                    ),
                )
        return None

    val = context.eval_int(len_expr)
    if val is not None:
        if val < 0:
            return (
                "high",
                "negative read length ({}) converts to a huge unsigned size or undefined behavior".format(val),
            )
        if capacity is not None and val > capacity:
            return (
                "high",
                "{}() requests {} bytes into '{}' ({} bytes)".format(
                    name, val, dest_name, capacity
                ),
            )
        return None

    len_ident = _plain_identifier(len_expr)
    if len_ident and context.is_signed_var(len_ident, call["offset"]):
        if name in ("read", "pread", "recv", "recvfrom", "fread"):
            return (
                "medium",
                "signed length '{}' passed to {}() without sizeof bound (negative values wrap to size_t)".format(
                    len_ident, name
                ),
            )
    if capacity is not None:
        return (
            "medium",
            "{}() reads an unverified variable length into fixed buffer '{}' ({} bytes)".format(
                name, dest_name, capacity
            ),
        )
    return None


def _m_sizeof_pointer(rule, call, context):
    for arg in call["args"]:
        for match in _SIZEOF_IDENT_RE.finditer(arg):
            ident = match.group(1) or match.group(2)
            ptr_info = context.pointer_at(ident, call["offset"])
            if ptr_info is None:
                continue
            if ptr_info["kind"] == "decayed_array_param":
                return (
                    "high",
                    "sizeof({}) on array parameter '{}' evaluates to pointer size, not array length".format(
                        ident, ident
                    ),
                )
            return (
                "high",
                "sizeof({}) evaluates the pointer size (4/8 bytes), not the buffer/object '{}' points to".format(
                    ident, ident
                ),
            )
    return None


MATCHERS.update({
    "unsafe_call": _m_unsafe_call,
    "unbounded_copy": _m_unbounded_copy,
    "format_copy": _m_format_copy,
    "scanf_width": _m_scanf_width,
    "bounded_copy": _m_bounded_copy,
    "format_string": _m_format_string,
    "variable_size_alloc": _m_variable_size_alloc,
    "alloc_arithmetic": _m_alloc_arithmetic,
    "bounded_string_copy": _m_bounded_string_copy,
    "input_read_length": _m_input_read_length,
    "sizeof_pointer": _m_sizeof_pointer,
    # Flow/statement matchers are implemented by dedicated scanners; register
    # their names so rule validation accepts them.
    "double_free": lambda rule, call, context: None,
    "use_after_free": lambda rule, call, context: None,
    "stack_return": lambda rule, call, context: None,
})


def is_suppressed(lines, line):
    for number in (line, line - 1):
        if 1 <= number <= len(lines):
            text = lines[number - 1].lower()
            if "boar:ignore" in text or "boar-ignore" in text:
                return True
    return False


def make_finding(context, file_label, rule, call, confidence=None, offset=None, note=None):
    position = call["offset"] if offset is None else offset
    line, column = context.position(position)
    code = context.line_text(line)
    if len(code) > 300:
        code = code[:297] + "..."
    finding = {
        "id": rule["id"],
        "rule": rule["name"],
        "severity": rule["severity"],
        "confidence": confidence or rule.get("confidence", "medium"),
        "cwe": list(rule.get("cwe", [])),
        "references": list(rule.get("references", [])),
        "file": file_label,
        "line": line,
        "column": column,
        "code": code,
        "description": rule.get("description", ""),
        "remediation": rule.get("remediation", ""),
    }
    if note:
        finding["note"] = note
    return finding


def _plain_identifier(expression):
    match = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*", expression)
    return match.group(1) if match else None


def _scope_for(context, offset):
    return _enclosing_scope(context.brace_pairs, offset, len(context.masked))


def _has_same_depth_terminator(masked, start, end):
    """Return earliest terminator offset at relative brace depth 0 in [start, end), or None."""
    depth = 0
    i = start
    while i < end:
        ch = masked[i]
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            if depth == 0:
                break
            depth -= 1
            i += 1
            continue
        if depth == 0:
            match = _TERMINATOR_RE.match(masked, i)
            if match and (i == 0 or not (masked[i - 1].isalnum() or masked[i - 1] == "_")):
                return i
        i += 1
    return None


def _rhs_assigned_value(source, eq_offset, limit):
    semi = source.find(";", eq_offset + 1, limit)
    end = limit if semi == -1 else semi
    return source[eq_offset + 1:end].strip()


def _is_null_rhs(rhs_text):
    cleaned = re.sub(r"^\(\s*void\s*\*\s*\)\s*", "", rhs_text.strip())
    return cleaned in _NULL_VALUES


def _else_branch_end(masked, close_brace, limit):
    """If `}` at close_brace is immediately followed by `else`, return end of else branch."""
    cursor = close_brace + 1
    while cursor < limit and masked[cursor].isspace():
        cursor += 1
    if not masked.startswith("else", cursor):
        return close_brace + 1
    after = cursor + 4
    if after < limit and (masked[after].isalnum() or masked[after] == "_"):
        return close_brace + 1
    while after < limit and masked[after].isspace():
        after += 1
    if after < limit and masked[after] == "{":
        depth = 1
        pos = after + 1
        while pos < limit and depth:
            if masked[pos] == "{":
                depth += 1
            elif masked[pos] == "}":
                depth -= 1
            pos += 1
        return pos
    semi = masked.find(";", after, limit)
    return (semi + 1) if semi != -1 else limit


def _lifetime_rules(rules):
    double_free = next((rule for rule in rules if rule["matcher"] == "double_free"), None)
    use_after_free = next((rule for rule in rules if rule["matcher"] == "use_after_free"), None)
    return double_free, use_after_free


def scan_lifetime(context, rules):
    double_rule, uaf_rule = _lifetime_rules(rules)
    if double_rule is None and uaf_rule is None:
        return []

    findings = []
    free_events = {}
    for call in context.calls:
        if call["name"] != "free" or not call["args"]:
            continue
        identifier = _plain_identifier(call["args"][0])
        if not identifier:
            continue
        match = re.search(
            r"\b" + re.escape(identifier) + r"\b",
            context.masked[call["offset"]:call["end"]],
        )
        if match:
            free_events[call["offset"] + match.start()] = (call, identifier)

    for free_call in [call for call in context.calls if call["name"] == "free"]:
        if not free_call["args"]:
            continue
        identifier = _plain_identifier(free_call["args"][0])
        if not identifier:
            continue
        inner_start, inner_end = _scope_for(context, free_call["offset"])
        func_scope = context.function_scope_for(free_call["offset"])
        outer_start, outer_end = func_scope if func_scope else (inner_start, inner_end)

        pattern = re.compile(r"\b" + re.escape(identifier) + r"\b")

        # Determine how far the freed state can flow:
        # 1) Inside its own block up to an unconditional terminator (`return`, `goto`, `break`, ...).
        # 2) If its block does NOT exit early and is nested inside a function, flow out into
        #    unconditional statements of the enclosing scope (skipping any mutually-exclusive `else`).
        term_in_inner = _has_same_depth_terminator(context.masked, free_call["end"], inner_end)
        segments = []
        if term_in_inner is not None:
            segments.append((free_call["end"], term_in_inner, False))
        else:
            segments.append((free_call["end"], inner_end, False))
            if inner_end < outer_end:
                resume = _else_branch_end(context.masked, inner_end, outer_end)
                term_in_outer = _has_same_depth_terminator(context.masked, resume, outer_end)
                limit = term_in_outer if term_in_outer is not None else outer_end
                if resume < limit:
                    segments.append((resume, limit, True))

        state = "freed"
        reported = False

        for seg_start, seg_end, unconditional_only in segments:
            if reported or state != "freed":
                break
            cursor = seg_start
            while cursor < seg_end:
                match = pattern.search(context.masked, cursor, seg_end)
                if not match:
                    break
                cursor = match.end()

                if unconditional_only:
                    # Only inspect statements directly in the enclosing function body,
                    # avoiding sibling `if (...)` branches that may be mutually exclusive.
                    hit_scope = _scope_for(context, match.start())
                    if hit_scope != (outer_start, outer_end):
                        continue

                event = free_events.get(match.start())
                if event is not None and event[1] == identifier:
                    call = event[0]
                    if state == "freed" and double_rule is not None:
                        line = context.position(call["offset"])[0]
                        if not is_suppressed(context.lines, line):
                            note = (
                                "conditional free() of '{}' can reach a second free()".format(identifier)
                                if unconditional_only
                                else "second free() of '{}' in the same block".format(identifier)
                            )
                            findings.append(make_finding(
                                context, context.file_label, double_rule, call,
                                confidence="medium",
                                note=note,
                            ))
                        reported = True
                        break
                    if state != "null":
                        state = "freed"
                    cursor = call["end"]
                    continue

                next_char = match.end()
                while next_char < seg_end and context.masked[next_char].isspace():
                    next_char += 1
                is_assignment = (
                    next_char < seg_end
                    and context.masked[next_char] == "="
                    and not (next_char + 1 < seg_end and context.masked[next_char + 1] == "=")
                )
                if is_assignment:
                    rhs = _rhs_assigned_value(context.source, next_char, seg_end)
                    state = "null" if _is_null_rhs(rhs) else "live"
                    continue

                if state == "freed" and uaf_rule is not None:
                    line = context.position(match.start())[0]
                    if not is_suppressed(context.lines, line):
                        note = (
                            "conditional free() of '{}' without return flows into use".format(identifier)
                            if unconditional_only
                            else "'{}' is used after free() in the same block".format(identifier)
                        )
                        findings.append(make_finding(
                            context, context.file_label, uaf_rule,
                            {"offset": match.start()},
                            confidence="medium",
                            note=note,
                        ))
                    reported = True
                    break
    return findings


def scan_stack_returns(context, rules):
    stack_rule = next((rule for rule in rules if rule["matcher"] == "stack_return"), None)
    if stack_rule is None:
        return []

    # Track pointers initialized/assigned from alloca() or local stack buffers inside functions.
    alloca_ptrs = []
    assign_re = re.compile(
        r"\b([A-Za-z_]\w*)\s*=\s*(?:__builtin_alloca|alloca)\s*\("
    )
    for match in assign_re.finditer(context.masked):
        f_scope = context.function_scope_for(match.start(1))
        if f_scope:
            alloca_ptrs.append((match.group(1), match.start(1), f_scope[0], f_scope[1]))

    findings = []
    for match in _RETURN_STMT_RE.finditer(context.masked):
        ret_offset = match.start()
        f_scope = context.function_scope_for(ret_offset)
        if not f_scope:
            continue
        expr = context.source[match.start(1):match.end(1)].strip()
        while expr.startswith("(") and expr.endswith(")"):
            inner = expr[1:-1].strip()
            if inner.count("(") == inner.count(")"):
                expr = inner
            else:
                break
        # Strip leading pointer cast e.g. `return (char *)buf;`
        cast = re.match(
            r"^\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?"
            r"(?:(?:struct|union|enum)\s+)?[A-Za-z_]\w*(?:\s*\*)*\s*\)\s*",
            expr,
        )
        if cast:
            expr = expr[cast.end():].strip()

        note = None
        addr_match = re.fullmatch(r"&\s*([A-Za-z_]\w*)(?:\s*\[[^\]]+\])?", expr)
        plain = _plain_identifier(expr)

        if addr_match:
            ident = addr_match.group(1)
            decl = context.buffer_decl_at(ident, ret_offset)
            if decl and not decl["is_static"] and decl["scope_start"] >= f_scope[0]:
                note = "returns stack address of local buffer '{}'".format(ident)
            elif any(
                item["name"] == ident
                and item["scope_start"] >= f_scope[0]
                and item["offset"] <= ret_offset <= item["scope_end"]
                for item in context.stack_locals
            ):
                note = "returns address of stack variable '{}'".format(ident)
        elif plain:
            decl = context.buffer_decl_at(plain, ret_offset)
            if decl and not decl["is_static"] and decl["scope_start"] >= f_scope[0]:
                note = "returns stack-allocated local array '{}'".format(plain)
            elif any(
                name == plain and start <= ret_offset <= end and decl_pos <= ret_offset
                for name, decl_pos, start, end in alloca_ptrs
            ):
                note = "returns alloca() stack pointer '{}'".format(plain)

        if note:
            line = context.position(ret_offset)[0]
            if not is_suppressed(context.lines, line):
                findings.append(make_finding(
                    context, context.file_label, stack_rule,
                    {"offset": ret_offset},
                    confidence="high",
                    note=note,
                ))
    return findings


def analyze_source(source, file_label, rules, context=None):
    context = context or SourceContext(source)
    context.file_label = file_label
    findings = []

    for rule in rules:
        if rule["matcher"] in ("double_free", "use_after_free", "stack_return"):
            continue
        names = set(rule.get("functions", []))
        if not names:
            continue
        matcher = MATCHERS[rule["matcher"]]
        for call in context.calls:
            if call["name"] not in names:
                continue
            result = matcher(rule, call, context)
            if result is None:
                continue
            if isinstance(result, tuple):
                confidence, note = result
            else:
                confidence, note = result, None
            line = context.position(call["offset"])[0]
            if is_suppressed(context.lines, line):
                continue
            findings.append(make_finding(
                context, file_label, rule, call, confidence=confidence, note=note,
            ))

    findings.extend(scan_lifetime(context, rules))
    findings.extend(scan_stack_returns(context, rules))
    return dedupe(findings)


def dedupe(findings):
    unique = []
    seen = set()
    for finding in findings:
        key = (finding["file"], finding["line"], finding["id"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def sort_findings(findings):
    return sorted(findings, key=lambda item: (
        severity_rank(item["severity"]), item["file"], item["line"], item["id"],
    ))


def iter_source_files(target):
    path = Path(target)
    if path.is_file():
        yield path, path.name
        return
    if not path.is_dir():
        raise FileNotFoundError("target '{}' is not a file or directory".format(target))

    for root, directories, files in os.walk(str(path)):
        directories[:] = sorted(directory for directory in directories if directory not in SKIP_DIRS)
        for name in sorted(files):
            if Path(name).suffix.lower() not in SOURCE_SUFFIXES:
                continue
            file_path = Path(root) / name
            yield file_path, str(file_path.relative_to(path))


def analyze_path(target, rules):
    findings = []
    for path, label in iter_source_files(target):
        source = path.read_text(encoding="utf-8", errors="ignore")
        findings.extend(analyze_source(source, label, rules))
    return sort_findings(dedupe(findings))


def filter_by_severity(findings, severity):
    if not severity or severity == "all":
        return findings
    severity = severity.lower()
    return [finding for finding in findings if finding["severity"] == severity]


def reaches_threshold(findings, threshold):
    if not threshold:
        return False
    limit = SEVERITY_ORDER.get(threshold.lower(), -1)
    return any(SEVERITY_ORDER.get(finding["severity"], len(SEVERITIES)) <= limit for finding in findings)


def build_report(target, findings, rules_count):
    summary = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        summary[finding["severity"]] += 1
    summary["total"] = len(findings)
    return {
        "tool": "BOAR",
        "version": "1.2.0",
        "timestamp": datetime.now().isoformat(),
        "target": str(target),
        "rules_loaded": rules_count,
        "summary": summary,
        "findings": findings,
    }


def render_text(report):
    lines = [
        "=" * 80,
        " BOAR MEMORY-SAFETY REPORT",
        "=" * 80,
        "Target: {}".format(report["target"]),
        "Rules: {} | Findings: {}".format(report["rules_loaded"], report["summary"]["total"]),
        "",
    ]

    if not report["findings"]:
        lines.append("No potential memory-safety issues matched the loaded rules.")
        lines.append("")
    else:
        for severity in SEVERITIES:
            group = [item for item in report["findings"] if item["severity"] == severity]
            if not group:
                continue
            lines.append("{} SEVERITY ({} items)".format(severity.upper(), len(group)))
            lines.append("-" * 80)
            for finding in group:
                lines.append("[{}] {} {} (confidence: {})".format(
                    severity.upper(), finding["id"], finding["rule"], finding["confidence"],
                ))
                lines.append("  Location: {}:{}:{}".format(
                    finding["file"], finding["line"], finding["column"],
                ))
                lines.append("  Code: {}".format(finding["code"]))
                if finding["cwe"]:
                    lines.append("  CWE: {}".format(", ".join(finding["cwe"])))
                if finding["references"]:
                    lines.append("  References: {}".format(", ".join(finding["references"])))
                lines.append("  Why: {}".format(finding["description"]))
                if finding.get("note"):
                    lines.append("  Note: {}".format(finding["note"]))
                lines.append("  Fix: {}".format(finding["remediation"]))
                lines.append("")
            lines.append("")

    lines.append("SUMMARY")
    lines.append("-" * 80)
    for severity in SEVERITIES:
        lines.append("  {:<9} {}".format(severity.upper(), report["summary"][severity]))
    lines.append("  {:<9} {}".format("TOTAL", report["summary"]["total"]))
    return "\n".join(lines)


_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SARIF_SECURITY_SCORE = {
    "critical": "9.0",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.5",
    "info": "1.0",
}


def build_sarif(target, findings, rules):
    """Build a SARIF 2.1.0 document compatible with GitHub Code Scanning."""
    sarif_rules = []
    rule_index = {}
    for idx, rule in enumerate(rules):
        rule_index[rule["id"]] = idx
        severity = rule.get("severity", "medium").lower()
        tags = ["security", "memory-safety"] + list(rule.get("cwe", []))
        help_parts = [rule.get("description", "")]
        if rule.get("remediation"):
            help_parts.append("Remediation: {}".format(rule["remediation"]))
        if rule.get("references"):
            help_parts.append("References: {}".format(", ".join(rule["references"])))

        sarif_rules.append({
            "id": rule["id"],
            "name": rule["name"],
            "shortDescription": {"text": rule.get("description") or rule["name"]},
            "help": {"text": "\n".join(part for part in help_parts if part)},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(severity, "warning"),
            },
            "properties": {
                "tags": tags,
                "precision": rule.get("confidence", "medium"),
                "security-severity": _SARIF_SECURITY_SCORE.get(severity, "5.0"),
            },
        })

    results = []
    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        msg = finding.get("description", finding["rule"])
        if finding.get("note"):
            msg = "{} ({})".format(msg, finding["note"])
        uri = str(finding["file"]).replace("\\", "/")
        result = {
            "ruleId": finding["id"],
            "level": _SARIF_LEVEL.get(severity, "warning"),
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": max(1, int(finding.get("line", 1))),
                            "startColumn": max(1, int(finding.get("column", 1))),
                            "snippet": {"text": finding.get("code", "")},
                        },
                    }
                }
            ],
            "properties": {
                "severity": severity,
                "confidence": finding.get("confidence", "medium"),
                "cwe": list(finding.get("cwe", [])),
            },
        }
        if finding["id"] in rule_index:
            result["ruleIndex"] = rule_index[finding["id"]]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "BOAR",
                        "fullName": "BOAR - Buffer Overflow Analysis & Remediation Framework",
                        "version": "1.2.0",
                        "informationUri": "https://github.com/AtokTajuddin/BOAR_Project",
                        "rules": sarif_rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "workingDirectory": {"uri": str(target).replace("\\", "/")},
                    }
                ],
                "results": results,
            }
        ],
    }
