(() => {
  "use strict";

  const ROOT = typeof window !== "undefined" ? window : globalThis;
  const RULES = (ROOT.BOAR_RULES && ROOT.BOAR_RULES.rules) || [];
  const HERO = ROOT.BOAR_HERO || null;

  const SEVERITIES = ["critical", "high", "medium", "low"];
  const SEVERITY_LABEL = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    all: "All",
  };
  const SEVERITY_COLOR = {
    critical: "#ff6b6b",
    high: "#ffa94d",
    medium: "#6b9bff",
    low: "#6be0a0",
  };
  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const FILTER_KEYS = ["all", "critical", "high", "medium", "low"];

  const SAMPLE = `#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NOTE_CAP 64

struct item { int size; };

void read_name(void) {
    char name[32];
    gets(name);
    printf(name);
}

void copy_note(char *input, int size) {
    char note[NOTE_CAP];
    strcpy(note, input);
    strncat(note, input, sizeof(note));
    memcpy(note, input, size);
    sprintf(note, "note: %s", input);
}

void read_count(void) {
    char count[8];
    scanf("%99s", count);
}

char *leak_stack(int n) {
    char local_buf[16];
    char *scratch = alloca(n);
    memset(scratch, 0, sizeof(scratch));
    return local_buf;
}

int main(int argc, char **argv) {
    struct item *p = malloc(sizeof(*p));
    free(p);
    p->size = 1;
    free(p);
    if (argc > 1) copy_note(argv[1], 32);
    return 0;
}
`;

  const clamp = (value, low, high) => Math.min(high, Math.max(low, value));
  const escapeRe = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // ---------------------------------------------------------------------------
  // Static analysis engine: browser port kept in parity with boar_engine.py.
  // ---------------------------------------------------------------------------

  const TYPE_PREFIX_RE = /\b(?:void|int|char|short|long|float|double|size_t|ssize_t|ptrdiff_t|unsigned|signed|struct|enum|union|const|static|inline|extern|_Bool|bool|wchar_t|u?int(?:8|16|32|64)_t|FILE|va_list)\s+\**\s*$/;
  const CALL_RE = /\b([A-Za-z_]\w*)\s*\(/g;
  const STRING_ONLY_RE = /^(?:\s*(?:u8|u|U|L)?"(?:\\.|[^"\\])*"\s*)+$/s;
  const STRING_TOKEN_RE = /(?:u8|u|U|L)?"((?:\\.|[^"\\])*)"/gs;
  const CONVERSION_RE = /%(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|L|j|z|t)?([diouxXeEfFgGaAcspn\[%])/g;
  const SCANF_CONV_RE = /%(\*)?(\d+)?(?:hh|h|ll|l|L|j|z|t)?(\[(?:\^?\]?[^\]]*)\]|[diouxXeEfFgGaAcspn%])/g;

  const ELEM_BYTES = {
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
  };

  const BUFFER_DECL_RE = /\b((?:(?:static|const|volatile|register)\s+)*)((?:unsigned|signed)\s+long\s+long|(?:unsigned|signed)\s+(?:char|short|int)|long\s+long|char|short|int|wchar_t|u?int(?:8|16|32|64)_t)\s+([A-Za-z_]\w*)\s*\[\s*([^\]\n;]+?)\s*\]/g;
  const DEFINE_CONST_RE = /^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+([^\n]+)/gm;
  const TYPED_CONST_RE = /\b(?:static\s+)?const\s+(?:unsigned\s+|signed\s+)?(?:size_t|ssize_t|int|long|short|u?int(?:8|16|32|64)_t)\s+([A-Za-z_]\w*)\s*=\s*([^;,\n]+)/g;
  const ENUM_BLOCK_RE = /\benum(?:\s+[A-Za-z_]\w*)?\s*\{([^}]*)\}/gs;
  const ENUM_ITEM_RE = /^\s*([A-Za-z_]\w*)\s*(?:=\s*([^,\n}]+))?/;
  const PTR_DECL_RE = /\b(?:const\s+|volatile\s+|static\s+|register\s+)*(?:(?:struct|union|enum)\s+[A-Za-z_]\w*|(?:unsigned|signed)\s+(?:char|short|int|long(?:\s+long)?)|void|char|short|int|long(?:\s+long)?|float|double|wchar_t|size_t|ssize_t|u?int(?:8|16|32|64)_t|FILE)\s*\*+\s*(?:const\s+|volatile\s+|restrict\s+)*([A-Za-z_]\w*)\s*(?=[,;=\)])/g;
  const SIGNED_DECL_RE = /\b(?:const\s+|volatile\s+|register\s+)*(?:signed\s+(?:char|short|int|long(?:\s+long)?)|short|int|long(?:\s+long)?|ssize_t|ptrdiff_t|int(?:8|16|32|64)_t)\s+([A-Za-z_]\w*)\s*(?=[,;=\)])/g;
  const LOCAL_SCALAR_DECL_RE = /\b((?:(?:static|const|volatile|register)\s+)*)(?:(?:struct|union|enum)\s+[A-Za-z_]\w*|(?:unsigned|signed)\s+(?:char|short|int|long(?:\s+long)?)|char|short|int|long(?:\s+long)?|float|double|wchar_t|bool|_Bool|size_t|ssize_t|u?int(?:8|16|32|64)_t)\s+([A-Za-z_]\w*)\s*(?=[;=,])/g;
  const FUNC_PARAM_ARRAY_RE = /\b(?:const\s+|volatile\s+)*(?:(?:unsigned|signed)\s+(?:char|short|int|long(?:\s+long)?)|char|short|int|long(?:\s+long)?|wchar_t|u?int(?:8|16|32|64)_t)\s+([A-Za-z_]\w*)\s*\[[^\]]*\]/g;
  const SIZEOF_IDENT_RE = /\bsizeof\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*)\b)/g;
  const RETURN_STMT_RE = /\breturn\s+([^;]+);/g;
  const TERMINATOR_RE = /^(?:return|goto|break|continue)\b|^(?:exit|_Exit|abort|longjmp)\s*\(/;
  const NULL_VALUES = new Set(["NULL", "0", "nullptr"]);

  function maskNoncode(source) {
    const out = source.split("");
    let i = 0;
    const size = source.length;
    while (i < size) {
      const ch = source[i];
      if (ch === "/" && source[i + 1] === "/") {
        out[i] = out[i + 1] = " ";
        i += 2;
        while (i < size && source[i] !== "\n") out[i++] = " ";
      } else if (ch === "/" && source[i + 1] === "*") {
        out[i] = out[i + 1] = " ";
        i += 2;
        while (i < size) {
          if (source[i] === "*" && source[i + 1] === "/") {
            out[i] = out[i + 1] = " ";
            i += 2;
            break;
          }
          if (source[i] !== "\n") out[i] = " ";
          i += 1;
        }
      } else if (ch === '"' || ch === "'") {
        const quote = ch;
        out[i++] = " ";
        while (i < size) {
          if (source[i] === "\\") {
            out[i] = " ";
            if (i + 1 < size) out[i + 1] = " ";
            i += 2;
            continue;
          }
          if (source[i] === quote) {
            out[i++] = " ";
            break;
          }
          if (source[i] !== "\n") out[i] = " ";
          i += 1;
        }
      } else {
        i += 1;
      }
    }
    return out.join("");
  }

  function splitArgs(text) {
    if (!text.trim()) return [];
    const args = [];
    let depth = 0;
    let start = 0;
    let i = 0;
    while (i < text.length) {
      const ch = text[i];
      if (ch === '"' || ch === "'") {
        const quote = ch;
        i += 1;
        while (i < text.length) {
          if (text[i] === "\\") {
            i += 2;
            continue;
          }
          if (text[i] === quote) {
            i += 1;
            break;
          }
          i += 1;
        }
        continue;
      }
      if (ch === "(" || ch === "[" || ch === "{") depth += 1;
      else if (ch === ")" || ch === "]" || ch === "}") depth -= 1;
      else if (ch === "," && depth === 0) {
        args.push(text.slice(start, i).trim());
        start = i + 1;
      }
      i += 1;
    }
    args.push(text.slice(start).trim());
    return args;
  }

  function extractCalls(source, masked) {
    const calls = [];
    const re = new RegExp(CALL_RE.source, "g");
    let match;
    while ((match = re.exec(masked))) {
      const name = match[1];
      const start = match.index;
      const before = masked.slice(0, start).replace(/\s+$/, "");
      if (before.endsWith(".") || before.endsWith("->")) continue;
      if (TYPE_PREFIX_RE.test(masked.slice(Math.max(0, start - 100), start))) continue;
      const lineStart = masked.lastIndexOf("\n", start) + 1;
      if (masked.slice(lineStart, start).replace(/^\s+/, "").startsWith("#")) continue;

      const open = match.index + match[0].length - 1;
      let depth = 1;
      let cursor = open + 1;
      while (cursor < masked.length && depth) {
        if (masked[cursor] === "(") depth += 1;
        else if (masked[cursor] === ")") depth -= 1;
        cursor += 1;
      }
      if (depth) continue;
      calls.push({
        name,
        offset: start,
        end: cursor,
        args: splitArgs(source.slice(open + 1, cursor - 1)),
      });
    }
    return calls;
  }

  function findBracePairs(masked) {
    const pairs = [];
    const stack = [];
    for (let i = 0; i < masked.length; i += 1) {
      if (masked[i] === "{") stack.push(i);
      else if (masked[i] === "}" && stack.length) pairs.push([stack.pop(), i]);
    }
    return pairs;
  }

  function numericValue(expression) {
    const text = expression.trim().replace(/(?:u|l)+$/i, "");
    if (!/^[+-]?(?:0x[0-9a-f]+|0[0-7]*|[1-9]\d*)$/i.test(text)) return null;
    if (/^[+-]?0[0-7]+$/.test(text)) {
      const sign = text.startsWith("-") ? -1 : 1;
      return sign * parseInt(text.replace(/^[+-]/, ""), 8);
    }
    const value = Number(text);
    return Number.isNaN(value) ? null : value;
  }

  function evalIntExpr(expression, constants) {
    if (!expression) return null;
    const direct = numericValue(expression);
    if (direct !== null) return direct;

    const map = constants || new Map();
    const stripped = expression.trim();
    if (!stripped) return null;
    const tokenRe = /\s*(?:(<<|>>|[+\-*/()])|(0x[0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)|([A-Za-z_]\w*))/y;
    const tokens = [];
    let pos = 0;
    while (pos < stripped.length) {
      tokenRe.lastIndex = pos;
      const match = tokenRe.exec(stripped);
      if (!match) return null;
      if (match[1]) {
        tokens.push(["op", match[1]]);
      } else if (match[2]) {
        const val = numericValue(match[2]);
        if (val === null) return null;
        tokens.push(["num", val]);
      } else if (match[3]) {
        if (!map.has(match[3])) return null;
        tokens.push(["num", map.get(match[3])]);
      }
      pos = tokenRe.lastIndex;
    }

    let cursor = 0;
    const peek = () => (cursor < tokens.length ? tokens[cursor] : null);
    const consume = () => tokens[cursor++];

    function parseShift() {
      let left = parseAdd();
      if (left === null) return null;
      while (true) {
        const tok = peek();
        if (tok && tok[0] === "op" && (tok[1] === "<<" || tok[1] === ">>")) {
          const op = consume()[1];
          const right = parseAdd();
          if (right === null || right < 0 || right > 52) return null;
          left = op === "<<" ? left * (2 ** right) : Math.floor(left / (2 ** right));
        } else break;
      }
      return left;
    }

    function parseAdd() {
      let left = parseMul();
      if (left === null) return null;
      while (true) {
        const tok = peek();
        if (tok && tok[0] === "op" && (tok[1] === "+" || tok[1] === "-")) {
          const op = consume()[1];
          const right = parseMul();
          if (right === null) return null;
          left = op === "+" ? left + right : left - right;
        } else break;
      }
      return left;
    }

    function parseMul() {
      let left = parseUnary();
      if (left === null) return null;
      while (true) {
        const tok = peek();
        if (tok && tok[0] === "op" && (tok[1] === "*" || tok[1] === "/")) {
          const op = consume()[1];
          const right = parseUnary();
          if (right === null) return null;
          if (op === "/") {
            if (right === 0) return null;
            left = Math.trunc(left / right);
          } else {
            left *= right;
          }
        } else break;
      }
      return left;
    }

    function parseUnary() {
      const tok = peek();
      if (!tok) return null;
      if (tok[0] === "op" && (tok[1] === "+" || tok[1] === "-")) {
        const op = consume()[1];
        const val = parseUnary();
        if (val === null) return null;
        return op === "+" ? val : -val;
      }
      if (tok[0] === "op" && tok[1] === "(") {
        consume();
        const val = parseShift();
        const endTok = peek();
        if (val === null || !endTok || endTok[0] !== "op" || endTok[1] !== ")") return null;
        consume();
        return val;
      }
      if (tok[0] === "num") return consume()[1];
      return null;
    }

    const value = parseShift();
    return value === null || cursor !== tokens.length ? null : value;
  }

  function collectConstants(masked) {
    const constants = new Map();
    const rawDefs = [];

    const defRe = new RegExp(DEFINE_CONST_RE.source, "gm");
    let match;
    while ((match = defRe.exec(masked))) {
      const name = match[1];
      const nameIdx = masked.indexOf(name, match.index);
      if (masked[nameIdx + name.length] === "(") continue;
      rawDefs.push([name, match[2].trim()]);
    }

    const typedRe = new RegExp(TYPED_CONST_RE.source, "g");
    while ((match = typedRe.exec(masked))) {
      rawDefs.push([match[1], match[2].trim()]);
    }

    const enumRe = new RegExp(ENUM_BLOCK_RE.source, "gs");
    while ((match = enumRe.exec(masked))) {
      let nextVal = 0;
      for (const item of match[1].split(",")) {
        const part = item.trim();
        if (!part) continue;
        const itemMatch = ENUM_ITEM_RE.exec(part);
        if (!itemMatch) continue;
        const [, ident, explicit] = itemMatch;
        if (explicit !== undefined) {
          const resolved = evalIntExpr(explicit, constants);
          if (resolved === null) {
            nextVal = null;
            continue;
          }
          nextVal = resolved;
        }
        if (nextVal !== null) {
          constants.set(ident, nextVal);
          nextVal += 1;
        }
      }
    }

    for (let pass = 0; pass < 3; pass += 1) {
      let progressed = false;
      for (const [name, expr] of rawDefs) {
        const val = evalIntExpr(expr, constants);
        if (val !== null && constants.get(name) !== val) {
          constants.set(name, val);
          progressed = true;
        }
      }
      if (!progressed) break;
    }
    return constants;
  }

  function enclosingScope(bracePairs, offset, totalLen) {
    let best = null;
    for (const [start, end] of bracePairs) {
      if (start < offset && offset < end) {
        if (!best || end - start < best[1] - best[0]) best = [start, end];
      }
    }
    return best || [0, totalLen];
  }

  function functionScopes(masked, bracePairs) {
    const sorted = bracePairs.slice().sort((a, b) => a[0] - b[0] || (b[1] - b[0]) - (a[1] - a[0]));
    const outer = [];
    for (const [start, end] of sorted) {
      if (outer.some(([ps, pe]) => ps < start && end < pe)) continue;
      const before = masked.slice(0, start).replace(/\s+$/, "");
      if (!before.endsWith(")")) continue;
      const closeParen = before.length - 1;
      let depth = 1;
      let cursor = closeParen - 1;
      while (cursor >= 0 && depth) {
        if (before[cursor] === ")") depth += 1;
        else if (before[cursor] === "(") depth -= 1;
        cursor -= 1;
      }
      const paramSpan = depth === 0 ? [cursor + 1, closeParen] : null;
      outer.push([start, end, paramSpan]);
    }
    return outer;
  }

  function collectScopedBuffers(masked, bracePairs, constants, funcScopes) {
    const paramRanges = funcScopes.map((s) => s[2]).filter(Boolean);
    const decls = [];
    const re = new RegExp(BUFFER_DECL_RE.source, "g");
    let match;
    while ((match = re.exec(masked))) {
      const storage = match[1] || "";
      const rawType = match[2].trim().replace(/\s+/g, " ");
      const name = match[3];
      const sizeExpr = match[4];
      const offset = match.index + match[0].indexOf(name, storage.length + match[2].length);
      if (paramRanges.some(([ps, pe]) => ps <= offset && offset <= pe)) continue;
      const count = evalIntExpr(sizeExpr, constants);
      if (count === null || count <= 0) continue;
      const elemBytes = ELEM_BYTES[rawType] || 1;
      const [scopeStart, scopeEnd] = enclosingScope(bracePairs, offset, masked.length);
      decls.push({
        name,
        elements: count,
        bytes: count * elemBytes,
        elemBytes,
        offset,
        scopeStart,
        scopeEnd,
        isStatic: /\bstatic\b/.test(storage),
      });
    }
    return decls;
  }

  function collectScopedSymbols(masked, bracePairs, funcScopes) {
    const pointers = [];
    const signedVars = [];
    const stackLocals = [];

    function paramOwnerScope(offset) {
      for (const [fs, fe, span] of funcScopes) {
        if (span && span[0] <= offset && offset <= span[1]) return [fs, fe, true];
      }
      const [ss, se] = enclosingScope(bracePairs, offset, masked.length);
      return [ss, se, false];
    }

    let match;
    const ptrRe = new RegExp(PTR_DECL_RE.source, "g");
    while ((match = ptrRe.exec(masked))) {
      const name = match[1];
      const offset = match.index + match[0].lastIndexOf(name);
      const [ss, se, isParam] = paramOwnerScope(offset);
      pointers.push({
        name,
        offset: isParam ? ss : offset,
        scopeStart: ss,
        scopeEnd: se,
        kind: "pointer",
      });
    }

    for (const [fs, fe, span] of funcScopes) {
      if (!span) continue;
      const paramText = masked.slice(span[0], span[1]);
      const arrRe = new RegExp(FUNC_PARAM_ARRAY_RE.source, "g");
      while ((match = arrRe.exec(paramText))) {
        pointers.push({
          name: match[1],
          offset: fs,
          scopeStart: fs,
          scopeEnd: fe,
          kind: "decayed_array_param",
        });
      }
    }

    const signedRe = new RegExp(SIGNED_DECL_RE.source, "g");
    while ((match = signedRe.exec(masked))) {
      const name = match[1];
      const offset = match.index + match[0].lastIndexOf(name);
      const [ss, se, isParam] = paramOwnerScope(offset);
      signedVars.push({
        name,
        offset: isParam ? ss : offset,
        scopeStart: ss,
        scopeEnd: se,
      });
    }

    const scalarRe = new RegExp(LOCAL_SCALAR_DECL_RE.source, "g");
    while ((match = scalarRe.exec(masked))) {
      const storage = match[1] || "";
      const name = match[2];
      const offset = match.index + match[0].lastIndexOf(name);
      const [ss, se, isParam] = paramOwnerScope(offset);
      if (ss === 0 && se === masked.length) continue;
      if (/\bstatic\b/.test(storage)) continue;
      stackLocals.push({
        name,
        offset: isParam ? ss : offset,
        scopeStart: ss,
        scopeEnd: se,
        isParam,
      });
    }

    return { pointers, signedVars, stackLocals };
  }

  class SourceContext {
    constructor(source) {
      this.source = source;
      this.masked = maskNoncode(source);
      this.lines = source.split("\n");
      this.lineStarts = [0];
      for (let i = 0; i < source.length; i += 1) {
        if (source[i] === "\n") this.lineStarts.push(i + 1);
      }
      this.calls = extractCalls(source, this.masked);
      this.bracePairs = findBracePairs(this.masked);
      this.constants = collectConstants(this.masked);
      this.funcScopes = functionScopes(this.masked, this.bracePairs);
      this.bufferDecls = collectScopedBuffers(
        this.masked, this.bracePairs, this.constants, this.funcScopes,
      );
      const syms = collectScopedSymbols(this.masked, this.bracePairs, this.funcScopes);
      this.pointers = syms.pointers;
      this.signedVars = syms.signedVars;
      this.stackLocals = syms.stackLocals;
    }

    position(offset) {
      let low = 0;
      let high = this.lineStarts.length - 1;
      while (low < high) {
        const mid = Math.ceil((low + high) / 2);
        if (this.lineStarts[mid] <= offset) low = mid;
        else high = mid - 1;
      }
      return [low + 1, offset - this.lineStarts[low] + 1];
    }

    lineText(line) {
      if (line < 1 || line > this.lines.length) return "";
      return this.lines[line - 1].trim();
    }

    evalInt(expression) {
      return evalIntExpr(expression, this.constants);
    }

    pointerAt(name, offset) {
      if (!name) return null;
      const candidates = this.pointers.filter((item) => (
        item.name === name
        && item.scopeStart <= offset && offset <= item.scopeEnd
        && item.offset <= offset
      ));
      if (!candidates.length) return null;
      candidates.sort((a, b) => (a.scopeEnd - a.scopeStart) - (b.scopeEnd - b.scopeStart) || b.offset - a.offset);
      const best = candidates[0];
      const innerArray = this.bufferDecls.some((decl) => (
        decl.name === name
        && decl.scopeStart <= offset && offset <= decl.scopeEnd
        && decl.offset <= offset
        && (decl.scopeEnd - decl.scopeStart) < (best.scopeEnd - best.scopeStart)
      ));
      return innerArray ? null : best;
    }

    bufferDeclAt(name, offset) {
      if (!name) return null;
      const ptr = this.pointerAt(name, offset);
      const candidates = this.bufferDecls.filter((decl) => (
        decl.name === name
        && decl.scopeStart <= offset && offset <= decl.scopeEnd
        && (decl.offset <= offset || decl.scopeStart === 0)
      ));
      if (!candidates.length) return null;
      candidates.sort((a, b) => (a.scopeEnd - a.scopeStart) - (b.scopeEnd - b.scopeStart) || b.offset - a.offset);
      const best = candidates[0];
      if (ptr) {
        const ptrSpan = ptr.scopeEnd - ptr.scopeStart;
        const bufSpan = best.scopeEnd - best.scopeStart;
        if (ptrSpan < bufSpan || (ptrSpan === bufSpan && ptr.offset > best.offset)) return null;
      }
      return best;
    }

    bufferCapacity(name, offset, inElements = false) {
      const decl = this.bufferDeclAt(name, offset);
      if (!decl) return null;
      return inElements ? decl.elements : decl.bytes;
    }

    isSignedVar(name, offset) {
      if (!name) return false;
      return this.signedVars.some((item) => (
        item.name === name
        && item.scopeStart <= offset && offset <= item.scopeEnd
        && item.offset <= offset
      ));
    }

    functionScopeFor(offset) {
      for (const [fs, fe] of this.funcScopes) {
        if (fs <= offset && offset <= fe) return [fs, fe];
      }
      return null;
    }
  }

  function decodedCStringLength(raw) {
    let length = 0;
    let i = 0;
    while (i < raw.length) {
      if (raw[i] === "\\" && i + 1 < raw.length) {
        const nxt = raw[i + 1];
        if (nxt === "x") {
          i += 2;
          while (i < raw.length && /[0-9a-fA-F]/.test(raw[i])) i += 1;
          length += 1;
          continue;
        }
        if (/[0-7]/.test(nxt)) {
          const end = Math.min(raw.length, i + 4);
          i += 2;
          while (i < end && /[0-7]/.test(raw[i])) i += 1;
          length += 1;
          continue;
        }
        i += 2;
        length += 1;
        continue;
      }
      i += 1;
      length += 1;
    }
    return length;
  }

  function literalText(argument) {
    if (!argument || !STRING_ONLY_RE.test(argument.trim())) return null;
    const re = new RegExp(STRING_TOKEN_RE.source, "gs");
    let match;
    let out = "";
    while ((match = re.exec(argument))) out += match[1];
    return out;
  }

  function literalByteLength(argument) {
    if (!argument || !STRING_ONLY_RE.test(argument.trim())) return null;
    const re = new RegExp(STRING_TOKEN_RE.source, "gs");
    let match;
    let total = 0;
    while ((match = re.exec(argument))) total += decodedCStringLength(match[1]);
    return total;
  }

  function baseIdentifier(expression) {
    let text = expression.trim();
    while (true) {
      const cast = /^\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:(?:struct|union|enum)\s+)?[A-Za-z_]\w*(?:\s*\*)*\s*\)\s*/.exec(text);
      if (!cast) break;
      text = text.slice(cast[0].length);
    }
    const match = /^&?\s*([A-Za-z_]\w*)/.exec(text);
    return match ? match[1] : null;
  }

  function sizeofTarget(expression) {
    const match = /^\s*sizeof\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))\s*$/.exec(expression);
    return match ? (match[1] || match[2]) : null;
  }

  function sizeofMinusOneTarget(expression) {
    const match = /^\s*sizeof\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))\s*-\s*1[uUlL]*\s*$/.exec(expression);
    return match ? (match[1] || match[2]) : null;
  }

  function resolveBoundBytes(expression, context, offset, inElements = false) {
    const val = context.evalInt(expression);
    if (val !== null) return val;
    const ident = sizeofTarget(expression);
    if (ident) return context.bufferCapacity(ident, offset, inElements);
    const identM1 = sizeofMinusOneTarget(expression);
    if (identM1) {
      const cap = context.bufferCapacity(identM1, offset, inElements);
      return cap !== null ? cap - 1 : null;
    }
    return null;
  }

  function formatArgument(rule, call) {
    const map = rule.format_arg || {};
    const index = Object.prototype.hasOwnProperty.call(map, call.name) ? map[call.name] : 1;
    if (index >= call.args.length) return null;
    return call.args[index];
  }

  function stringConversions(formatText, requireUnbounded) {
    const found = [];
    const re = new RegExp(CONVERSION_RE.source, "g");
    let match;
    while ((match = re.exec(formatText))) {
      const width = match[1];
      const precision = match[2];
      const conversion = match[3];
      if (conversion === "s" || conversion === "[") {
        if (!requireUnbounded || (!width && !precision)) found.push(match[0]);
      }
    }
    return found;
  }

  function hasExplicitNullTermination(context, destName, afterOffset) {
    if (!destName) return false;
    const [, scopeEnd] = enclosingScope(context.bracePairs, afterOffset, context.masked.length);
    const tail = context.source.slice(afterOffset, scopeEnd);
    const re = new RegExp(`\\b${escapeRe(destName)}\\s*\\[[^\\]]+\\]\\s*=\\s*(?:'\\\\0'|0|L'\\\\0')\\s*;`);
    return re.test(tail);
  }

  function plainIdentifier(expression) {
    const match = /^\s*([A-Za-z_]\w*)\s*$/.exec(expression);
    return match ? match[1] : null;
  }

  const MATCHERS = {
    unsafe_call(rule) {
      return rule.confidence || "high";
    },

    unbounded_copy(rule, call, context) {
      if (call.args.length < 2) return null;
      const destination = call.args[0];
      const source = call.args[1];
      const inElements = call.name.startsWith("wcs");
      const destName = baseIdentifier(destination);
      const capacity = context.bufferCapacity(destName, call.offset, inElements);
      const litLen = literalByteLength(source);
      if (litLen === null) return "high";
      const needed = litLen + 1;
      const isCat = call.name === "strcat" || call.name === "wcscat";
      if (capacity !== null) {
        if (needed > capacity) {
          return ["high", `literal requires ${needed} units (including NUL) but '${destName}' holds ${capacity}`];
        }
        if (!isCat) return null;
        return "low";
      }
      return "medium";
    },

    format_copy(rule, call, context) {
      const formatText = formatArgument(rule, call);
      if (formatText === null) return null;
      const literal = literalText(formatText);
      if (literal === null) return "high";
      const destName = call.args.length ? baseIdentifier(call.args[0]) : null;
      const capacity = context.bufferCapacity(destName, call.offset);
      if (capacity !== null) {
        const staticPart = literal.replace(
          new RegExp(CONVERSION_RE.source, "g"),
          (_, _w, _p, conv) => (conv === "%" ? "%" : (conv !== "n" ? "X" : "")),
        );
        const minNeeded = decodedCStringLength(staticPart) + 1;
        if (minNeeded > capacity) {
          return ["high", `format string writes at least ${minNeeded} bytes (including NUL) into '${destName}' (${capacity} bytes)`];
        }
      }
      return stringConversions(literal, false).length ? "medium" : null;
    },

    scanf_width(rule, call, context) {
      const map = rule.format_arg || {};
      const index = Object.prototype.hasOwnProperty.call(map, call.name) ? map[call.name] : 0;
      if (index >= call.args.length) return null;
      const literal = literalText(call.args[index]);
      if (literal === null) return "medium";

      const isVaList = call.name.startsWith("v");
      let argCursor = index + 1;
      const re = new RegExp(SCANF_CONV_RE.source, "g");
      let match;
      while ((match = re.exec(literal))) {
        const [, suppressed, widthText, spec] = match;
        if (spec === "%" || suppressed === "*") continue;
        const destExpr = (!isVaList && argCursor < call.args.length) ? call.args[argCursor] : null;
        argCursor += 1;

        const isStringSpec = spec === "s" || spec.startsWith("[");
        if (isStringSpec) {
          if (!widthText) {
            return ["high", `unbounded '${match[0]}' conversion can overflow destination`];
          }
          if (destExpr !== null) {
            const destName = baseIdentifier(destExpr);
            const capacity = context.bufferCapacity(destName, call.offset);
            const needed = Number(widthText) + 1;
            if (capacity !== null && needed > capacity) {
              return ["high", `conversion '${match[0]}' writes up to ${needed} bytes (including NUL) into '${destName}' (${capacity} bytes)`];
            }
          }
        } else if (spec === "c" && widthText && destExpr !== null) {
          const destName = baseIdentifier(destExpr);
          const capacity = context.bufferCapacity(destName, call.offset);
          const needed = Number(widthText);
          if (capacity !== null && needed > capacity) {
            return ["high", `conversion '${match[0]}' writes ${needed} bytes into '${destName}' (${capacity} bytes)`];
          }
        }
      }
      return null;
    },

    bounded_copy(rule, call, context) {
      if (call.args.length < 3) return null;
      const lengthExpression = call.args[2];
      const inElements = call.name.startsWith("w");
      const destination = call.name === "bcopy" ? call.args[1] : call.args[0];
      const destName = baseIdentifier(destination);
      const capacity = context.bufferCapacity(destName, call.offset, inElements);

      if (/\bsizeof\b/.test(lengthExpression)) {
        const sizeofIdent = sizeofTarget(lengthExpression);
        if (sizeofIdent && context.pointerAt(sizeofIdent, call.offset) !== null) return null;
        if (sizeofIdent && capacity !== null && sizeofIdent !== destName) {
          const otherCap = context.bufferCapacity(sizeofIdent, call.offset, inElements);
          if (otherCap !== null && otherCap > capacity) {
            return ["high", `sizeof(${sizeofIdent}) (${otherCap} bytes) exceeds destination '${destName}' (${capacity} bytes)`];
          }
        }
        return null;
      }

      const length = context.evalInt(lengthExpression);
      if (length !== null) {
        if (length < 0) return ["high", "negative length wraps around when converted to size_t"];
        if (capacity === null) return "low";
        return length > capacity
          ? ["high", `copy length ${length} exceeds '${destName}' capacity (${capacity})`]
          : null;
      }
      return "medium";
    },

    format_string(rule, call) {
      const formatText = formatArgument(rule, call);
      if (formatText === null) return null;
      return literalText(formatText) !== null ? null : "high";
    },

    variable_size_alloc(rule, call, context) {
      if (!call.args.length) return null;
      if (/\bsizeof\b/.test(call.args[0]) && !call.args[0].includes("*")) return "low";
      return context.evalInt(call.args[0]) !== null ? "low" : "high";
    },

    alloc_arithmetic(rule, call, context) {
      const sizeIdx = call.name === "realloc" ? 1 : 0;
      if (call.args.length <= sizeIdx) return null;
      const expr = call.args[sizeIdx];
      if (!expr.includes("*") && !expr.includes("+")) return null;
      if (context.evalInt(expr) !== null) return null;
      if (!expr.includes("*")) {
        const parts = expr.split("+").map((p) => p.trim());
        if (parts.every((p) => context.evalInt(p) !== null || sizeofTarget(p) !== null)) return null;
      }
      return "medium";
    },

    bounded_string_copy(rule, call, context) {
      if (call.args.length < 3) return null;
      const [destExpr, srcExpr, lenExpr] = call.args;
      const destName = baseIdentifier(destExpr);
      const inElements = call.name.startsWith("wcs");
      const isCat = call.name === "strncat" || call.name === "wcsncat";
      const capacity = context.bufferCapacity(destName, call.offset, inElements);

      const sizeofIdent = sizeofTarget(lenExpr);
      if (sizeofIdent && context.pointerAt(sizeofIdent, call.offset) !== null) return null;

      const bound = resolveBoundBytes(lenExpr, context, call.offset, inElements);
      if (isCat) {
        if (sizeofIdent && sizeofIdent === destName) {
          return ["high", `${call.name}() passed sizeof(${destName}) instead of remaining space (sizeof(${destName}) - strlen(${destName}) - 1)`];
        }
        if (capacity !== null && bound !== null && bound >= capacity) {
          return ["high", `${call.name}() bound ${bound} writes up to ${bound + 1} units (including NUL) into '${destName}' (${capacity} units)`];
        }
        return null;
      }

      if (sizeofIdent && destName && sizeofIdent !== destName) {
        const otherCap = context.bufferCapacity(sizeofIdent, call.offset, inElements);
        if (capacity !== null && otherCap !== null && otherCap > capacity) {
          return ["high", `sizeof(${sizeofIdent}) (${otherCap}) exceeds destination '${destName}' (${capacity})`];
        }
        const srcName = baseIdentifier(srcExpr);
        if (sizeofIdent === srcName) {
          return ["high", `${call.name}() bound uses source size sizeof(${srcName}) instead of destination capacity`];
        }
      }

      if (capacity !== null && bound !== null) {
        if (bound > capacity) {
          return ["high", `${call.name}() bound ${bound} exceeds '${destName}' capacity (${capacity})`];
        }
        if (bound === capacity && !hasExplicitNullTermination(context, destName, call.end)) {
          return ["medium", `${call.name}() with full capacity (${capacity}) leaves '${destName}' unterminated when source length >= ${capacity}`];
        }
      } else if (sizeofIdent && sizeofIdent === destName && !hasExplicitNullTermination(context, destName, call.end)) {
        return ["medium", `${call.name}() with sizeof(${destName}) may leave '${destName}' without a NUL terminator`];
      }
      return null;
    },

    input_read_length(rule, call, context) {
      const { name, args } = call;
      let bufExpr;
      let lenExpr;
      if (name === "fgets" || name === "fgets_unlocked") {
        if (args.length < 3) return null;
        [bufExpr, lenExpr] = args;
      } else if (name === "read" || name === "pread" || name === "recv" || name === "recvfrom") {
        if (args.length < 3) return null;
        [, bufExpr, lenExpr] = args;
      } else if (name === "fread") {
        if (args.length < 4) return null;
        bufExpr = args[0];
        lenExpr = `(${args[1]}) * (${args[2]})`;
      } else {
        return null;
      }

      const destName = baseIdentifier(bufExpr);
      const capacity = context.bufferCapacity(destName, call.offset);
      const sizeofIdent = sizeofTarget(lenExpr);
      if (sizeofIdent && context.pointerAt(sizeofIdent, call.offset) !== null) return null;

      if (/\bsizeof\b/.test(lenExpr)) {
        if (capacity !== null) {
          const bound = resolveBoundBytes(lenExpr, context, call.offset);
          if (bound !== null && bound > capacity) {
            return ["high", `${name}() size ${bound} exceeds '${destName}' capacity (${capacity} bytes)`];
          }
        }
        return null;
      }

      const val = context.evalInt(lenExpr);
      if (val !== null) {
        if (val < 0) {
          return ["high", `negative read length (${val}) converts to a huge unsigned size or undefined behavior`];
        }
        if (capacity !== null && val > capacity) {
          return ["high", `${name}() requests ${val} bytes into '${destName}' (${capacity} bytes)`];
        }
        return null;
      }

      const lenIdent = plainIdentifier(lenExpr);
      if (lenIdent && context.isSignedVar(lenIdent, call.offset)) {
        if (name === "read" || name === "pread" || name === "recv" || name === "recvfrom" || name === "fread") {
          return ["medium", `signed length '${lenIdent}' passed to ${name}() without sizeof bound (negative values wrap to size_t)`];
        }
      }
      if (capacity !== null) {
        return ["medium", `${name}() reads an unverified variable length into fixed buffer '${destName}' (${capacity} bytes)`];
      }
      return null;
    },

    sizeof_pointer(rule, call, context) {
      for (const arg of call.args) {
        const re = new RegExp(SIZEOF_IDENT_RE.source, "g");
        let match;
        while ((match = re.exec(arg))) {
          const ident = match[1] || match[2];
          const ptrInfo = context.pointerAt(ident, call.offset);
          if (!ptrInfo) continue;
          if (ptrInfo.kind === "decayed_array_param") {
            return ["high", `sizeof(${ident}) on array parameter '${ident}' evaluates to pointer size, not array length`];
          }
          return ["high", `sizeof(${ident}) evaluates the pointer size (4/8 bytes), not the buffer/object '${ident}' points to`];
        }
      }
      return null;
    },
  };

  function isSuppressed(lines, line) {
    for (const number of [line, line - 1]) {
      if (number >= 1 && number <= lines.length) {
        const text = lines[number - 1].toLowerCase();
        if (text.includes("boar:ignore") || text.includes("boar-ignore")) return true;
      }
    }
    return false;
  }

  function makeFinding(context, file, rule, call, confidence, offset, note) {
    const position = context.position(offset === undefined ? call.offset : offset);
    let code = context.lineText(position[0]);
    if (code.length > 300) code = `${code.slice(0, 297)}...`;
    const finding = {
      id: rule.id,
      rule: rule.name,
      severity: rule.severity,
      confidence: confidence || rule.confidence || "medium",
      cwe: Array.isArray(rule.cwe) ? rule.cwe.slice() : [],
      references: Array.isArray(rule.references) ? rule.references.slice() : [],
      file,
      line: position[0],
      column: position[1],
      code,
      description: rule.description || "",
      remediation: rule.remediation || "",
    };
    if (note) finding.note = note;
    return finding;
  }

  function scopeFor(context, offset) {
    return enclosingScope(context.bracePairs, offset, context.masked.length);
  }

  function hasSameDepthTerminator(masked, start, end) {
    let depth = 0;
    let i = start;
    while (i < end) {
      const ch = masked[i];
      if (ch === "{") {
        depth += 1;
        i += 1;
        continue;
      }
      if (ch === "}") {
        if (depth === 0) break;
        depth -= 1;
        i += 1;
        continue;
      }
      if (depth === 0) {
        const prev = i > 0 ? masked[i - 1] : " ";
        if (!/[A-Za-z0-9_]/.test(prev) && TERMINATOR_RE.test(masked.slice(i, i + 20))) {
          return i;
        }
      }
      i += 1;
    }
    return null;
  }

  function rhsAssignedValue(source, eqOffset, limit) {
    const semi = source.indexOf(";", eqOffset + 1);
    const end = (semi === -1 || semi > limit) ? limit : semi;
    return source.slice(eqOffset + 1, end).trim();
  }

  function isNullRhs(rhsText) {
    const cleaned = rhsText.trim().replace(/^\(\s*void\s*\*\s*\)\s*/, "");
    return NULL_VALUES.has(cleaned);
  }

  function elseBranchEnd(masked, closeBrace, limit) {
    let cursor = closeBrace + 1;
    while (cursor < limit && /\s/.test(masked[cursor])) cursor += 1;
    if (!masked.startsWith("else", cursor)) return closeBrace + 1;
    let after = cursor + 4;
    if (after < limit && /[A-Za-z0-9_]/.test(masked[after])) return closeBrace + 1;
    while (after < limit && /\s/.test(masked[after])) after += 1;
    if (after < limit && masked[after] === "{") {
      let depth = 1;
      let pos = after + 1;
      while (pos < limit && depth) {
        if (masked[pos] === "{") depth += 1;
        else if (masked[pos] === "}") depth -= 1;
        pos += 1;
      }
      return pos;
    }
    const semi = masked.indexOf(";", after);
    return (semi !== -1 && semi < limit) ? semi + 1 : limit;
  }

  function scanLifetime(context, file, rules) {
    const doubleRule = rules.find((rule) => rule.matcher === "double_free");
    const uafRule = rules.find((rule) => rule.matcher === "use_after_free");
    if (!doubleRule && !uafRule) return [];

    const freeCalls = context.calls.filter((call) => call.name === "free");
    const freeEvents = new Map();
    for (const call of freeCalls) {
      if (!call.args.length) continue;
      const identifier = plainIdentifier(call.args[0]);
      if (!identifier) continue;
      const local = context.masked.slice(call.offset, call.end);
      const match = new RegExp(`\\b${escapeRe(identifier)}\\b`).exec(local);
      if (match) freeEvents.set(call.offset + match.index, [call, identifier]);
    }

    const findings = [];
    for (const freeCall of freeCalls) {
      if (!freeCall.args.length) continue;
      const identifier = plainIdentifier(freeCall.args[0]);
      if (!identifier) continue;
      const [innerStart, innerEnd] = scopeFor(context, freeCall.offset);
      const funcScope = context.functionScopeFor(freeCall.offset);
      const [outerStart, outerEnd] = funcScope || [innerStart, innerEnd];

      const termInInner = hasSameDepthTerminator(context.masked, freeCall.end, innerEnd);
      const segments = [];
      if (termInInner !== null) {
        segments.push([freeCall.end, termInInner, false]);
      } else {
        segments.push([freeCall.end, innerEnd, false]);
        if (innerEnd < outerEnd) {
          const resume = elseBranchEnd(context.masked, innerEnd, outerEnd);
          const termInOuter = hasSameDepthTerminator(context.masked, resume, outerEnd);
          const limit = termInOuter !== null ? termInOuter : outerEnd;
          if (resume < limit) segments.push([resume, limit, true]);
        }
      }

      let state = "freed";
      let reported = false;

      for (const [segStart, segEnd, unconditionalOnly] of segments) {
        if (reported || state !== "freed") break;
        const pattern = new RegExp(`\\b${escapeRe(identifier)}\\b`, "g");
        pattern.lastIndex = segStart;
        let match;
        while ((match = pattern.exec(context.masked)) && match.index < segEnd) {
          if (unconditionalOnly) {
            const hitScope = scopeFor(context, match.index);
            if (hitScope[0] !== outerStart || hitScope[1] !== outerEnd) continue;
          }

          const event = freeEvents.get(match.index);
          if (event && event[1] === identifier) {
            const call = event[0];
            if (state === "freed" && doubleRule) {
              const line = context.position(call.offset)[0];
              if (!isSuppressed(context.lines, line)) {
                const note = unconditionalOnly
                  ? `conditional free() of '${identifier}' can reach a second free()`
                  : `second free() of '${identifier}' in the same block`;
                findings.push(makeFinding(context, file, doubleRule, call, "medium", undefined, note));
              }
              reported = true;
              break;
            }
            if (state !== "null") state = "freed";
            pattern.lastIndex = call.end;
            continue;
          }

          let next = match.index + match[0].length;
          while (next < segEnd && /\s/.test(context.masked[next])) next += 1;
          const isAssignment = next < segEnd
            && context.masked[next] === "="
            && context.masked[next + 1] !== "=";
          if (isAssignment) {
            const rhs = rhsAssignedValue(context.source, next, segEnd);
            state = isNullRhs(rhs) ? "null" : "live";
            continue;
          }

          if (state === "freed" && uafRule) {
            const line = context.position(match.index)[0];
            if (!isSuppressed(context.lines, line)) {
              const note = unconditionalOnly
                ? `conditional free() of '${identifier}' without return flows into use`
                : `'${identifier}' is used after free() in the same block`;
              findings.push(makeFinding(context, file, uafRule, { offset: match.index }, "medium", undefined, note));
            }
            reported = true;
            break;
          }
        }
      }
    }
    return findings;
  }

  function scanStackReturns(context, file, rules) {
    const stackRule = rules.find((rule) => rule.matcher === "stack_return");
    if (!stackRule) return [];

    const allocaPtrs = [];
    const assignRe = /\b([A-Za-z_]\w*)\s*=\s*(?:__builtin_alloca|alloca)\s*\(/g;
    let match;
    while ((match = assignRe.exec(context.masked))) {
      const fScope = context.functionScopeFor(match.index);
      if (fScope) allocaPtrs.push([match[1], match.index, fScope[0], fScope[1]]);
    }

    const findings = [];
    const retRe = new RegExp(RETURN_STMT_RE.source, "g");
    while ((match = retRe.exec(context.masked))) {
      const retOffset = match.index;
      const fScope = context.functionScopeFor(retOffset);
      if (!fScope) continue;
      const exprStart = match.index + match[0].indexOf(match[1]);
      let expr = context.source.slice(exprStart, exprStart + match[1].length).trim();
      while (expr.startsWith("(") && expr.endsWith(")")) {
        const inner = expr.slice(1, -1).trim();
        if ((inner.match(/\(/g) || []).length === (inner.match(/\)/g) || []).length) expr = inner;
        else break;
      }
      const cast = /^\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:(?:struct|union|enum)\s+)?[A-Za-z_]\w*(?:\s*\*)*\s*\)\s*/.exec(expr);
      if (cast) expr = expr.slice(cast[0].length).trim();

      let note = null;
      const addrMatch = /^&\s*([A-Za-z_]\w*)(?:\s*\[[^\]]+\])?$/.exec(expr);
      const plain = plainIdentifier(expr);

      if (addrMatch) {
        const ident = addrMatch[1];
        const decl = context.bufferDeclAt(ident, retOffset);
        if (decl && !decl.isStatic && decl.scopeStart >= fScope[0]) {
          note = `returns stack address of local buffer '${ident}'`;
        } else if (context.stackLocals.some((item) => (
          item.name === ident
          && item.scopeStart >= fScope[0]
          && item.offset <= retOffset && retOffset <= item.scopeEnd
        ))) {
          note = `returns address of stack variable '${ident}'`;
        }
      } else if (plain) {
        const decl = context.bufferDeclAt(plain, retOffset);
        if (decl && !decl.isStatic && decl.scopeStart >= fScope[0]) {
          note = `returns stack-allocated local array '${plain}'`;
        } else if (allocaPtrs.some(([name, declPos, start, end]) => (
          name === plain && start <= retOffset && retOffset <= end && declPos <= retOffset
        ))) {
          note = `returns alloca() stack pointer '${plain}'`;
        }
      }

      if (note) {
        const line = context.position(retOffset)[0];
        if (!isSuppressed(context.lines, line)) {
          findings.push(makeFinding(context, file, stackRule, { offset: retOffset }, "high", undefined, note));
        }
      }
    }
    return findings;
  }

  function dedupe(findings) {
    const seen = new Set();
    return findings.filter((finding) => {
      const key = `${finding.file}:${finding.line}:${finding.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function sortFindings(findings) {
    return findings.slice().sort((a, b) => (
      (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
      || a.file.localeCompare(b.file)
      || a.line - b.line
      || a.id.localeCompare(b.id)
    ));
  }

  function analyzeSource(source, file, customRules) {
    const activeRules = customRules || RULES;
    const context = new SourceContext(source);
    const findings = [];
    for (const rule of activeRules) {
      if (rule.matcher === "double_free" || rule.matcher === "use_after_free" || rule.matcher === "stack_return") {
        continue;
      }
      const names = new Set(rule.functions || []);
      if (!names.size) continue;
      const matcher = MATCHERS[rule.matcher];
      if (!matcher) continue;
      for (const call of context.calls) {
        if (!names.has(call.name)) continue;
        const result = matcher(rule, call, context);
        if (!result) continue;
        const [confidence, note] = Array.isArray(result) ? result : [result, undefined];
        const line = context.position(call.offset)[0];
        if (isSuppressed(context.lines, line)) continue;
        findings.push(makeFinding(context, file, rule, call, confidence, undefined, note));
      }
    }
    findings.push(...scanLifetime(context, file, activeRules));
    findings.push(...scanStackReturns(context, file, activeRules));
    return sortFindings(dedupe(findings));
  }

  ROOT.BOAR_ANALYZE = analyzeSource;
  if (typeof document === "undefined") return;

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  // ---------------------------------------------------------------------------
  // Page state and rendering.
  // ---------------------------------------------------------------------------

  const state = {
    findings: [],
    filter: "all",
    fileName: "sample.c",
    uploadName: null,
    analyzedAt: 0,
  };

  const els = {
    source: $("#source"),
    gutter: $("#gutter"),
    status: $("#status"),
    cursor: $("#cursor"),
    findings: $("#findings"),
    filters: $("#filters"),
    summaryBar: $("#summary-bar"),
    total: $("#total-findings"),
    statFindings: $("#stat-findings"),
    statRules: $("#stat-rules"),
    statUpload: $("#stat-upload"),
    ruleGrid: $("#rule-grid"),
    dropZone: $("#drop-zone"),
    fileInput: $("#file-input"),
    heroStage: $("#hero-stage"),
    heroReadout: $("#hero-readout"),
  };

  function countsFor(findings) {
    const counts = { all: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
    for (const finding of findings) {
      if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
    }
    return counts;
  }

  function render() {
    const counts = countsFor(state.findings);
    els.total.textContent = String(counts.all);
    els.statFindings.textContent = String(counts.all);
    els.statRules.textContent = String(RULES.length);
    els.statUpload.textContent = state.uploadName || "None";
    renderSummaryBar(counts);
    renderFilters(counts);
    renderFindings();
    updateStatus();
    updateHero(counts);
  }

  function renderSummaryBar(counts) {
    if (!counts.all) {
      els.summaryBar.replaceChildren();
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const severity of SEVERITIES) {
      if (!counts[severity]) continue;
      const segment = document.createElement("span");
      segment.style.width = `${(counts[severity] / counts.all) * 100}%`;
      segment.style.background = SEVERITY_COLOR[severity];
      fragment.append(segment);
    }
    els.summaryBar.replaceChildren(fragment);
  }

  function renderFilters(counts) {
    const fragment = document.createDocumentFragment();
    for (const key of FILTER_KEYS) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `filter${state.filter === key ? " is-active" : ""}`;
      button.dataset.filter = key;
      button.setAttribute("aria-pressed", String(state.filter === key));

      const label = document.createElement("span");
      label.textContent = SEVERITY_LABEL[key];
      const number = document.createElement("span");
      number.className = "n";
      number.textContent = String(counts[key] || 0);
      button.append(label, number);
      button.addEventListener("click", () => selectFilter(key));
      fragment.append(button);
    }
    els.filters.replaceChildren(fragment);
  }

  function renderFindings() {
    const visible = state.filter === "all"
      ? state.findings
      : state.findings.filter((finding) => finding.severity === state.filter);

    if (!visible.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      const strong = document.createElement("strong");
      strong.textContent = state.findings.length ? "Nothing in this tray." : "No findings.";
      const span = document.createElement("span");
      span.textContent = state.findings.length
        ? "Try another severity, or edit the source and scan again."
        : "The loaded rules did not match. Paste more code or load the sample to see the analyzer in action.";
      empty.append(strong, span);
      els.findings.replaceChildren(empty);
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const finding of visible) {
      fragment.append(renderFinding(finding));
    }
    els.findings.replaceChildren(fragment);
  }

  function renderFinding(finding) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "finding";
    card.style.setProperty("--sev", SEVERITY_COLOR[finding.severity] || "var(--muted)");
    card.setAttribute("aria-label", `${SEVERITY_LABEL[finding.severity]} ${finding.rule} at line ${finding.line}`);

    const top = document.createElement("span");
    top.className = "finding-top";

    const severity = document.createElement("span");
    severity.className = "sev";
    severity.textContent = SEVERITY_LABEL[finding.severity];
    const id = document.createElement("span");
    id.className = "rule-id";
    id.textContent = finding.id;
    const confidence = document.createElement("span");
    confidence.className = "confidence";
    confidence.textContent = `${finding.confidence} confidence`;
    top.append(severity, id, confidence);

    const name = document.createElement("span");
    name.className = "finding-name";
    name.textContent = finding.rule;

    const code = document.createElement("code");
    code.className = "finding-code";
    code.textContent = finding.code || "(line unavailable)";

    const why = document.createElement("span");
    why.className = "finding-why";
    why.textContent = finding.note ? `${finding.description} ${finding.note}.` : finding.description;

    const fix = document.createElement("span");
    fix.className = "finding-fix";
    const fixLabel = document.createElement("strong");
    fixLabel.textContent = "Fix: ";
    fix.append(fixLabel, document.createTextNode(finding.remediation || "Review this path manually."));

    const meta = document.createElement("span");
    meta.className = "finding-meta";
    const parts = [`line ${finding.line}:${finding.column}`];
    if (finding.cwe.length) parts.push(finding.cwe.join(", "));
    if (finding.references.length) parts.push(finding.references.slice(0, 2).join(", "));
    meta.textContent = parts.join(" · ");

    card.append(top, name, code, why, fix, meta);
    card.addEventListener("click", () => selectLine(finding.line, finding.column));
    return card;
  }

  function renderRules() {
    const fragment = document.createDocumentFragment();
    RULES.forEach((rule, index) => {
      const card = document.createElement("article");
      card.className = "rule-card";

      const idx = document.createElement("span");
      idx.className = "idx";
      idx.textContent = String(index + 1).padStart(2, "0");

      const body = document.createElement("div");
      const title = document.createElement("h3");
      title.textContent = rule.name;
      const description = document.createElement("p");
      description.textContent = rule.description;
      body.append(title, description);

      const severity = document.createElement("span");
      severity.className = "sev";
      severity.style.setProperty("--sev", SEVERITY_COLOR[rule.severity] || "var(--muted)");
      severity.textContent = SEVERITY_LABEL[rule.severity] || rule.severity;

      card.append(idx, body, severity);
      fragment.append(card);
    });
    els.ruleGrid.replaceChildren(fragment);
  }

  function updateStatus() {
    const lineCount = els.source.value.split("\n").length;
    const label = state.uploadName || state.fileName;
    els.status.textContent = `${state.findings.length} findings · ${lineCount} lines · ${label}`;
  }

  function updateGutter() {
    const lineCount = Math.max(1, els.source.value.split("\n").length);
    const numbers = [];
    for (let line = 1; line <= lineCount; line += 1) numbers.push(line);
    els.gutter.textContent = numbers.join("\n");
    els.gutter.scrollTop = els.source.scrollTop;
  }

  function updateCursor() {
    const value = els.source.value;
    const position = els.source.selectionStart || 0;
    const before = value.slice(0, position);
    const line = before.split("\n").length;
    const column = position - before.lastIndexOf("\n");
    els.cursor.textContent = `Ln ${line}, Col ${column}`;
  }

  function selectLine(line, column) {
    const lines = els.source.value.split("\n");
    if (line < 1 || line > lines.length) return;
    let start = 0;
    for (let i = 0; i < line - 1; i += 1) start += lines[i].length + 1;
    const end = start + lines[line - 1].length;
    els.source.focus();
    els.source.setSelectionRange(start, end);
    const style = getComputedStyle(els.source);
    const lineHeight = parseFloat(style.lineHeight) || 22;
    const padding = parseFloat(style.paddingTop) || 0;
    els.source.scrollTop = Math.max(0, padding + (line - 1) * lineHeight - els.source.clientHeight * 0.32);
    updateCursor();
  }

  function selectFilter(key) {
    if (!FILTER_KEYS.includes(key)) return;
    state.filter = key;
    const counts = countsFor(state.findings);
    renderFilters(counts);
    renderFindings();
    updateHero(counts);
  }

  function analyze() {
    state.findings = analyzeSource(els.source.value, state.fileName);
    state.analyzedAt = Date.now();
    render();
  }

  function scheduleAnalyze() {
    window.clearTimeout(scheduleAnalyze.timer);
    scheduleAnalyze.timer = window.setTimeout(analyze, 260);
  }

  function setSource(text, name, uploaded) {
    els.source.value = text;
    state.fileName = name || "untitled.c";
    state.uploadName = uploaded ? name : null;
    updateGutter();
    updateCursor();
    analyze();
  }

  async function readFile(file) {
    if (!file) return;
    const text = await file.text();
    setSource(text, file.name, true);
  }

  // ---------------------------------------------------------------------------
  // Anatomy hero: four severity trays under a probe and a dial.
  // ---------------------------------------------------------------------------

  const hero = {
    mounted: false,
    layers: {},
    projection: null,
    x: 0,
    tip: 0,
    needle: 0,
    targetX: 0,
    targetTip: 0,
    targetNeedle: 0,
    targetIndex: 0,
    counts: { all: 0, critical: 0, high: 0, medium: 0, low: 0 },
    frame: 0,
    reduced: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    stationX: [],
    stationLabels: [],
  };

  function iso(point, projection) {
    const a = (projection.azimuth * Math.PI) / 180;
    const e = (projection.elevation * Math.PI) / 180;
    const k = projection.scale * Math.sqrt(1.6);
    const [x, y, z] = point;
    return [
      projection.origin[0] + (x * Math.sin(a) - y * Math.cos(a)) * k,
      projection.origin[1] + ((x * Math.cos(a) + y * Math.sin(a)) * Math.sin(e) - z * Math.cos(e)) * k,
    ];
  }

  function round(value, digits = 2) {
    const factor = 10 ** digits;
    return Math.round(value * factor) / factor;
  }

  function translateAlong(by) {
    const origin = iso([0, 0, 0], hero.projection);
    const moved = iso(by, hero.projection);
    return `translate(${round(moved[0] - origin[0])} ${round(moved[1] - origin[1])})`;
  }

  function lineOnTop(from, to, z) {
    const a = iso([from[0], from[1], z], hero.projection);
    const b = iso([to[0], to[1], z], hero.projection);
    return `M${round(a[0])} ${round(a[1])}L${round(b[0])} ${round(b[1])}`;
  }

  function needlePath(turns) {
    const angle = turns * Math.PI * 2;
    const { x, y, top, radius } = HERO.dial;
    return lineOnTop(
      [x - Math.sin(angle) * 3.4, y + Math.cos(angle) * 3.4],
      [x + Math.sin(angle) * (radius - 4), y - Math.cos(angle) * (radius - 4)],
      top + 0.2,
    );
  }

  function heightUnder(carriageX) {
    const probe = HERO.dial.x;
    let top = HERO.base;
    HERO.heights.forEach((height, index) => {
      const center = carriageX + probe - HERO.stops[index];
      if (Math.abs(center - probe) <= 7.8 + HERO.dial.tipRadius) {
        top = Math.max(top, HERO.base + height);
      }
    });
    return top;
  }

  function mountHero() {
    if (!HERO || !els.heroStage) return;
    els.heroStage.innerHTML = HERO.svg;
    hero.mounted = true;
    hero.projection = HERO.projection;
    hero.stationX = [HERO.home, ...HERO.stops];
    hero.stationLabels = ["all", ...HERO.severities];
    hero.x = HERO.home;
    hero.tip = HERO.base;
    hero.needle = 0;
    hero.targetX = HERO.home;
    hero.targetTip = HERO.base;
    hero.targetNeedle = 0;
    hero.layers.carriage = $('[data-part="carriage"]', els.heroStage);
    hero.layers.plunger = $('[data-part="plunger"]', els.heroStage);
    hero.layers.needle = $('[data-part="needle"]', els.heroStage);
    hero.layers.canary = $('[data-part="canary-glow"]', els.heroStage);
    drawHero();

    els.heroStage.addEventListener("pointermove", (event) => {
      const box = els.heroStage.getBoundingClientRect();
      const share = clamp((event.clientX - box.left) / box.width, 0, 1);
      const index = Math.round(share * (FILTER_KEYS.length - 1));
      selectFilter(FILTER_KEYS[index]);
    });
    els.heroStage.addEventListener("keydown", (event) => {
      const current = FILTER_KEYS.indexOf(state.filter);
      let next = null;
      if (event.key === "ArrowRight" || event.key === "ArrowUp") next = Math.max(0, current - 1);
      if (event.key === "ArrowLeft" || event.key === "ArrowDown") next = Math.min(FILTER_KEYS.length - 1, current + 1);
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = FILTER_KEYS.length - 1;
      if (next === null) return;
      event.preventDefault();
      selectFilter(FILTER_KEYS[next]);
    });
  }

  function updateHero(counts) {
    if (!hero.mounted) return;
    hero.counts = counts;
    hero.targetIndex = Math.max(0, FILTER_KEYS.indexOf(state.filter));
    hero.targetX = hero.stationX[hero.targetIndex];
    hero.targetNeedle = (state.filter === "all" ? counts.all : counts[state.filter] || 0) / HERO.dial.perTurn;
    if (hero.reduced) {
      hero.x = hero.targetX;
      hero.tip = heightUnder(hero.x);
      hero.needle = hero.targetNeedle;
      drawHero();
      return;
    }
    if (!hero.frame) hero.frame = window.requestAnimationFrame(tickHero);
  }

  function tickHero() {
    hero.frame = 0;
    hero.x += (hero.targetX - hero.x) * 0.14;
    hero.tip += (heightUnder(hero.x) - hero.tip) * 0.2;
    hero.needle += (hero.targetNeedle - hero.needle) * 0.16;
    const settled = Math.abs(hero.targetX - hero.x) < 0.01
      && Math.abs(heightUnder(hero.x) - hero.tip) < 0.01
      && Math.abs(hero.targetNeedle - hero.needle) < 0.002;
    if (settled) {
      hero.x = hero.targetX;
      hero.tip = heightUnder(hero.x);
      hero.needle = hero.targetNeedle;
    }
    drawHero();
    if (!settled) hero.frame = window.requestAnimationFrame(tickHero);
  }

  function drawHero() {
    if (!hero.mounted) return;
    if (hero.layers.carriage) {
      hero.layers.carriage.setAttribute("transform", translateAlong([hero.x, 0, 0]));
    }
    if (hero.layers.plunger) {
      hero.layers.plunger.setAttribute("transform", translateAlong([0, 0, hero.tip]));
    }
    if (hero.layers.needle) {
      hero.layers.needle.setAttribute("d", needlePath(hero.needle));
    }
    if (hero.layers.canary) {
      hero.layers.canary.style.opacity = hero.counts.critical > 0 ? "0.86" : "0.14";
    }

    const label = SEVERITY_LABEL[state.filter] || "All";
    const count = state.filter === "all" ? hero.counts.all : hero.counts[state.filter] || 0;
    const readout = `${label.toLowerCase()} · ${count} ${count === 1 ? "finding" : "findings"}`;
    if (els.heroReadout && els.heroReadout.textContent !== readout) els.heroReadout.textContent = readout;
    els.heroStage.setAttribute("aria-valuenow", String(hero.targetIndex));
    els.heroStage.setAttribute("aria-valuetext", readout);
  }

  // ---------------------------------------------------------------------------
  // Wiring.
  // ---------------------------------------------------------------------------

  function bindEvents() {
    $("#analyze-button").addEventListener("click", analyze);
    $("#hero-analyze").addEventListener("click", () => {
      setSource(SAMPLE, "sample.c", false);
      $("#workspace").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    $("#sample-button").addEventListener("click", () => setSource(SAMPLE, "sample.c", false));
    $("#clear-button").addEventListener("click", () => setSource("", "untitled.c", false));

    els.source.addEventListener("input", () => {
      updateGutter();
      updateCursor();
      scheduleAnalyze();
    });
    els.source.addEventListener("scroll", () => {
      els.gutter.scrollTop = els.source.scrollTop;
    });
    for (const event of ["click", "keyup", "select"]) {
      els.source.addEventListener(event, updateCursor);
    }
    els.source.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        analyze();
      }
    });

    els.fileInput.addEventListener("change", () => {
      readFile(els.fileInput.files && els.fileInput.files[0]);
      els.fileInput.value = "";
    });

    for (const event of ["dragenter", "dragover"]) {
      els.dropZone.addEventListener(event, (dragEvent) => {
        dragEvent.preventDefault();
        els.dropZone.classList.add("is-over");
      });
    }
    for (const event of ["dragleave", "drop"]) {
      els.dropZone.addEventListener(event, (dragEvent) => {
        dragEvent.preventDefault();
        els.dropZone.classList.remove("is-over");
      });
    }
    els.dropZone.addEventListener("drop", (dragEvent) => {
      const file = dragEvent.dataTransfer && dragEvent.dataTransfer.files[0];
      readFile(file);
    });
    document.addEventListener("dragover", (event) => event.preventDefault());
    document.addEventListener("drop", (event) => event.preventDefault());
  }

  function init() {
    if (!RULES.length) {
      els.status.textContent = "rules.js is missing or empty.";
      return;
    }
    renderRules();
    bindEvents();
    mountHero();
    setSource(SAMPLE, "sample.c", false);
  }

  init();
})();
