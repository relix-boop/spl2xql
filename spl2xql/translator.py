"""Translate a practical subset of Splunk SPL into Cortex XQL.

The goal is a reviewable first draft, not a black box: every construct the
translator cannot carry over faithfully is reported as a warning, and
unsupported commands are left in the output as ``// UNSUPPORTED`` comments.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import mappings

META_FIELDS = {"index", "sourcetype", "source", "earliest", "latest"}
DROPPED_FIELDS = {"tag", "eventtype"}
TIME_UNITS = {"s": "s", "m": "m", "h": "h", "d": "d", "w": "w", "mon": "mo", "y": "y"}


@dataclass
class Result:
    xql: str
    warnings: list[str] = field(default_factory=list)


class Unsupported(Exception):
    pass


# --------------------------------------------------------------------------
# Splitting helpers
# --------------------------------------------------------------------------

def split_top(text: str, sep: str) -> list[str]:
    """Split on ``sep`` outside quotes, parentheses and brackets."""
    parts, buf, depth, quote, i = [], [], 0, None, 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in "([":
            depth += 1
            buf.append(ch)
        elif ch in ")]":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf).strip())
    return parts


def split_by_clause(text: str) -> tuple[str, str]:
    """Split ``<aggs> by <fields>`` at the top-level BY keyword."""
    depth, quote = 0, None
    for m in re.finditer(r"[\"'()]|\bby\b", text, flags=re.I):
        tok = m.group(0)
        if quote:
            if tok == quote:
                quote = None
        elif tok in "\"'":
            quote = tok
        elif tok == "(":
            depth += 1
        elif tok == ")":
            depth -= 1
        elif depth == 0 and tok.lower() == "by":
            return text[: m.start()].strip(), text[m.end():].strip()
    return text.strip(), ""


def field_list(text: str) -> list[str]:
    return [f.strip().strip('"') for f in re.split(r"[,\s]+", text.strip()) if f.strip()]


# --------------------------------------------------------------------------
# Translator
# --------------------------------------------------------------------------

class Translator:
    def __init__(self, mode: str = "datamodel", mapping: dict | None = None,
                 double_backslashes: bool = False):
        if mode not in ("datamodel", "dataset"):
            raise ValueError("mode must be 'datamodel' or 'dataset'")
        self.mode = mode
        self.double_backslashes = double_backslashes
        mapping = mapping or {}
        self.fields = {**mappings.FIELDS, **mapping.get("fields", {})}
        self.values = {**mappings.VALUES, **mapping.get("values", {})}
        self.datasets = {**mappings.DATASETS, **mapping.get("datasets", {})}
        self.warnings: list[str] = []
        self.local: set[str] = set()      # fields created inside the query
        self.meta: dict[str, str] = {}

    # ---- utilities -------------------------------------------------------

    def warn(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)

    def fld(self, name: str) -> str:
        name = name.strip().strip("'")
        if name in self.local or name.startswith("_") or self.mode == "dataset":
            return name
        if name in self.fields:
            if name in mappings.AMBIGUOUS:
                self.warn(mappings.AMBIGUOUS[name])
            return self.fields[name]
        if not name.startswith("xdm."):
            self.warn(f"No XDM mapping for field '{name}'; left unchanged")
        return name

    def lit(self, value: str, target: str | None = None) -> str:
        """Render a search value as an XQL literal."""
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        vmap = self.values.get(target or "", {})
        if value.lower() in vmap:
            self.warn(f"Value '{value}' translated to {vmap[value.lower()]}; "
                      "verify the enum against your tenant")
            return vmap[value.lower()]
        if vmap:
            self.warn(f"'{target}' is an enum in XDM; value '{value}' was not translated")
        if re.fullmatch(r"-?\d+(\.\d+)?", value):
            return value
        return '"' + value.replace('"', '\\"') + '"'

    def regex(self, pattern: str) -> str:
        # The XQL Search editor takes regex backslashes as written. Some
        # deployment paths (rule content shipped as files or through an API)
        # need them doubled; --double-backslashes covers that case.
        if self.double_backslashes:
            pattern = pattern.replace("\\", "\\\\")
        return '"' + pattern.replace('"', '\\"') + '"'

    # ---- search terms (base search and the `search` command) -------------

    def search_tokens(self, text: str) -> list[str]:
        toks, i, n = [], 0, len(text)
        while i < n:
            ch = text[i]
            if ch.isspace():
                i += 1
            elif ch in "()":
                toks.append(ch)
                i += 1
            elif ch == ",":
                i += 1
            else:
                j = i
                while j < n and not text[j].isspace() and text[j] not in "(),":
                    if text[j] == '"':
                        j += 1
                        while j < n and text[j] != '"':
                            j += 2 if text[j] == "\\" else 1
                    j += 1
                toks.append(text[i:j])
                i = j
        return toks

    def search_expr(self, text: str) -> str:
        self._t = self.search_tokens(text)
        self._i = 0
        out = self._s_or(top=True)
        return out

    def _peek(self) -> str | None:
        return self._t[self._i] if self._i < len(self._t) else None

    def _s_or(self, top: bool = False) -> str:
        parts = [self._s_and(top)]
        while (self._peek() or "").upper() == "OR":
            self._i += 1
            parts.append(self._s_and(False))
        parts = [p for p in parts if p]
        if len(parts) > 1:
            return "(" + " or ".join(parts) + ")" if not top else " or ".join(parts)
        return parts[0] if parts else ""

    def _s_and(self, top: bool) -> str:
        parts = []
        while self._peek() is not None and self._peek() != ")" \
                and self._peek().upper() != "OR":
            if self._peek().upper() == "AND":
                self._i += 1
                continue
            p = self._s_not(top)
            if p:
                parts.append(p)
        if len(parts) > 1 and any(" or " in p and not p.startswith("(") for p in parts):
            parts = [f"({p})" if " or " in p and not p.startswith("(") else p for p in parts]
        return " and ".join(parts)

    def _s_not(self, top: bool) -> str:
        if (self._peek() or "").upper() == "NOT":
            self._i += 1
            inner = self._s_not(False)
            if not inner:
                return ""
            return f"not ({inner})"
        return self._s_atom(top)

    def _s_atom(self, top: bool) -> str:
        tok = self._t[self._i]
        self._i += 1
        if tok == "(":
            inner = self._s_or()
            if self._peek() == ")":
                self._i += 1
            return inner if inner.startswith("(") or not inner else f"({inner})"
        if tok.startswith("`"):
            self.warn(f"Macro {tok} was not expanded")
            return ""
        nxt = self._peek()
        if nxt and nxt.upper() == "IN" and self._i + 1 < len(self._t) \
                and self._t[self._i + 1] == "(":
            self._i += 2
            vals = []
            while self._peek() is not None and self._peek() != ")":
                vals.append(self._t[self._i])
                self._i += 1
            self._i += 1
            name = self.fld(tok)
            return f"{name} in ({', '.join(self.lit(v, name) for v in vals)})"
        m = re.match(r"^([\w.:{}\-]+?)(!=|>=|<=|=|>|<)(.*)$", tok)
        if not m:
            term = tok.strip('"')
            self.warn(f"Free-text term '{term}' translated to a _raw_log substring match")
            return '_raw_log contains "' + term.replace("*", "") + '"'
        name, op, value = m.groups()
        if name in META_FIELDS:
            if not top or op != "=":
                self.warn(f"'{name}' inside OR/NOT or with '{op}' is not supported; "
                          "only the plain form was used")
            self.meta.setdefault(name, value.strip('"'))
            return ""
        if name in DROPPED_FIELDS:
            self.warn(f"'{tok}' has no XQL equivalent (Splunk knowledge object); dropped")
            return ""
        xname = self.fld(name)
        if value == "*":
            return f"{xname} != null" if op == "=" else f"{xname} = null"
        if op == "!=":
            # SPL field!=x skips events without the field; an XQL filter keeps
            # null rows for !=, so the null guard preserves the SPL meaning.
            return f"({xname} != {self.lit(value, xname)} and {xname} != null)"
        return f"{xname} {op} {self.lit(value, xname)}"

    # ---- eval / where expressions ----------------------------------------

    TOKEN = re.compile(r"""
        \s*(?:
          (?P<str>"(?:\\.|[^"\\])*")
        | (?P<qid>'[^']*')
        | (?P<num>\d+(?:\.\d+)?)
        | (?P<id>[A-Za-z_][\w.]*)
        | (?P<op>==|!=|<=|>=|[=<>+\-*/%.(),])
        )""", re.X)

    def expr(self, text: str) -> str:
        toks, pos = [], 0
        text = text.strip()
        while pos < len(text):
            m = self.TOKEN.match(text, pos)
            if not m:
                raise Unsupported(f"cannot parse expression near '{text[pos:pos + 20]}'")
            toks.append((m.lastgroup, m.group(m.lastgroup)))
            pos = m.end()
        self._e, self._p = toks, 0
        out = self._e_or()
        if self._p != len(self._e):
            raise Unsupported(f"unexpected token '{self._e[self._p][1]}' in expression")
        return out

    def _ek(self, *vals: str) -> bool:
        if self._p >= len(self._e):
            return False
        kind, val = self._e[self._p]
        return (kind in ("op", "id")) and val.upper() in vals

    def _e_or(self) -> str:
        left = self._e_and()
        while self._ek("OR"):
            self._p += 1
            left = f"{left} or {self._e_and()}"
        return left

    def _e_and(self) -> str:
        left = self._e_not()
        while self._ek("AND"):
            self._p += 1
            right = self._e_not()
            left = " and ".join(f"({x})" if " or " in x and not x.startswith("(") else x
                                for x in (left, right))
        return left

    def _e_not(self) -> str:
        if self._ek("NOT"):
            self._p += 1
            return f"not ({self._e_not()})"
        return self._e_cmp()

    def _e_cmp(self) -> str:
        left = self._e_add()
        if self._ek("==", "=", "!=", "<", "<=", ">", ">="):
            op = self._e[self._p][1]
            self._p += 1
            right = self._e_add()
            if '*' in right and right.startswith('"'):
                self.warn("A literal '*' inside a compared string acts as a wildcard in XQL")
            if right.startswith('"') and op in ("==", "=", "!="):
                self.warn("where/eval string comparisons are case-sensitive in SPL; XQL is "
                          "case-insensitive unless you add 'config case_sensitive = true'")
            if op == "!=":
                self.warn("An XQL filter keeps rows where the field is null for '!='; SPL "
                          "where drops them. Add 'and <field> != null' if that matters")
            right = self._enum(left, right)
            return f"{left} {'=' if op == '==' else op} {right}"
        if self._ek("IN"):
            self._p += 1
            args = self._e_args()
            return f"{left} in ({', '.join(self._enum(left, a) for a in args)})"
        if self._ek("LIKE"):
            self._p += 1
            return self._like(left, self._e_add())
        return left

    def _enum(self, left: str, right: str) -> str:
        if left in self.values and right.startswith('"'):
            return self.lit(right, left)
        return right

    def _e_add(self) -> str:
        left = self._e_mul()
        while self._ek("+", "-", "."):
            op = self._e[self._p][1]
            self._p += 1
            right = self._e_mul()
            fn = {"+": "add", "-": "subtract", ".": "concat"}[op]
            if fn == "concat" and left.startswith("concat("):
                left = f"{left[:-1]}, {right})"
            else:
                left = f"{fn}({left}, {right})"
        return left

    def _e_mul(self) -> str:
        left = self._e_unary()
        while self._ek("*", "/", "%"):
            op = self._e[self._p][1]
            self._p += 1
            fn = {"*": "multiply", "/": "divide", "%": "mod"}[op]
            left = f"{fn}({left}, {self._e_unary()})"
        return left

    def _e_unary(self) -> str:
        if self._ek("-"):
            self._p += 1
            inner = self._e_unary()
            return f"-{inner}" if re.fullmatch(r"\d+(\.\d+)?", inner) else f"multiply({inner}, -1)"
        return self._e_primary()

    def _e_args(self) -> list[str]:
        if not self._ek("("):
            raise Unsupported("expected '('")
        self._p += 1
        args = []
        while not self._ek(")"):
            args.append(self._e_or())
            if self._ek(","):
                self._p += 1
            elif not self._ek(")"):
                raise Unsupported("unbalanced parentheses in expression")
        self._p += 1
        return args

    def _e_primary(self) -> str:
        if self._p >= len(self._e):
            raise Unsupported("incomplete expression")
        kind, val = self._e[self._p]
        self._p += 1
        if kind in ("str", "num"):
            return val
        if kind == "qid":
            return self.fld(val)
        if kind == "op" and val == "(":
            inner = self._e_or()
            if not self._ek(")"):
                raise Unsupported("unbalanced parentheses in expression")
            self._p += 1
            return f"({inner})"
        if kind == "id":
            if self._ek("("):
                return self._func(val.lower(), self._e_args())
            if val.lower() in ("true", "false", "null"):
                return val.lower()
            return self.fld(val)
        raise Unsupported(f"unexpected token '{val}' in expression")

    def _like(self, left: str, pattern: str) -> str:
        body = pattern.strip('"')
        if "_" in body:
            self.warn("LIKE '_' (single character) has no direct XQL wildcard; kept as-is")
        return f'{left} = "{body.replace("%", "*")}"'

    def _func(self, name: str, a: list[str]) -> str:
        if name == "isnull" and len(a) == 1:
            return f"{a[0]} = null"
        if name == "isnotnull" and len(a) == 1:
            return f"{a[0]} != null"
        if name == "like" and len(a) == 2:
            return self._like(a[0], a[1])
        if name == "match" and len(a) == 2:
            return f"{a[0]} ~= {self.regex(a[1][1:-1])}"
        if name == "cidrmatch" and len(a) == 2:
            return f"{a[1]} incidr {a[0]}"
        if name in ("true", "false", "null") and not a:
            return name
        if name == "case":
            if len(a) >= 2 and a[-2] in ("true", "1 = 1"):
                a = a[:-2] + [a[-1]]
            return f"if({', '.join(a)})"
        if name == "strftime":
            self.warn("strftime format strings differ from XQL format_timestamp; review the format")
            return f"format_timestamp({', '.join(reversed(a))})"
        if name in mappings.FUNCS:
            if name == "replace":
                a = [a[0]] + [self.regex(a[1][1:-1])] + a[2:] if a[1].startswith('"') else a
            return f"{mappings.FUNCS[name]}({', '.join(a)})"
        self.warn(f"Function '{name}()' has no known XQL equivalent; left unchanged")
        return f"{name}({', '.join(a)})"

    # ---- commands --------------------------------------------------------

    def cmd_where(self, arg: str) -> list[str]:
        return [f"filter {self.expr(arg)}"]

    def cmd_search(self, arg: str) -> list[str]:
        out = self.search_expr(arg)
        return [f"filter {out}"] if out else []

    def cmd_regex(self, arg: str) -> list[str]:
        m = re.match(r'^([\w.]+)\s*(!=|=)\s*"(.*)"$', arg.strip())
        if not m:
            m2 = re.match(r'^"(.*)"$', arg.strip())
            if not m2:
                raise Unsupported("unrecognised regex syntax")
            return [f"filter _raw_log ~= {self.regex(m2.group(1))}"]
        name, op, pat = m.groups()
        expr = f"{self.fld(name)} ~= {self.regex(pat)}"
        return [f"filter not ({expr})" if op == "!=" else f"filter {expr}"]

    def _aggs(self, text: str) -> list[str]:
        if re.search(r"\beval\s*\(", text):
            raise Unsupported("eval() inside an aggregation")
        out = []
        pat = re.compile(r'([A-Za-z_]\w*)\s*(?:\(([^()]*)\))?(?:\s+as\s+("[^"]+"|[\w.]+))?', re.I)
        pos = 0
        text = text.strip()
        while pos < len(text):
            if text[pos] in ", \t":
                pos += 1
                continue
            m = pat.match(text, pos)
            if not m:
                raise Unsupported(f"cannot parse aggregation near '{text[pos:pos + 20]}'")
            fn, arg, alias = m.group(1).lower(), m.group(2), m.group(3)
            pos = m.end()
            if fn not in mappings.AGGS:
                raise Unsupported(f"aggregation '{fn}'")
            xfn = mappings.AGGS[fn]
            arg = (arg or "").strip()
            xarg = "" if arg in ("", "*") else self.fld(arg)
            if alias:
                alias = alias.strip('"').replace(" ", "_")
            elif not arg:
                alias = "count"
            else:
                alias = re.sub(r"\W+", "_", f"{fn}_{arg}").strip("_")
                self.warn(f"Splunk names this column '{fn}({arg})'; XQL output uses '{alias}'")
            self.local.add(alias)
            out.append(f"{xfn}({xarg}) as {alias}")
        return out

    def cmd_stats(self, arg: str) -> list[str]:
        aggs, by = split_by_clause(arg)
        parts = self._aggs(aggs)
        line = "comp " + ", ".join(parts)
        if by:
            line += " by " + ", ".join(self.fld(f) for f in field_list(by))
        return [line]

    def cmd_eval(self, arg: str) -> list[str]:
        items = []
        for part in split_top(arg, ","):
            name, _, rhs = part.partition("=")
            name = name.strip().strip("'\"")
            value = self.expr(rhs)
            self.local.add(name)
            items.append(f"{name} = {value}")
        return ["alter " + ", ".join(items)]

    def cmd_fields(self, arg: str) -> list[str]:
        arg = arg.strip()
        minus = arg.startswith("-")
        names = [self.fld(f) for f in field_list(arg.lstrip("+- "))]
        return [("fields - " if minus else "fields ") + ", ".join(names)]

    def cmd_table(self, arg: str) -> list[str]:
        return ["fields " + ", ".join(self.fld(f) for f in field_list(arg))]

    def cmd_rename(self, arg: str) -> list[str]:
        alters, drops = [], []
        for old, new in re.findall(r'("[^"]+"|[\w.]+)\s+as\s+("[^"]+"|[\w.]+)', arg, flags=re.I):
            src = self.fld(old.strip('"'))
            new = new.strip('"').replace(" ", "_")
            self.local.add(new)
            alters.append(f"{new} = {src}")
            drops.append(src)
        if not alters:
            raise Unsupported("unrecognised rename syntax")
        return ["alter " + ", ".join(alters), "fields - " + ", ".join(drops)]

    def cmd_sort(self, arg: str) -> list[str]:
        arg = arg.strip()
        limit = None
        m = re.match(r"^(?:limit\s*=\s*)?(\d+)\s+", arg)
        if m:
            limit, arg = int(m.group(1)), arg[m.end():]
        trailing_desc = bool(re.search(r"\s+d(esc)?$", arg))
        arg = re.sub(r"\s+(d|desc)$", "", arg)
        arg = re.sub(r"([+-])\s+", r"\1", arg)
        items = []
        for f in field_list(arg):
            desc = f.startswith("-")
            f = f.lstrip("+-")
            f = re.sub(r"^(?:num|str|ip|auto)\((.*)\)$", r"\1", f)
            items.append(f"{'desc' if desc != trailing_desc else 'asc'} {self.fld(f)}")
        lines = ["sort " + ", ".join(items)]
        if limit:
            lines.append(f"limit {limit}")
        return lines

    def cmd_head(self, arg: str) -> list[str]:
        arg = arg.strip() or "10"
        if not arg.isdigit():
            raise Unsupported("head with an expression")
        return [f"limit {arg}"]

    def cmd_dedup(self, arg: str) -> list[str]:
        if re.search(r"\b(sortby|keepevents|keepempty|consecutive)\b", arg):
            raise Unsupported("dedup options")
        names = field_list(arg)
        if names and names[0].isdigit():
            if names[0] != "1":
                self.warn("dedup N keeps N events per value in SPL; XQL dedup keeps one")
            names = names[1:]
        return ["dedup " + ", ".join(self.fld(f) for f in names)]

    def _top(self, arg: str, direction: str) -> list[str]:
        main, by = split_by_clause(arg)
        limit = 10
        m = re.search(r"\blimit\s*=\s*(\d+)", main)
        if m:
            limit, main = int(m.group(1)), main.replace(m.group(0), "")
        main = re.sub(r"\b\w+\s*=\s*\S+", "", main)
        names = field_list(main)
        if names and names[0].isdigit():
            limit, names = int(names[0]), names[1:]
        if by:
            self.warn("top/rare with BY returns N rows per group in SPL; "
                      "the XQL draft limits the whole result")
        self.warn("top/rare also returns a 'percent' column in SPL; not reproduced")
        group = [self.fld(f) for f in names + field_list(by)]
        self.local.add("count")
        return [f"comp count() as count by {', '.join(group)}",
                f"sort {direction} count", f"limit {limit}"]

    def cmd_top(self, arg: str) -> list[str]:
        return self._top(arg, "desc")

    def cmd_rare(self, arg: str) -> list[str]:
        return self._top(arg, "asc")

    @staticmethod
    def _span(text: str) -> tuple[str | None, str]:
        m = re.search(r"\bspan\s*=\s*(\d+)(mon|[smhdwy])\w*", text)
        if not m:
            return None, text
        return f"{m.group(1)}{TIME_UNITS[m.group(2)]}", text.replace(m.group(0), "").strip()

    def cmd_bin(self, arg: str) -> list[str]:
        span, rest = self._span(arg)
        names = field_list(rest)
        if not span or len(names) != 1:
            raise Unsupported("bin without span=<n><unit> and a single field")
        return [f"bin {self.fld(names[0])} span = {span}"]

    cmd_bucket = cmd_bin

    def cmd_timechart(self, arg: str) -> list[str]:
        span, rest = self._span(arg)
        if not span:
            raise Unsupported("timechart without an explicit span")
        aggs, by = split_by_clause(rest)
        line = "comp " + ", ".join(self._aggs(aggs)) + " by _time"
        if by:
            line += ", " + ", ".join(self.fld(f) for f in field_list(by))
            self.warn("timechart pivots the BY field into columns; the XQL draft returns rows")
        return [f"bin _time span = {span}", line]

    def cmd_fillnull(self, arg: str) -> list[str]:
        value = "0"
        m = re.search(r'\bvalue\s*=\s*("[^"]*"|\S+)', arg)
        if m:
            value, arg = m.group(1), arg.replace(m.group(0), "")
        names = field_list(arg)
        if not names:
            raise Unsupported("fillnull without a field list")
        value = value if re.fullmatch(r'-?\d+(\.\d+)?|".*"', value) else f'"{value}"'
        return ["alter " + ", ".join(f"{self.fld(f)} = coalesce({self.fld(f)}, {value})"
                                     for f in names)]

    # ---- driver ----------------------------------------------------------

    def _timeframe(self) -> str | None:
        rel = r"-(\d+)(mon|[smhdwy])(@\w+)?"
        e, l = self.meta.get("earliest"), self.meta.get("latest")
        if not e:
            if l:
                self.warn("latest= without earliest= was ignored")
            return None
        me = re.fullmatch(rel, e)
        if not me:
            self.warn(f"earliest={e} is not a simple relative time; set the timeframe manually")
            return None
        if me.group(3) or (l and "@" in l):
            self.warn("Snap-to-time (@unit) is not reproduced; the window is rolling")
        start = f"{me.group(1)}{TIME_UNITS[me.group(2)]}"
        if not l or l == "now":
            return f"config timeframe = {start}"
        ml = re.fullmatch(rel, l)
        if not ml:
            self.warn(f"latest={l} is not a simple relative time; set the timeframe manually")
            return f"config timeframe = {start}"
        return (f'config timeframe between "-{start}" and '
                f'"-{ml.group(1)}{TIME_UNITS[ml.group(2)]}"')

    def _source(self) -> str:
        dataset = None
        for key in ("sourcetype", "index", "source"):
            if key in self.meta:
                dataset = self.datasets.get(f"{key}:{self.meta[key]}")
                if dataset:
                    break
        if not dataset:
            hint = ", ".join(f"{k}={self.meta[k]}" for k in ("index", "sourcetype", "source")
                             if k in self.meta) or "no index/sourcetype"
            self.warn(f"No dataset mapping for {hint}; replace <dataset> manually")
            dataset = "<dataset>"
        prefix = "datamodel dataset" if self.mode == "datamodel" else "dataset"
        return f"{prefix} = {dataset}"

    def translate(self, spl: str) -> Result:
        spl = " ".join(spl.strip().split())
        segments = split_top(spl, "|")
        stages: list[str] = []
        base = segments[0]
        if base.lower().startswith("search "):
            base = base[7:]
        if "[" in spl:
            self.warn("Subsearches ([...]) are not translated")
        if base:
            flt = self.search_expr(base)
            if flt:
                stages.append(f"filter {flt}")
        else:
            self.warn("Query starts with a generating command; no base search found")
        for seg in segments[1:]:
            if not seg:
                continue
            name, _, arg = seg.partition(" ")
            handler = getattr(self, f"cmd_{name.lower()}", None)
            try:
                if handler is None:
                    raise Unsupported("no translation rule")
                stages.extend(handler(arg))
            except Unsupported as exc:
                self.warn(f"'{name}' not translated: {exc}")
                stages.append(f"// UNSUPPORTED: {seg}")
        head = [s for s in (self._timeframe(), self._source()) if s]
        lines = []
        for stage in head + stages:
            # Comments stand on their own line so the pipeline stays valid.
            lines.append(stage if stage.startswith("//") or not lines else f"| {stage}")
        return Result("\n".join(lines), self.warnings)


def translate(spl: str, mode: str = "datamodel", mapping: dict | None = None,
              double_backslashes: bool = False) -> Result:
    return Translator(mode=mode, mapping=mapping,
                      double_backslashes=double_backslashes).translate(spl)
