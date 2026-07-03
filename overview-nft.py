#!/usr/bin/env python3
"""
nft-overview-tabnft.py — leesbaar overzicht van een nftables JSON-ruleset.

Gebruik:
    nft -j list ruleset | ./nft-overview-tabnft.py
    ./nft-overview-tabnft.py ruleset.json
    ./nft-overview-tabnft.py ruleset.json --ports-only
    ./nft-overview-tabnft.py ruleset.json --format md
    ./nft-overview-tabnft.py ruleset.json --resolve
    ./nft-overview-tabnft.py --live
    ./nft-overview-tabnft.py --deps

Doel:
  * Gebruikt python3-tabulate voor nette tabellen als die beschikbaar is.
  * Gebruikt python3-nftables optioneel voor --live, dus rechtstreeks via
    libnftables in plaats van shelling out naar `nft`.
  * Gebruikt python3-jsonschema optioneel voor lichte inputvalidatie.
  * Robuuster dan eenvoudige tekstparsing: gebruikt de JSON van `nft -j`.
  * Behoudt meer informatie: meerdere matches per regel, negatieve matches,
    bitwise-expressies, named sets, maps, fib, NAT-acties, xt-compat, mangle,
    dynamic-set updates en jump/goto/return.
  * Geeft een bruikbare poorten-samenvatting. Met --resolve wordt ook een
    begrensde control-flow-analyse gedaan voor jump/goto/return-paden.

Belangrijke beperking:
  Dit is statische analyse. Een "accept-pad" betekent: deze ruleset bevat een
  pad naar accept in de geanalyseerde chain/hook-context. Het is niet hetzelfde
  als een garantie dat verkeer globaal wordt toegelaten door alle hooks, routes,
  policy routing, sysctls, conntrack-statussen, interfaces en externe filters.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from tabulate import tabulate as _tabulate
except Exception:  # pragma: no cover - optionele dependency
    _tabulate = None

try:
    import jsonschema as _jsonschema
except Exception:  # pragma: no cover - optionele dependency
    _jsonschema = None

try:
    from nftables import Nftables as _Nftables
except Exception:  # pragma: no cover - optionele dependency
    _Nftables = None


Key3 = Tuple[str, str, str]


NFTABLES_TOPLEVEL_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "description": "Lichte validatie voor nft -j list ruleset output. Dit is bewust geen volledige nftables-schema-validatie.",
    "oneOf": [
        {
            "type": "object",
            "required": ["nftables"],
            "properties": {
                "nftables": {
                    "type": "array",
                    "items": {"type": "object"},
                }
            },
            "additionalProperties": True,
        },
        {
            "type": "array",
            "items": {"type": "object"},
        },
    ],
}


# ---------------------------------------------------------------------------
# Interne representatie
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MatchAtom:
    field: str
    op: str
    value: Any
    value_text: str
    category: str = "other"

    def render(self) -> str:
        return f"{self.field} {self.op} {self.value_text}"


@dataclass(frozen=True)
class Verdict:
    kind: str = "continue"
    target: Optional[str] = None
    detail: Optional[str] = None

    def render(self) -> str:
        if self.target:
            return f"{self.kind} -> {self.target}"
        if self.detail:
            return f"{self.kind} ({self.detail})"
        return self.kind


@dataclass
class RuleSummary:
    family: str
    table: str
    chain: str
    index: int
    handle: Optional[int] = None
    comment: Optional[str] = None
    matches: List[MatchAtom] = field(default_factory=list)
    verdict: Verdict = field(default_factory=Verdict)
    extra: List[str] = field(default_factory=list)
    raw_expr: List[Any] = field(default_factory=list)

    @property
    def key(self) -> Key3:
        return (self.family, self.table, self.chain)


@dataclass
class ResolvedPath:
    verdict: str
    constraints: List[MatchAtom]
    trace: List[str]
    base: Key3
    note: str = ""


@dataclass
class Frame:
    key: Key3
    index: int


@dataclass
class State:
    stack: List[Frame]
    constraints: List[MatchAtom]
    trace: List[str]
    base: Key3

    def signature(self) -> Tuple[Any, ...]:
        # Compacte maar effectieve cycledetectie.
        cons = tuple((m.field, m.op, m.value_text) for m in self.constraints[-12:])
        stack = tuple((f.key, f.index) for f in self.stack[-12:])
        return (stack, cons)


@dataclass
class RulesetModel:
    metainfo: Dict[str, Any] = field(default_factory=dict)
    tables: Dict[Tuple[str, str], Dict[str, Any]] = field(default_factory=dict)
    chains: Dict[Key3, Dict[str, Any]] = field(default_factory=dict)
    sets: Dict[Key3, Dict[str, Any]] = field(default_factory=dict)
    maps: Dict[Key3, Dict[str, Any]] = field(default_factory=dict)
    flowtables: Dict[Key3, Dict[str, Any]] = field(default_factory=dict)
    raw_rules: List[Dict[str, Any]] = field(default_factory=list)
    rules: Dict[Key3, List[RuleSummary]] = field(default_factory=lambda: defaultdict(list))
    warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class TextRenderer:
    def __init__(self, out=sys.stdout, width: int = 120, tablefmt: Optional[str] = None):
        self.out = out
        self.width = width
        self.tablefmt = tablefmt or "simple"

    def line(self, text: str = "") -> None:
        print(text, file=self.out)

    def heading(self, text: str, level: int = 1) -> None:
        if level <= 1:
            self.line("=" * min(self.width, 90))
            self.line(text.upper())
            self.line("=" * min(self.width, 90))
        else:
            self.line(text)
            self.line("-" * min(self.width, max(20, len(text))))

    def note(self, text: str) -> None:
        self.line(f"Let op: {text}")

    def format_cell(self, value: Any, cap: int, *, preserve_newlines: bool = False) -> str:
        if value is None:
            s = ""
        else:
            s = str(value)
        if not preserve_newlines:
            s = s.replace("\n", " ⏎ ")
        if cap and len(s) > cap:
            return s[: max(1, cap - 1)] + "…"
        return s

    def table(
        self,
        columns: Sequence[Tuple[str, str]],
        rows: Sequence[Dict[str, Any]],
        cap: int = 44,
        *,
        multiline: bool = False,
    ) -> None:
        if not rows:
            self.line("(geen rijen)")
            return

        headers = [title for _, title in columns]
        data = [
            [self.format_cell(row.get(key, ""), cap, preserve_newlines=multiline) for key, _ in columns]
            for row in rows
        ]

        if _tabulate is not None:
            self.line(_tabulate(data, headers=headers, tablefmt=self.tablefmt, disable_numparse=True))
            return

        # Fallback zonder python3-tabulate. Multiline-cellen worden dan plat
        # gemaakt; de nette meerregelige weergave is precies waarvoor
        # python3-tabulate nuttig is.
        data = [[str(cell).replace("\n", " ⏎ ") for cell in row] for row in data]

        widths: Dict[int, int] = {}
        for idx, title in enumerate(headers):
            max_len = len(title)
            for row in data:
                max_len = max(max_len, len(str(row[idx])))
            widths[idx] = min(cap or max_len, max(4, max_len))

        def cell(value: Any, width: int) -> str:
            s = str(value)
            if len(s) > width:
                return s[: max(1, width - 1)] + "…"
            return s.ljust(width)

        self.line(" ".join(cell(title, widths[i]) for i, title in enumerate(headers)))
        self.line(" ".join("-" * widths[i] for i in range(len(headers))))
        for row in data:
            self.line(" ".join(cell(row[i], widths[i]) for i in range(len(headers))))


class MarkdownRenderer(TextRenderer):
    def __init__(self, out=sys.stdout, width: int = 120, tablefmt: Optional[str] = None):
        super().__init__(out=out, width=width, tablefmt=tablefmt or "github")

    def esc(self, value: Any) -> str:
        s = str(value)
        return (
            s.replace("\\", "\\\\")
             .replace("|", "\\|")
             .replace("\n", "<br>")
        )

    def heading(self, text: str, level: int = 1) -> None:
        self.line(f"{'#' * max(1, level)} {self.esc(text)}")

    def note(self, text: str) -> None:
        self.line(f"> **Let op:** {self.esc(text)}")

    def format_cell(self, value: Any, cap: int, *, preserve_newlines: bool = False) -> str:
        if value is None:
            s = ""
        else:
            s = str(value)
        if not preserve_newlines:
            s = s.replace("\n", " ⏎ ")
        if cap and len(s) > cap:
            s = s[: max(1, cap - 1)] + "…"
        return self.esc(s)

    def table(
        self,
        columns: Sequence[Tuple[str, str]],
        rows: Sequence[Dict[str, Any]],
        cap: int = 10_000,
        *,
        multiline: bool = False,
    ) -> None:
        if not rows:
            self.line("_Geen rijen._")
            return
        super().table(columns, rows, cap=cap, multiline=multiline)


# ---------------------------------------------------------------------------
# Waarden en expressies formatteren
# ---------------------------------------------------------------------------

def first_key(d: Dict[str, Any]) -> Optional[str]:
    return next(iter(d.keys()), None) if d else None


def short_json(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def strip_at(name: str) -> str:
    return name[1:] if isinstance(name, str) and name.startswith("@") else name


def verdict_from_object(obj: Dict[str, Any]) -> Optional[Verdict]:
    for kind in ("accept", "drop", "return"):
        if kind in obj:
            return Verdict(kind)
    if "reject" in obj:
        r = obj["reject"]
        if isinstance(r, dict):
            detail = ", ".join(f"{k}={v}" for k, v in r.items())
        else:
            detail = None
        return Verdict("reject", detail=detail)
    if "jump" in obj:
        j = obj["jump"]
        return Verdict("jump", target=j.get("target") if isinstance(j, dict) else str(j))
    if "goto" in obj:
        g = obj["goto"]
        return Verdict("goto", target=g.get("target") if isinstance(g, dict) else str(g))
    return None


def field_name(left: Any) -> str:
    """Herleid een leesbare veldnaam uit een nftables JSON-expressie."""
    if isinstance(left, str):
        return left

    if isinstance(left, list):
        return " . ".join(field_name(x) for x in left)

    if not isinstance(left, dict):
        return "?"

    if "payload" in left:
        p = left["payload"]
        proto = p.get("protocol", "")
        field_ = p.get("field", "")
        return f"{proto} {field_}".strip()

    if "meta" in left:
        return f"meta {left['meta'].get('key', '')}".strip()

    if "ct" in left:
        c = left["ct"]
        key = c.get("key", "")
        direction = c.get("dir")
        return f"ct {direction} {key}".strip() if direction else f"ct {key}".strip()

    if "fib" in left:
        f = left["fib"]
        result = f.get("result", "")
        flags = ",".join(f.get("flags", []))
        suffix = f" flags={flags}" if flags else ""
        return f"fib {result}{suffix}".strip()

    if "rt" in left:
        return f"rt {left['rt'].get('key', '')}".strip()

    if "exthdr" in left:
        e = left["exthdr"]
        name = e.get("name", "")
        field_ = e.get("field", "")
        return f"exthdr {name} {field_}".strip()

    if "socket" in left:
        return f"socket {left['socket'].get('key', '')}".strip()

    if "osf" in left:
        return "osf"

    if "numgen" in left:
        n = left["numgen"]
        return f"numgen {n.get('mode', '')} mod {n.get('mod', '')}".strip()

    if "jhash" in left:
        return "jhash " + fmt_value(left["jhash"])

    if "symhash" in left:
        return "symhash " + fmt_value(left["symhash"])

    if "concat" in left:
        return " . ".join(field_name(part) for part in left["concat"])

    if "&" in left:
        ops = left["&"]
        if isinstance(ops, list) and ops:
            base = field_name(ops[0])
            mask = fmt_value(ops[1]) if len(ops) > 1 else "?"
            return f"{base} & {mask}"
        return "&"

    if "|" in left:
        ops = left["|"]
        if isinstance(ops, list):
            return " | ".join(field_name(x) if isinstance(x, dict) else fmt_value(x) for x in ops)
        return "|"

    if "^" in left:
        ops = left["^"]
        if isinstance(ops, list):
            return " ^ ".join(field_name(x) if isinstance(x, dict) else fmt_value(x) for x in ops)
        return "^"

    if "map" in left:
        return fmt_value(left)

    if "vmap" in left:
        return fmt_value(left)

    return short_json(left)


def categorize_field(name: str) -> str:
    if name.endswith(" dport") or name.endswith(" sport") or name in ("th dport", "th sport"):
        return "port"
    if name in ("ip saddr", "ip6 saddr", "ip daddr", "ip6 daddr"):
        return "addr"
    if name in ("meta iif", "meta iifname", "meta oif", "meta oifname"):
        return "iface"
    if name in ("meta l4proto", "ip protocol", "ip6 nexthdr"):
        return "proto"
    if name.startswith("ct "):
        return "ct"
    return "other"


def fmt_limit(lim: Dict[str, Any]) -> str:
    if not isinstance(lim, dict):
        return fmt_value(lim)
    rate = lim.get("rate", "?")
    per = lim.get("per", "second")
    burst = lim.get("burst")
    inv = lim.get("inv", False)
    parts = [f"{'boven' if inv else 'tot'} {rate}/{per}"]
    if burst is not None:
        parts.append(f"burst {burst}")
    return "limit " + ", ".join(parts)


def fmt_set_element(e: Any, *, model: Optional[RulesetModel] = None, family: Optional[str] = None,
                    table: Optional[str] = None, with_meta: bool = True) -> str:
    if isinstance(e, dict) and "elem" in e:
        elem = e["elem"]
        if isinstance(elem, dict):
            val = elem.get("val", elem)
            base = fmt_value(val, model=model, family=family, table=table)
            meta = []
            if with_meta:
                if "timeout" in elem:
                    meta.append(f"timeout={elem['timeout']}s")
                if "expires" in elem:
                    meta.append(f"expires={elem['expires']}s")
                if "limit" in elem:
                    meta.append(fmt_limit(elem["limit"]))
            return base + (f" ({'; '.join(meta)})" if meta else "")
        return fmt_value(elem, model=model, family=family, table=table)
    return fmt_value(e, model=model, family=family, table=table)


def fmt_set_ref(name: str, *, model: Optional[RulesetModel], family: Optional[str],
                table: Optional[str], preview: int = 8) -> str:
    if not model or not family or not table:
        return name

    set_name = strip_at(name)
    s = model.sets.get((family, table, set_name))
    m = model.maps.get((family, table, set_name))
    if s is None and m is None:
        return name

    obj = s if s is not None else m
    kind = "map" if m is not None else "set"
    elems = obj.get("elem")
    flags = ",".join(obj.get("flags", [])) if obj.get("flags") else ""
    suffix_bits = []
    if flags:
        suffix_bits.append(flags)
    if obj.get("timeout") is not None:
        suffix_bits.append(f"timeout={obj.get('timeout')}s")
    suffix = f" [{'; '.join(suffix_bits)}]" if suffix_bits else ""

    if elems is None:
        return f"{name}=({kind}: dynamisch/leeg bij export){suffix}"

    shown = [fmt_set_element(x, model=model, family=family, table=table, with_meta=False) for x in elems[:preview]]
    more = f", +{len(elems) - preview} meer" if len(elems) > preview else ""
    return f"{name}={{" + ", ".join(shown) + more + f"}}{suffix}"


def fmt_value(v: Any, *, model: Optional[RulesetModel] = None, family: Optional[str] = None,
              table: Optional[str] = None) -> str:
    """Zet een nftables JSON-waarde om naar een leesbare string."""
    if isinstance(v, str):
        if v.startswith("@"):
            return fmt_set_ref(v, model=model, family=family, table=table)
        return v

    if isinstance(v, (int, float, bool)) or v is None:
        return str(v)

    if isinstance(v, list):
        # Pair-list in maps: [[key, value], ...]
        if v and all(isinstance(x, list) and len(x) == 2 for x in v):
            return "{ " + ", ".join(
                f"{fmt_value(k, model=model, family=family, table=table)} : "
                f"{fmt_value(val, model=model, family=family, table=table)}"
                for k, val in v
            ) + " }"
        return ", ".join(fmt_value(x, model=model, family=family, table=table) for x in v)

    if not isinstance(v, dict):
        return str(v)

    verdict = verdict_from_object(v)
    if verdict:
        return verdict.render()

    if "range" in v:
        lo, hi = v["range"]
        return f"{fmt_value(lo, model=model, family=family, table=table)}-" \
               f"{fmt_value(hi, model=model, family=family, table=table)}"

    if "prefix" in v:
        p = v["prefix"]
        return f"{p.get('addr')}/{p.get('len')}"

    if "set" in v:
        elems = v["set"]
        return "{ " + fmt_value(elems, model=model, family=family, table=table) + " }"

    if "concat" in v:
        return " . ".join(fmt_value(x, model=model, family=family, table=table) for x in v["concat"])

    if "elem" in v:
        return fmt_set_element(v, model=model, family=family, table=table)

    if "map" in v:
        mp = v["map"]
        if isinstance(mp, dict):
            key = fmt_value(mp.get("key"), model=model, family=family, table=table)
            data = fmt_value(mp.get("data"), model=model, family=family, table=table)
            return f"{key} map {data}"
        return f"map {fmt_value(mp, model=model, family=family, table=table)}"

    if "vmap" in v:
        mp = v["vmap"]
        if isinstance(mp, dict):
            key = fmt_value(mp.get("key"), model=model, family=family, table=table)
            data = fmt_value(mp.get("data"), model=model, family=family, table=table)
            return f"{key} vmap {data}"
        return f"vmap {fmt_value(mp, model=model, family=family, table=table)}"

    if "&" in v:
        ops = v["&"]
        if isinstance(ops, list):
            return " & ".join(fmt_value(x, model=model, family=family, table=table) for x in ops)
        return short_json(v)

    if "|" in v:
        ops = v["|"]
        if isinstance(ops, list):
            return " | ".join(fmt_value(x, model=model, family=family, table=table) for x in ops)
        return short_json(v)

    if "^" in v:
        ops = v["^"]
        if isinstance(ops, list):
            return " ^ ".join(fmt_value(x, model=model, family=family, table=table) for x in ops)
        return short_json(v)

    # Expressies als waarde.
    if any(k in v for k in ("payload", "meta", "ct", "fib", "rt", "exthdr", "socket")):
        return field_name(v)

    if "limit" in v:
        return fmt_limit(v["limit"])

    return short_json(v)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def validate_top_level(obj: Any) -> None:
    """Lichte JSON-validatie. De volledige nftables-expressietaal blijft expres open-ended."""
    if _jsonschema is None:
        return
    _jsonschema.validate(instance=obj, schema=NFTABLES_TOPLEVEL_SCHEMA)


def extract_nftables_items(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, dict) and isinstance(obj.get("nftables"), list):
        return obj["nftables"]
    if isinstance(obj, list):
        return obj
    raise ValueError("JSON bevat geen top-level 'nftables'-lijst")


def parse_json_payload(data: Any, *, validate: bool) -> List[Dict[str, Any]]:
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    if isinstance(data, str):
        obj = json.loads(data)
    else:
        obj = data
    if validate:
        validate_top_level(obj)
    return extract_nftables_items(obj)


def load_ruleset(path: Optional[str], *, validate: bool = True) -> List[Dict[str, Any]]:
    if path is None or path == "-":
        data = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
    return parse_json_payload(data, validate=validate)


def load_ruleset_via_libnftables(command: str = "list ruleset", *, handles: bool = True,
                                 validate: bool = True) -> List[Dict[str, Any]]:
    """Lees live via python3-nftables/libnftables.

    De Debian-binding exposeert Nftables.cmd() als tuple (rc, stdout, stderr).
    Bij JSON-output is stdout normaal een JSON-string met een top-level
    {'nftables': [...]} object.
    """
    if _Nftables is None:
        raise RuntimeError("python3-nftables is niet beschikbaar; installeer: apt install python3-nftables")

    nft = _Nftables()
    if hasattr(nft, "set_json_output"):
        nft.set_json_output(True)
    if handles and hasattr(nft, "set_handle_output"):
        nft.set_handle_output(True)

    rc, out, err = nft.cmd(command)
    if rc != 0:
        msg = err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err)
        raise RuntimeError(f"libnftables faalde voor `{command}`: {msg.strip()}")
    return parse_json_payload(out, validate=validate)


def fmt_nat_detail(obj: Any, *, model: RulesetModel, family: str, table: str) -> Optional[str]:
    if obj in (None, {}):
        return None
    if not isinstance(obj, dict):
        return fmt_value(obj, model=model, family=family, table=table)
    parts: List[str] = []
    if obj.get("family") is not None:
        parts.append(f"family={obj.get('family')}")
    if obj.get("addr") is not None:
        parts.append(f"addr={fmt_value(obj.get('addr'), model=model, family=family, table=table)}")
    if obj.get("port") is not None:
        parts.append(f"port={fmt_value(obj.get('port'), model=model, family=family, table=table)}")
    if obj.get("flags") is not None:
        parts.append(f"flags={fmt_value(obj.get('flags'), model=model, family=family, table=table)}")
    unknown = {k: v for k, v in obj.items() if k not in {"family", "addr", "port", "flags"}}
    if unknown:
        parts.append(fmt_value(unknown, model=model, family=family, table=table))
    return ", ".join(parts) if parts else None


def parse_verdict_expr(expr: Dict[str, Any], *, model: RulesetModel, family: str, table: str) -> Optional[Verdict]:
    v = verdict_from_object(expr)
    if v:
        return v

    if "queue" in expr:
        return Verdict("queue", detail=fmt_value(expr["queue"], model=model, family=family, table=table))

    if "masquerade" in expr:
        return Verdict("masquerade", detail=fmt_nat_detail(expr["masquerade"], model=model, family=family, table=table))

    if "snat" in expr:
        return Verdict("snat", detail=fmt_nat_detail(expr["snat"], model=model, family=family, table=table))

    if "dnat" in expr:
        return Verdict("dnat", detail=fmt_nat_detail(expr["dnat"], model=model, family=family, table=table))

    if "redirect" in expr:
        return Verdict("redirect", detail=fmt_nat_detail(expr["redirect"], model=model, family=family, table=table))

    return None


def fmt_set_statement(st: Dict[str, Any], *, model: RulesetModel, family: str, table: str) -> str:
    op = st.get("op", "add")
    set_name = st.get("set", "?")
    elem = fmt_value(st.get("elem"), model=model, family=family, table=table)
    stmt = st.get("stmt") or []
    suffix = ""
    if stmt:
        suffix = " if " + "; ".join(fmt_expr(x, model=model, family=family, table=table) for x in stmt)
    return f"{op} {elem} -> {fmt_value(set_name, model=model, family=family, table=table)}{suffix}"


def fmt_expr(expr: Any, *, model: RulesetModel, family: str, table: str) -> str:
    if not isinstance(expr, dict):
        return fmt_value(expr, model=model, family=family, table=table)

    if "match" in expr:
        m = expr["match"]
        field = field_name(m.get("left"))
        return f"{field} {m.get('op', '==')} {fmt_value(m.get('right'), model=model, family=family, table=table)}"

    v = parse_verdict_expr(expr, model=model, family=family, table=table)
    if v:
        return v.render()

    if "counter" in expr:
        c = expr["counter"]
        if isinstance(c, dict):
            return f"counter packets={c.get('packets', '?')} bytes={c.get('bytes', '?')}"
        return "counter"

    if "log" in expr:
        return "log " + fmt_value(expr["log"], model=model, family=family, table=table)

    if "limit" in expr:
        return fmt_limit(expr["limit"])

    if "mangle" in expr:
        mg = expr["mangle"]
        key = field_name(mg.get("key"))
        val = fmt_value(mg.get("value"), model=model, family=family, table=table)
        return f"set {key} = {val}"

    if "set" in expr:
        return fmt_set_statement(expr["set"], model=model, family=family, table=table)

    if "map" in expr:
        return "map " + fmt_value(expr["map"], model=model, family=family, table=table)

    if "vmap" in expr:
        return "vmap " + fmt_value(expr["vmap"], model=model, family=family, table=table)

    if "xt" in expr:
        xt = expr["xt"]
        if isinstance(xt, dict):
            return f"xt-{xt.get('type', '?')} {xt.get('name', '?')}"
        return "xt " + fmt_value(xt, model=model, family=family, table=table)

    if "flow" in expr:
        return "flow " + fmt_value(expr["flow"], model=model, family=family, table=table)

    return short_json(expr)


def parse_rule(raw_rule: Dict[str, Any], index: int, model: RulesetModel) -> RuleSummary:
    family = raw_rule.get("family", "?")
    table = raw_rule.get("table", "?")
    chain = raw_rule.get("chain", "?")

    out = RuleSummary(
        family=family,
        table=table,
        chain=chain,
        index=index,
        handle=raw_rule.get("handle"),
        comment=raw_rule.get("comment"),
        raw_expr=raw_rule.get("expr", []),
    )

    for expr in raw_rule.get("expr", []):
        if not isinstance(expr, dict):
            out.extra.append(str(expr))
            continue

        if "match" in expr:
            m = expr["match"]
            left = m.get("left")
            right = m.get("right")
            op = m.get("op", "==")
            fname = field_name(left)
            value_text = fmt_value(right, model=model, family=family, table=table)
            out.matches.append(MatchAtom(fname, op, right, value_text, categorize_field(fname)))
            continue

        verdict = parse_verdict_expr(expr, model=model, family=family, table=table)
        if verdict:
            out.verdict = verdict
            continue

        # Niet-terminale statements.
        if "counter" in expr:
            # Counter alleen tonen als er non-zero waarden zijn; anders wordt output snel ruis.
            c = expr["counter"]
            if isinstance(c, dict) and (c.get("packets", 0) or c.get("bytes", 0)):
                out.extra.append(fmt_expr(expr, model=model, family=family, table=table))
            continue

        if any(k in expr for k in ("log", "limit", "mangle", "set", "map", "vmap", "xt", "flow")):
            out.extra.append(fmt_expr(expr, model=model, family=family, table=table))
            continue

        out.extra.append(fmt_expr(expr, model=model, family=family, table=table))

    return out


def build_model(items: List[Dict[str, Any]]) -> RulesetModel:
    model = RulesetModel()

    for item in items:
        if not isinstance(item, dict):
            continue

        if "metainfo" in item:
            model.metainfo.update(item["metainfo"])

        elif "table" in item:
            t = item["table"]
            model.tables[(t.get("family", "?"), t.get("name", "?"))] = t

        elif "chain" in item:
            c = item["chain"]
            model.chains[(c.get("family", "?"), c.get("table", "?"), c.get("name", "?"))] = c

        elif "set" in item:
            s = item["set"]
            model.sets[(s.get("family", "?"), s.get("table", "?"), s.get("name", "?"))] = s

        elif "map" in item:
            m = item["map"]
            model.maps[(m.get("family", "?"), m.get("table", "?"), m.get("name", "?"))] = m

        elif "flowtable" in item:
            ft = item["flowtable"]
            model.flowtables[(ft.get("family", "?"), ft.get("table", "?"), ft.get("name", "?"))] = ft

        elif "rule" in item:
            model.raw_rules.append(item["rule"])

    per_chain_counter: Dict[Key3, int] = defaultdict(int)
    for rr in model.raw_rules:
        key = (rr.get("family", "?"), rr.get("table", "?"), rr.get("chain", "?"))
        idx = per_chain_counter[key]
        per_chain_counter[key] += 1
        rule = parse_rule(rr, idx, model)
        model.rules[key].append(rule)

    return model


# ---------------------------------------------------------------------------
# Rule/chain beschrijven
# ---------------------------------------------------------------------------

def describe_rule(rule: RuleSummary) -> Tuple[str, str]:
    parts = [m.render() for m in rule.matches]
    parts.extend(rule.extra)
    cond = " ; ".join(parts) if parts else "(altijd)"
    verdict = rule.verdict.render()
    if rule.comment:
        cond = f"{cond}  # {rule.comment}"
    return cond, verdict


def marker_for(verdict: Verdict) -> str:
    if verdict.kind in ("accept", "masquerade", "snat", "dnat", "redirect"):
        return "✔"
    if verdict.kind in ("drop", "reject"):
        return "✘"
    if verdict.kind in ("jump", "goto", "return"):
        return "↪"
    return "·"


def chain_label(c: Dict[str, Any]) -> str:
    name = c.get("name", "?")
    if c.get("hook"):
        return (
            f"chain {name} "
            f"(type={c.get('type', '-')}, hook={c.get('hook')}, "
            f"prio={c.get('prio')}, policy={c.get('policy', '-')})"
        )
    return f"chain {name} (regular chain)"


# ---------------------------------------------------------------------------
# Samenvattingen
# ---------------------------------------------------------------------------

def atoms_by_field(atoms: Iterable[MatchAtom], names: Iterable[str]) -> List[MatchAtom]:
    wanted = set(names)
    return [m for m in atoms if m.field in wanted]


def atoms_ending(atoms: Iterable[MatchAtom], suffix: str) -> List[MatchAtom]:
    return [m for m in atoms if m.field.endswith(suffix)]


def render_atoms(atoms: Sequence[MatchAtom], default: str = "-") -> str:
    if not atoms:
        return default
    return " & ".join(f"{m.op} {m.value_text}" for m in atoms)


def infer_proto(atoms: Sequence[MatchAtom], dports: Sequence[MatchAtom] = ()) -> str:
    # Dport-veld zelf is vaak de beste hint.
    for m in dports:
        proto = m.field.split()[0]
        if proto and proto not in ("th", "?"):
            return proto

    for m in atoms:
        if m.field == "meta l4proto":
            return m.value_text
        if m.field == "ip protocol":
            return m.value_text
        if m.field == "ip6 nexthdr":
            return m.value_text
    return "?"


def summarize_path_constraints(atoms: Sequence[MatchAtom]) -> Dict[str, str]:
    dports = atoms_ending(atoms, " dport")
    sports = atoms_ending(atoms, " sport")
    saddr = atoms_by_field(atoms, ("ip saddr", "ip6 saddr"))
    daddr = atoms_by_field(atoms, ("ip daddr", "ip6 daddr"))
    iif = atoms_by_field(atoms, ("meta iif", "meta iifname"))
    oif = atoms_by_field(atoms, ("meta oif", "meta oifname"))
    state = atoms_by_field(atoms, ("ct state",))
    proto = infer_proto(atoms, dports)

    return {
        "proto": proto,
        "dport": render_atoms(dports),
        "sport": render_atoms(sports),
        "src": render_atoms(saddr, "overal"),
        "dst": render_atoms(daddr),
        "iif": render_atoms(iif),
        "oif": render_atoms(oif),
        "state": render_atoms(state),
    }


def is_port_rule(rule: RuleSummary) -> bool:
    return bool(atoms_ending(rule.matches, " dport"))


def direct_port_rows(model: RulesetModel, verdicts: Sequence[str]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    wanted = set(verdicts)
    for key, rules in model.rules.items():
        family, table, chain = key
        for rule in rules:
            if rule.verdict.kind not in wanted or not is_port_rule(rule):
                continue
            s = summarize_path_constraints(rule.matches)
            rows.append({
                "actie": rule.verdict.render(),
                "proto": s["proto"],
                "dport": s["dport"],
                "sport": s["sport"],
                "bron": s["src"],
                "doel": s["dst"],
                "iif": s["iif"],
                "oif": s["oif"],
                "state": s["state"],
                "chain": f"{family}/{table}/{chain}",
                "handle": rule.handle if rule.handle is not None else "",
                "comment": rule.comment or "",
            })
    rows.sort(key=lambda r: (r["actie"], r["proto"], r["dport"], r["chain"], str(r["handle"])))
    return rows


def nat_rows(model: RulesetModel) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for key, rules in model.rules.items():
        family, table, chain = key
        for rule in rules:
            if rule.verdict.kind not in ("dnat", "snat", "masquerade", "redirect"):
                continue
            s = summarize_path_constraints(rule.matches)
            rows.append({
                "actie": rule.verdict.kind,
                "matches": ";\n".join(m.render() for m in rule.matches) or "(altijd)",
                "detail": rule.verdict.detail or "",
                "chain": f"{family}/{table}/{chain}",
                "handle": rule.handle if rule.handle is not None else "",
            })
    rows.sort(key=lambda r: (r["actie"], r["chain"], str(r["handle"])))
    return rows


def warning_rows(model: RulesetModel) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for key, rules in model.rules.items():
        family, table, chain = key
        for rule in rules:
            for extra in rule.extra:
                if extra.startswith("xt-"):
                    rows.append({
                        "type": "xt-compat",
                        "chain": f"{family}/{table}/{chain}",
                        "handle": rule.handle if rule.handle is not None else "",
                        "detail": extra,
                    })
                elif extra.startswith("flow "):
                    rows.append({
                        "type": "flowtable",
                        "chain": f"{family}/{table}/{chain}",
                        "handle": rule.handle if rule.handle is not None else "",
                        "detail": extra,
                    })
    return rows


# ---------------------------------------------------------------------------
# Begrensde control-flow-analyse
# ---------------------------------------------------------------------------

TERMINAL_VERDICTS = {"accept", "drop", "reject", "queue", "snat", "dnat", "redirect", "masquerade"}


def make_target_key(current: Key3, target: Optional[str]) -> Optional[Key3]:
    if not target:
        return None
    return (current[0], current[1], target)


def is_base_chain(model: RulesetModel, key: Key3) -> bool:
    return bool(model.chains.get(key, {}).get("hook"))


def resolve_paths(model: RulesetModel, *, max_states: int = 50000, only_base: bool = True) -> List[ResolvedPath]:
    """Volg jump/goto/return globaal maar begrensd. Branches: rule matcht wel/niet."""
    starts = []
    for key, chain in model.chains.items():
        if only_base and not chain.get("hook"):
            continue
        starts.append(key)

    results: List[ResolvedPath] = []

    for start in sorted(starts):
        work: List[State] = [State(stack=[Frame(start, 0)], constraints=[], trace=[], base=start)]
        seen = set()
        states = 0

        while work:
            state = work.pop()
            sig = state.signature()
            if sig in seen:
                continue
            seen.add(sig)
            states += 1

            if states > max_states:
                results.append(ResolvedPath(
                    verdict="unresolved",
                    constraints=state.constraints,
                    trace=state.trace,
                    base=start,
                    note=f"state-limit {max_states} bereikt",
                ))
                break

            if not state.stack:
                continue

            frame = state.stack[-1]
            key = frame.key
            rules = model.rules.get(key, [])
            chain_meta = model.chains.get(key, {})

            if frame.index >= len(rules):
                # Einde base chain: policy. Einde regular chain: impliciete return.
                if is_base_chain(model, key):
                    policy = chain_meta.get("policy", "accept")
                    results.append(ResolvedPath(f"policy:{policy}", state.constraints, state.trace + [f"{key[2]}:policy:{policy}"], start))
                    continue

                new_stack = state.stack[:-1]
                if not new_stack:
                    results.append(ResolvedPath("return", state.constraints, state.trace + [f"{key[2]}:return"], start))
                    continue

                work.append(State(new_stack, state.constraints, state.trace + [f"{key[2]}:return"], start))
                continue

            rule = rules[frame.index]
            label = f"{key[2]}[{rule.index}" + (f"#{rule.handle}" if rule.handle is not None else "") + "]"

            # Branch 1: regel matcht niet, ga door.
            skip_stack = list(state.stack)
            skip_stack[-1] = Frame(key, frame.index + 1)
            work.append(State(skip_stack, state.constraints, state.trace, start))

            # Branch 2: regel matcht wel.
            constraints = state.constraints + rule.matches
            trace = state.trace + [label]
            verdict = rule.verdict.kind

            if verdict in TERMINAL_VERDICTS:
                results.append(ResolvedPath(verdict, constraints, trace, start))
                continue

            if verdict == "continue":
                next_stack = list(state.stack)
                next_stack[-1] = Frame(key, frame.index + 1)
                work.append(State(next_stack, constraints, trace, start))
                continue

            if verdict == "return":
                if is_base_chain(model, key):
                    policy = chain_meta.get("policy", "accept")
                    results.append(ResolvedPath(f"policy:{policy}", constraints, trace + [f"{key[2]}:policy:{policy}"], start))
                else:
                    new_stack = state.stack[:-1]
                    if new_stack:
                        work.append(State(new_stack, constraints, trace + [f"{key[2]}:return"], start))
                    else:
                        results.append(ResolvedPath("return", constraints, trace + [f"{key[2]}:return"], start))
                continue

            if verdict in ("jump", "goto"):
                target_key = make_target_key(key, rule.verdict.target)
                if not target_key or target_key not in model.chains:
                    results.append(ResolvedPath("unresolved", constraints, trace, start, note=f"target ontbreekt: {rule.verdict.target}"))
                    continue

                if verdict == "jump":
                    # Caller hervat na de jump-regel.
                    call_stack = list(state.stack)
                    call_stack[-1] = Frame(key, frame.index + 1)
                    call_stack.append(Frame(target_key, 0))
                    work.append(State(call_stack, constraints, trace + [f"jump:{rule.verdict.target}"], start))
                else:
                    # goto keert niet terug naar caller.
                    goto_stack = list(state.stack)
                    goto_stack[-1] = Frame(target_key, 0)
                    work.append(State(goto_stack, constraints, trace + [f"goto:{rule.verdict.target}"], start))
                continue

    return dedupe_paths(results)


def dedupe_paths(paths: Sequence[ResolvedPath]) -> List[ResolvedPath]:
    out: List[ResolvedPath] = []
    seen = set()
    for p in paths:
        sig = (
            p.verdict,
            p.base,
            tuple((m.field, m.op, m.value_text) for m in p.constraints),
            tuple(p.trace),
            p.note,
        )
        if sig in seen:
            continue
        seen.add(sig)
        out.append(p)
    return out


def resolved_port_rows(paths: Sequence[ResolvedPath]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for p in paths:
        if p.verdict != "accept":
            continue
        if not atoms_ending(p.constraints, " dport"):
            continue
        s = summarize_path_constraints(p.constraints)
        rows.append({
            "proto": s["proto"],
            "dport": s["dport"],
            "sport": s["sport"],
            "bron": s["src"],
            "doel": s["dst"],
            "iif": s["iif"],
            "oif": s["oif"],
            "state": s["state"],
            "base": f"{p.base[0]}/{p.base[1]}/{p.base[2]}",
            "pad": " → ".join(p.trace),
        })

    rows.sort(key=lambda r: (r["proto"], r["dport"], r["base"], r["pad"]))
    return rows


# ---------------------------------------------------------------------------
# Outputsecties
# ---------------------------------------------------------------------------

def render_metadata(model: RulesetModel, r: TextRenderer) -> None:
    if not model.metainfo:
        return
    r.heading("Metadata", 2)
    rows = [{"key": k, "value": v} for k, v in sorted(model.metainfo.items())]
    r.table([("key", "Key"), ("value", "Value")], rows)
    r.line()


def render_sets(model: RulesetModel, r: TextRenderer, preview: int) -> None:
    if not model.sets:
        return
    r.heading("Named sets", 2)
    rows = []
    for (family, table, name), s in sorted(model.sets.items()):
        elems = s.get("elem")
        if elems is None:
            content = "(dynamisch/leeg bij export)"
            count = "?"
        else:
            shown = [fmt_set_element(e, model=model, family=family, table=table) for e in elems[:preview]]
            more = f" (+{len(elems) - preview} meer)" if len(elems) > preview else ""
            content = ", ".join(shown) + more
            count = str(len(elems))
        flags = ",".join(s.get("flags", [])) or "-"
        rows.append({
            "naam": f"{family}/{table}/@{name}",
            "type": s.get("type", "-"),
            "flags": flags,
            "timeout": s.get("timeout", "-"),
            "size": s.get("size", "-"),
            "count": count,
            "inhoud": content,
        })
    r.table([
        ("naam", "Naam"),
        ("type", "Type"),
        ("flags", "Flags"),
        ("timeout", "Timeout"),
        ("size", "Size"),
        ("count", "Elems"),
        ("inhoud", "Preview"),
    ], rows, cap=60)
    r.line()


def render_maps(model: RulesetModel, r: TextRenderer, preview: int) -> None:
    if not model.maps:
        return
    r.heading("Named maps", 2)
    rows = []
    for (family, table, name), m in sorted(model.maps.items()):
        elems = m.get("elem")
        if elems:
            shown = [fmt_set_element(e, model=model, family=family, table=table) for e in elems[:preview]]
            more = f" (+{len(elems) - preview} meer)" if len(elems) > preview else ""
            content = ", ".join(shown) + more
            count = str(len(elems))
        else:
            content = "(geen elementen in export)"
            count = "0"
        rows.append({
            "naam": f"{family}/{table}/@{name}",
            "key_type": fmt_value(m.get("type"), model=model, family=family, table=table),
            "value_type": fmt_value(m.get("map"), model=model, family=family, table=table),
            "flags": ",".join(m.get("flags", [])) or "-",
            "count": count,
            "inhoud": content,
        })
    r.table([
        ("naam", "Naam"),
        ("key_type", "Key type"),
        ("value_type", "Value type"),
        ("flags", "Flags"),
        ("count", "Elems"),
        ("inhoud", "Preview"),
    ], rows, cap=60)
    r.line()


def render_chain_overview(model: RulesetModel, r: TextRenderer) -> None:
    r.heading("Nftables overzicht per table / chain", 1)

    for family, table in sorted(model.tables.keys()):
        r.heading(f"table {family} {table}", 2)
        chain_keys = [k for k in model.chains if k[0] == family and k[1] == table]
        if not chain_keys:
            r.line("(geen chains)")
            r.line()
            continue

        for key in sorted(chain_keys, key=lambda x: (0 if model.chains[x].get("hook") else 1, x[2])):
            c = model.chains[key]
            r.line(chain_label(c))
            rules = model.rules.get(key, [])
            if not rules:
                r.line("  (geen regels)")
                continue
            for rule in rules:
                cond, verdict = describe_rule(rule)
                handle = f" handle={rule.handle}" if rule.handle is not None else ""
                r.line(f"  {marker_for(rule.verdict)} [{rule.index}]{handle} {cond} => {verdict}")
            r.line()


def render_direct_ports(model: RulesetModel, r: TextRenderer) -> None:
    r.heading("Directe poorten-samenvatting", 1)
    rows = direct_port_rows(model, ("accept",))
    if not rows:
        r.note("Geen directe accept-regels met expliciete dport gevonden.")
        r.line()
        return
    r.table([
        ("proto", "Proto"),
        ("dport", "Dport"),
        ("sport", "Sport"),
        ("bron", "Bron"),
        ("doel", "Doel"),
        ("iif", "IIF"),
        ("oif", "OIF"),
        ("state", "State"),
        ("chain", "Chain"),
        ("handle", "Handle"),
        ("comment", "Comment"),
    ], rows)
    r.note("Dit zijn directe accept-regels met een dport-match; jump/goto-paden staan alleen in --resolve.")
    r.line()


def render_reject_drop_ports(model: RulesetModel, r: TextRenderer) -> None:
    rows = direct_port_rows(model, ("drop", "reject"))
    if not rows:
        return
    r.heading("Directe drop/reject-poortregels", 2)
    r.table([
        ("actie", "Actie"),
        ("proto", "Proto"),
        ("dport", "Dport"),
        ("bron", "Bron"),
        ("doel", "Doel"),
        ("iif", "IIF"),
        ("chain", "Chain"),
        ("handle", "Handle"),
        ("comment", "Comment"),
    ], rows)
    r.line()


def render_nat(model: RulesetModel, r: TextRenderer) -> None:
    rows = nat_rows(model)
    if not rows:
        return
    r.heading("NAT / redirect / masquerade", 2)
    r.table([
        ("actie", "Actie"),
        ("matches", "Matches"),
        ("detail", "Detail"),
        ("chain", "Chain"),
        ("handle", "Handle"),
    ], rows, cap=0, multiline=True)
    r.line()


def render_warnings(model: RulesetModel, r: TextRenderer) -> None:
    rows = warning_rows(model)
    if not rows:
        return
    r.heading("Waarschuwingen / deels ondersteunde constructies", 2)
    r.table([
        ("type", "Type"),
        ("chain", "Chain"),
        ("handle", "Handle"),
        ("detail", "Detail"),
    ], rows, cap=70)
    r.note("xt-compat/flowtable-achtige regels worden weergegeven, maar niet volledig semantisch geïnterpreteerd.")
    r.line()


def render_resolved(model: RulesetModel, r: TextRenderer, max_states: int) -> None:
    r.heading("Opgeloste accept-paden met dport (--resolve)", 1)
    paths = resolve_paths(model, max_states=max_states)
    unresolved = [p for p in paths if p.verdict == "unresolved"]
    rows = resolved_port_rows(paths)
    if not rows:
        r.note("Geen accept-paden met expliciete dport gevonden binnen de resolvelimiet.")
    else:
        r.table([
            ("proto", "Proto"),
            ("dport", "Dport"),
            ("sport", "Sport"),
            ("bron", "Bron"),
            ("doel", "Doel"),
            ("iif", "IIF"),
            ("oif", "OIF"),
            ("state", "State"),
            ("base", "Base chain"),
            ("pad", "Pad"),
        ], rows, cap=70)
        r.note("Dit is een begrensde statische padanalyse; conflicterende matches worden niet formeel bewezen of uitgesloten.")
    if unresolved:
        r.heading("Onopgeloste paden", 2)
        r.table([
            ("base", "Base"),
            ("note", "Note"),
            ("trace", "Trace"),
        ], [{"base": f"{p.base[0]}/{p.base[1]}/{p.base[2]}", "note": p.note, "trace": " → ".join(p.trace)} for p in unresolved])
    r.line()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_renderer(fmt: str, tablefmt: Optional[str] = None) -> TextRenderer:
    if fmt == "md":
        return MarkdownRenderer(tablefmt=tablefmt)
    return TextRenderer(tablefmt=tablefmt)


def dependency_rows() -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    checks = [
        ("python3-tabulate", _tabulate is not None, "nette tabellen en Markdown/GitHub tablefmt"),
        ("python3-nftables", _Nftables is not None, "--live via libnftables; geen subprocess nodig"),
        ("python3-jsonschema", _jsonschema is not None, "lichte validatie van top-level nftables JSON"),
    ]
    for name, ok, use in checks:
        rows.append({"pakket": name, "status": "ok" if ok else "niet geladen", "gebruik": use})
    return rows


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Maak een leesbaar overzicht van een nftables ruleset uit `nft -j list ruleset`."
    )
    ap.add_argument("file", nargs="?", default=None, help="JSON-bestand. Zonder argument of '-' wordt stdin gelezen.")
    ap.add_argument("--live", action="store_true", help="Lees live via python3-nftables/libnftables in plaats van stdin/bestand.")
    ap.add_argument("--nft-command", default="list ruleset", help="Commando voor --live, default: 'list ruleset'.")
    ap.add_argument("--no-live-handles", action="store_true", help="Vraag libnftables niet expliciet om handles bij --live.")
    ap.add_argument("--no-validate", action="store_true", help="Sla lichte JSON-validatie met python3-jsonschema over.")
    ap.add_argument("--deps", action="store_true", help="Toon welke optionele Python-pakketten geladen zijn en stop.")
    ap.add_argument("--format", choices=("text", "md"), default="text", help="Uitvoerformaat.")
    ap.add_argument("--tablefmt", default=None, help="tabulate tablefmt, bv. simple, grid, rounded_grid, github, pipe, tsv.")
    ap.add_argument("--ports-only", action="store_true", help="Toon alleen poorten/NAT-samenvattingen.")
    ap.add_argument("--no-sets", action="store_true", help="Sla named-set overzicht over.")
    ap.add_argument("--no-maps", action="store_true", help="Sla named-map overzicht over.")
    ap.add_argument("--no-nat", action="store_true", help="Sla NAT-samenvatting over.")
    ap.add_argument("--resolve", action="store_true", help="Doe begrensde jump/goto/return padanalyse voor accept-poorten.")
    ap.add_argument("--max-states", type=int, default=50000, help="Maximaal aantal states per base-chain bij --resolve.")
    ap.add_argument("--set-preview", type=int, default=8, help="Aantal set/map-elementen dat in previews wordt getoond.")
    args = ap.parse_args(argv)

    r = build_renderer(args.format, args.tablefmt)
    if args.deps:
        r.heading("Dependency status", 1)
        r.table([("pakket", "Pakket"), ("status", "Status"), ("gebruik", "Gebruik")], dependency_rows(), cap=80)
        return 0

    try:
        if args.live:
            items = load_ruleset_via_libnftables(
                args.nft_command,
                handles=not args.no_live_handles,
                validate=not args.no_validate,
            )
        else:
            items = load_ruleset(args.file, validate=not args.no_validate)
        model = build_model(items)
    except FileNotFoundError:
        print(f"Bestand niet gevonden: {args.file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Kon JSON niet parsen: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Fout bij verwerken ruleset: {e}", file=sys.stderr)
        return 1

    if not args.ports_only:
        render_metadata(model, r)
        if not args.no_sets:
            render_sets(model, r, args.set_preview)
        if not args.no_maps:
            render_maps(model, r, args.set_preview)
        render_chain_overview(model, r)

    render_direct_ports(model, r)
    render_reject_drop_ports(model, r)
    if not args.no_nat:
        render_nat(model, r)
    render_warnings(model, r)

    if args.resolve:
        render_resolved(model, r, args.max_states)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
