#!/usr/bin/env python3
"""Regenerate the Backend API resource modules from the public OpenAPI document.

    python3 scripts/generate.py [spec.json | --live]

Writes lib/atlas/resources/*.ex, lib/atlas/resource_index.ex and the checked-in
operation list test/fixtures/operations.txt (every BAPI and PLATFORM operation).
scripts/name_pins.json keeps every published function name stable: an operation
already in it keeps its name, a new one is named and appended. CI regenerates from
scripts/openapi.snapshot.json and fails on any diff.
"""
import json, os, re, sys, urllib.request, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# Default: the checked-in snapshot (the live host answers automated clients with 403).
# Pass a file, or --live, to use another spec.
args = [x for x in sys.argv[1:] if not x.startswith("--")]
src = args[0] if args else ("https://api.atlasauth.net/v1/openapi.json" if "--live" in sys.argv else os.path.join(HERE, "openapi.snapshot.json"))
if src.startswith("http"):
    req = urllib.request.Request(src, headers={"user-agent": "atlasauth-elixir-gen"})
    spec = json.load(urllib.request.urlopen(req, timeout=120))
else:
    spec = json.load(open(src))
PINS_FILE = os.path.join(HERE, "name_pins.json")
PINS = json.load(open(PINS_FILE))
METHODS = ("get", "post", "put", "patch", "delete")
VERB = {"get": "get", "post": "post", "put": "put", "patch": "update", "delete": "delete"}
# Resources whose functions carry `@doc deprecated:` (shown in docs; no compile warning).
DEPRECATED = {"sign_in_tokens": "Use Atlas.Sessions.create/3 with mode browser_ticket"}


def snake(s):
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()
    return re.sub(r"[^a-z0-9_]+", "_", s).strip("_") or "x"


def camel(s):
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"[_\-]+", s) if p)


SHARED = {"DryRun": "dry_run", "AtlasStrict": "atlas_strict", "SecretRecipient": "secret_recipient", "MetadataFilter": "metadata[key]"}


def resolve(p):
    if "$ref" in p:
        # The snapshot keeps schemas only; these four shared query params are documented once, in `Atlas.Client`.
        return {"name": SHARED.get(p["$ref"].split("/")[-1]), "in": "query", "shared": True}
    return p


def deref(sc):
    seen = 0
    while isinstance(sc, dict) and "$ref" in sc and seen < 20:
        sc = spec["components"]["schemas"][sc["$ref"].split("/")[-1]]
        seen += 1
    return sc if isinstance(sc, dict) else {}


def tname(sc):
    sc = deref(sc)
    t = sc.get("type")
    if isinstance(t, list):
        t = "|".join(str(x) for x in t)
    if sc.get("enum"):
        return "enum"
    return t or ("object" if sc.get("properties") else "any")


def walk(sc, prefix, out, seen, depth=0):
    """Dotted names of every property reachable from a schema (depth-limited, cycle-safe)."""
    if depth > 4 or not isinstance(sc, dict):
        return
    if "$ref" in sc:
        if sc["$ref"] in seen:
            return
        seen = seen | {sc["$ref"]}
        sc = deref(sc)
    for k in ("allOf", "oneOf", "anyOf"):
        for x in sc.get(k) or []:
            walk(x, prefix, out, seen, depth + 1)
    if sc.get("items"):
        walk(sc["items"], prefix, out, seen, depth + 1)
    for k, v in (sc.get("properties") or {}).items():
        out.append(prefix + k)
        walk(v, prefix + k + ".", out, seen, depth + 1)


def field_docs(o):
    lines = []
    op = o["op"]
    q = [resolve(p) for p in op.get("parameters", [])]
    q = [p for p in q if p.get("in") == "query" and not p.get("shared")]
    if q:
        lines.append("  Query params (`params:`): " + ", ".join(f"`{p['name']}`" for p in q) + ".")
    rb = ((op.get("requestBody") or {}).get("content") or {}).get("application/json", {}).get("schema")
    if rb:
        top = deref(rb)
        req = set(top.get("required") or [])
        props = top.get("properties") or {}
        out = []
        walk(rb, "", out, frozenset())
        nested = [n for n in dict.fromkeys(out) if "." in n]
        if props:
            lines.append("  Body fields: " + ", ".join(f"`{k}` ({tname(v)}{', required' if k in req else ''})" for k, v in props.items()) + ".")
        if nested:
            lines.append("  Nested body fields: " + ", ".join(f"`{n}`" for n in nested) + ".")
    for code in ("200", "201", "202"):
        rs = (((op.get("responses") or {}).get(code) or {}).get("content") or {}).get("application/json", {}).get("schema")
        if rs:
            out = []
            walk(rs, "", out, frozenset())
            if out:
                lines.append("  Response fields: " + ", ".join(f"`{n}`" for n in dict.fromkeys(out)) + ".")
            break
    return lines


def doc(s):
    s = re.sub(r"\s+", " ", s or "").replace('"""', "'''").strip()
    return s


ops = []
for path, item in spec["paths"].items():
    for m in METHODS:
        o = item.get(m)
        if not o or o.get("tags") not in (["BAPI"], ["PLATFORM"]):
            continue
        segs = path.split("/")  # '', v1, resource, ...
        res = segs[2]
        rest = segs[3:]
        if res == "platform" and len(segs) > 3:  # /v1/platform/apps -> Atlas.PlatformApps
            res = "platform_" + segs[3]
            rest = segs[4:]
        params = [x[1:-1] for x in segs if x.startswith("{")]
        rb = o.get("requestBody")
        body = None
        if rb:
            cts = list((rb.get("content") or {}).keys())
            body = "json"
            if cts and not any("json" in c for c in cts):
                body = cts[0]
            body_required = bool(rb.get("required"))
        else:
            body_required = False
        qnames = {resolve(p).get("name") for p in o.get("parameters", [])}
        paginated = m == "get" and "starting_after" in qnames
        ops.append(dict(method=m, path=path, res=res, rest=rest, params=params, body=body,
                        body_required=body_required, paginated=paginated,
                        summary=doc(o.get("summary") or o.get("description")),
                        scope=o.get("x-required-scope"), op=o))


def names_for(res_ops):
    def short(o):
        r = o["rest"]
        toks = [snake(x) for x in r if not x.startswith("{")]
        if not toks:
            return {"get": "list", "post": "create"}.get(o["method"], VERB[o["method"]])
        base = VERB[o["method"]]
        if o["method"] == "get" and r and r[-1].startswith("{") and len(toks) == 0:
            base = "get"
        return base + "_" + "_".join(toks) if r[0].startswith("{") is False or len(r) > 1 else base

    def with_params(o):
        parts = []
        for x in o["rest"]:
            parts.append("by_" + snake(x[1:-1]) if x.startswith("{") else snake(x))
        return VERB[o["method"]] + "_" + "_".join(parts) if parts else short(o)

    def single(o):  # /v1/res/{id}
        return {"get": "get"}.get(o["method"], VERB[o["method"]])

    used = {PINS[f"{o['method'].upper()} {o['path']}"][0] for o in res_ops if f"{o['method'].upper()} {o['path']}" in PINS}
    used |= {n + "_with_body" for n in used}
    for o in sorted(res_ops, key=lambda x: (len(x["params"]), x["path"])):
        key = f"{o['method'].upper()} {o['path']}"
        spec_shape = "n" if o["body"] is None else ("d" if o["body"] == "json" and not o["body_required"] else "r")
        if key in PINS:
            o["name"], o["shape"] = PINS[key]
            continue
        o["shape"] = spec_shape
        base = single(o) if len(o["rest"]) == 1 and o["rest"][0].startswith("{") else short(o)
        tail = o["method"] + "_" + snake("_".join(x.strip("{}") for x in o["rest"]))
        n = 2
        cands = [base, with_params(o), tail]
        name = next((c for c in cands if c not in used), None)
        while name is None:
            name = f"{tail}_{n}" if f"{tail}_{n}" not in used else None
            n += 1
        used.add(name)
        o["name"] = name
    for o in res_ops:
        PINS[f"{o['method'].upper()} {o['path']}"] = [o["name"], o["shape"]]


by_res = collections.OrderedDict()
for o in ops:
    by_res.setdefault(o["res"], []).append(o)

outdir = os.path.join(ROOT, "lib", "atlas", "resources")
os.makedirs(outdir, exist_ok=True)
for f in os.listdir(outdir):
    os.remove(os.path.join(outdir, f))

mods = []
for res, rops in by_res.items():
    names_for(rops)
    mod = "Atlas." + camel(res)
    mods.append(mod)
    out = [f"# Generated by scripts/generate.py from the Atlas OpenAPI document. Do not edit.",
           f"defmodule {mod} do",
           f'  @moduledoc """',
           f"  Backend API operations under `/v1/{res}`.",
           "",
           "  Every function takes an `Atlas.Client` first, then the path parameters, then",
           "  (for operations with a request body) the body map, then a keyword list of options:",
           "  `:params` (query string), `:headers`, `:idempotency_key`. Body maps omit a key you leave out;",
           "  put `key: nil` to send an explicit JSON null (clears the field on a PATCH). It returns",
           "  `{:ok, decoded_body}` or `{:error, %Atlas.Error{}}`.",
           '  """',
           ""]
    meta = []
    for o in rops:
        vs, used = [], {"client", "body", "opts"}
        for p in o["params"]:
            v = snake(p)
            while v in used:
                v += "_param"
            used.add(v)
            vs.append(v)
        bind = "%{" + ", ".join(f'"{p}" => {v}' for p, v in zip(o["params"], vs)) + "}"
        sc = f" Required scope: `{o['scope']}`." if o["scope"] else ""
        # shape: n = no body, d = optional body (defaults to %{}), r = required body. A published
        # signature never changes: an operation that shipped without a body and later gained one keeps
        # its bodyless function and gets `<name>_with_body`.
        variants = [(o["name"], o["shape"])]
        if o["shape"] == "n" and o["body"] is not None:
            variants.append((o["name"] + "_with_body", "r"))
        for fname, shape in variants:
            has_body = shape != "n"
            sig_args = ["client"] + vs
            call_body = "nil"
            if has_body:
                sig_args.append("body" + (" \\\\ %{}" if shape == "d" else ""))
                call_body = "body"
            sig_args.append("opts \\\\ []")
            opts_expr = "opts"
            if has_body and o["body"] not in (None, "json"):
                opts_expr = f'Keyword.put_new(opts, :content_type, "{o["body"]}")'
            out += [f'  @doc ~S"""', f"  {o['summary'] or fname}", "",
                    f"  `{o['method'].upper()} {o['path']}`.{sc}", *(([""] + field_docs(o)) if field_docs(o) else []), '  """',
                    *([f'  @doc deprecated: "{DEPRECATED[res]}"'] if res in DEPRECATED else []),
                    f"  def {fname}({', '.join(sig_args)}),",
                    f'    do: Atlas.Client.request(client, :{o["method"]}, "{o["path"]}", {bind}, {call_body}, {opts_expr})',
                    ""]
            meta.append(f'{{:{fname}, :{o["method"]}, "{o["path"]}", {len(vs)}, '
                        f'{"false" if not has_body else ("true" if o["body"] == "json" else ":binary")}, {"true" if o["paginated"] and fname == o["name"] else "false"}}}')
        if o["paginated"]:
            out += [f'  @doc ~S"""', f"  Lazy stream over every item of `{o['name']}`, following the cursor page by page.",
                    "  Raises `Atlas.Error` if a page request fails.", '  """',
                    f"  def stream_{o['name']}({', '.join(['client'] + vs + ['opts \\\\ []'])}),",
                    f'    do: Atlas.Client.stream(client, "{o["path"]}", {bind}, opts)', ""]
    out += ["  @doc false", "  def __operations__, do: [", "    " + ",\n    ".join(meta), "  ]", "end", ""]
    open(os.path.join(outdir, snake(res) + ".ex"), "w").write("\n".join(out))

open(os.path.join(ROOT, "lib", "atlas", "resource_index.ex"), "w").write(
    "# Generated by scripts/generate.py. Do not edit.\ndefmodule Atlas.ResourceIndex do\n"
    '  @moduledoc "Every generated Backend API resource module."\n\n  @modules [\n    '
    + ",\n    ".join(mods) + "\n  ]\n\n  @doc \"All resource modules.\"\n  def all, do: @modules\nend\n")
fx = os.path.join(ROOT, "test", "fixtures")
os.makedirs(fx, exist_ok=True)
lines = sorted(f"{o['method'].upper()} {o['path']}" for o in ops)
open(os.path.join(fx, "operations.txt"), "w").write("\n".join(lines) + "\n")
json.dump(dict(sorted(PINS.items())), open(PINS_FILE, "w"), indent=1)
open(PINS_FILE, "a").write("\n")
print(len(ops), "operations,", len(mods), "modules")
