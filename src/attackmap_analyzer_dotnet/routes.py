"""ASP.NET Core route and per-route auth extraction (#2).

Covers attribute routing on controllers, minimal APIs (including nested
`MapGroup` prefixes), `MapHub`, `MapControllerRoute` and Razor Pages
`@page`, with ASP.NET template semantics:

- a member template starting with `/` or `~/` is absolute and replaces the
  controller prefix;
- `[controller]`, `[action]` and `[area]` are replaced case-insensitively
  (`[action]` drops an `Async` suffix, as ASP.NET Core does by default);
- every path starts with `/`.

Each route also gets its *effective* auth state:

- attribute routes: `[AllowAnonymous]` on the action or controller wins over
  any `[Authorize]` (ASP.NET ignores `[Authorize]` once `[AllowAnonymous]` is
  present); otherwise `[Authorize]` on either makes it `required`;
- minimal APIs: `.AllowAnonymous()` / `.RequireAuthorization()` (and lambda
  `[AllowAnonymous]` / `[Authorize]`) on the endpoint or any enclosing group,
  with the same anonymous-wins rule;
- anything else is `unknown`; the analyzer upgrades unknown routes to
  `required` when the repo sets an authorization fallback policy, or calls
  `MapControllers().RequireAuthorization()` / `MapRazorPages().RequireAuthorization()`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .csharp import (
    AttributeBlock,
    attribute_blocks,
    class_scopes,
    innermost_scope,
    mask_comments,
    member_name,
    parse_chains,
    string_literal,
    string_literals,
)

REQUIRED = "required"
ANONYMOUS = "anonymous"
UNKNOWN = "unknown"

HTTP_VERB_ATTRIBUTES = {
    "HttpGet": "GET",
    "HttpPost": "POST",
    "HttpPut": "PUT",
    "HttpDelete": "DELETE",
    "HttpPatch": "PATCH",
    "HttpHead": "HEAD",
    "HttpOptions": "OPTIONS",
}
MINIMAL_VERBS = {
    "MapGet": "GET",
    "MapPost": "POST",
    "MapPut": "PUT",
    "MapDelete": "DELETE",
    "MapPatch": "PATCH",
}
DEFAULT_CONVENTIONAL_ROUTE = "{controller=Home}/{action=Index}/{id?}"
_CHAIN_START = re.compile(
    r"Map(?:Get|Post|Put|Delete|Patch|Methods|Group|Hub|GrpcService|Controllers|RazorPages"
    r"|ControllerRoute|DefaultControllerRoute|AreaControllerRoute)"
    r"|RequireAuthorization|AllowAnonymous"
)
_TOKEN_RE = re.compile(r"\[(controller|action|area)\]", re.IGNORECASE)


@dataclass
class RouteSpec:
    path: str
    method: str
    offset: int
    kind: str  # "attribute", "minimal", "conventional", "hub", "razor"
    auth: str = UNKNOWN
    auth_evidence: str | None = None


@dataclass
class FileRoutes:
    routes: list[RouteSpec] = field(default_factory=list)
    # Repo-wide defaults this file declares.
    controllers_require_auth: bool = False
    razor_pages_require_auth: bool = False
    fallback_policy_requires_auth: bool = False
    # Offsets of `[Authorize]` attributes that guard no extracted route.
    unattached_authorize: list[int] = field(default_factory=list)
    # (hint, offset) protocol hints: SignalR hubs, gRPC services.
    protocol_hints: list[tuple[str, int]] = field(default_factory=list)


# ---------- Template semantics ----------


def normalize(path: str) -> str:
    path = path.strip()
    if path.startswith("~/"):
        path = path[1:]
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return path


def combine(prefix: str, template: str) -> str:
    """ASP.NET attribute-route combination of a controller and action template."""
    t = template.strip()
    if t.startswith("/") or t.startswith("~/"):
        return normalize(t)
    p = prefix.strip().strip("/")
    t = t.strip("/")
    if p and t:
        return normalize(p + "/" + t)
    return normalize(p or t)


def replace_tokens(template: str, controller: str | None, action: str | None, area: str | None) -> str:
    def sub(m: re.Match[str]) -> str:
        token = m.group(1).lower()
        if token == "controller" and controller:
            return controller[: -len("Controller")] if controller.endswith("Controller") and controller != "Controller" else controller
        if token == "action" and action:
            return action[: -len("Async")] if action.endswith("Async") and action != "Async" else action
        if token == "area" and area:
            return area
        return m.group(0)

    return _TOKEN_RE.sub(sub, template)


def _effective(flags: set[str]) -> str:
    if ANONYMOUS in flags:
        return ANONYMOUS
    if REQUIRED in flags:
        return REQUIRED
    return UNKNOWN


# ---------- Attribute routing ----------


def _route_templates(block: AttributeBlock) -> list[str] | None:
    """`[Route]` templates on a block; None if one isn't a readable literal."""
    templates: list[str] = []
    for attribute in block.get("Route"):
        value = attribute.args.first_string("template", "Template")
        if value is None:
            return None
        templates.append(value)
    return templates


def _auth_flags(block: AttributeBlock | None) -> set[str]:
    flags: set[str] = set()
    if block is None:
        return flags
    if block.has("AllowAnonymous"):
        flags.add(ANONYMOUS)
    if block.has("Authorize"):
        flags.add(REQUIRED)
    return flags


def _auth_evidence(member: AttributeBlock, klass: AttributeBlock | None, class_name: str | None, state: str) -> str | None:
    owner = f"controller {class_name}" if class_name else "controller"
    if state == ANONYMOUS:
        return "[AllowAnonymous] on action" if member.has("AllowAnonymous") else f"[AllowAnonymous] on {owner}"
    if state == REQUIRED:
        return "[Authorize] on action" if member.has("Authorize") else f"[Authorize] on {owner}"
    return None


def _attribute_routes(masked: str, out: FileRoutes) -> None:
    blocks = attribute_blocks(masked)
    if not blocks:
        return
    scopes = class_scopes(masked)
    class_blocks: dict[int, AttributeBlock] = {
        b.class_keyword_at: b for b in blocks if b.class_keyword_at is not None
    }
    used_authorize: set[int] = set()

    for block in blocks:
        if block.class_keyword_at is not None:
            continue
        verbs = [(HTTP_VERB_ATTRIBUTES[a.name], a) for a in block.attributes if a.name in HTTP_VERB_ATTRIBUTES]
        accept = block.get("AcceptVerbs")
        member_templates = _route_templates(block)
        if not verbs and not accept and not member_templates:
            continue
        if member_templates is None:
            continue

        scope = innermost_scope(scopes, block.start)
        klass = class_blocks.get(scope.keyword_at) if scope is not None else None
        class_name = scope.name if scope is not None else None
        class_templates = _route_templates(klass) if klass is not None else []
        if class_templates is None:
            continue  # controller template is a constant: unknown prefix
        prefixes = class_templates or [""]
        area = None
        for source in (block, klass):
            if source is not None and source.get("Area"):
                area = source.get("Area")[0].args.first_string("areaName") or area
                break
        action = member_name(masked, block.end)

        # (method, template, anchor offset)
        pairs: list[tuple[str, str, int]] = []
        for method, attribute in verbs:
            if attribute.args.has_template("template"):
                template = attribute.args.first_string("template")
                if template is None:
                    continue  # template is a constant: unknown path
                pairs.append((method, template, attribute.start))
            elif member_templates:
                pairs.extend((method, t, attribute.start) for t in member_templates)
            else:
                pairs.append((method, "", attribute.start))
        for attribute in accept:
            accept_verbs = [string_literal(p) for p in attribute.args.positional]
            route = attribute.args.named.get("Route")
            templates = [string_literal(route)] if route is not None else (member_templates or [""])
            for verb in (v for v in accept_verbs if v):
                pairs.extend((verb.upper(), t, attribute.start) for t in templates if t is not None)
        if member_templates and all(a.args.has_template("template") for _, a in verbs) and not accept:
            # [Route] on the action with no template-less verb: any method.
            anchor = block.get("Route")[0].start
            pairs.extend(("ANY", t, anchor) for t in member_templates)

        flags = _auth_flags(block) | _auth_flags(klass)
        state = _effective(flags)
        evidence = _auth_evidence(block, klass, class_name, state)
        if pairs and state == REQUIRED:
            for source in (block, klass):
                if source is not None:
                    used_authorize.update(a.start for a in source.get("Authorize"))
        for method, template, anchor in pairs:
            for prefix in prefixes:
                prefix_t = replace_tokens(prefix, class_name, action, area)
                template_t = replace_tokens(template, class_name, action, area)
                out.routes.append(
                    RouteSpec(combine(prefix_t, template_t), method, anchor, "attribute", state, evidence)
                )

    for block in blocks:
        for attribute in block.get("Authorize"):
            if attribute.start not in used_authorize:
                out.unattached_authorize.append(attribute.start)


# ---------- Minimal APIs ----------


@dataclass
class _Group:
    prefix: str | None  # None when the prefix isn't a literal
    parent: _Group | None
    flags: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)

    def full_prefix(self) -> str | None:
        parts: list[str] = []
        node: _Group | None = self
        while node is not None:
            if node.prefix is None:
                return None
            parts.append(node.prefix)
            node = node.parent
        path = ""
        for part in reversed(parts):
            path = _join(path, part)
        return path

    def all_flags(self) -> tuple[set[str], list[str]]:
        flags: set[str] = set()
        evidence: list[str] = []
        node: _Group | None = self
        while node is not None:
            flags |= node.flags
            evidence.extend(node.evidence)
            node = node.parent
        return flags, evidence


@dataclass
class _Endpoint:
    group: _Group
    specs: list[RouteSpec]
    flags: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    target: str | None = None  # "controllers" / "razor" for convention builders


def _join(a: str, b: str) -> str:
    a = a.strip().rstrip("/")
    b = b.strip()
    if not b or b == "/":
        return a or "/"
    return a + "/" + b.lstrip("/")


def _lambda_flags(raw_args: str) -> set[str]:
    flags: set[str] = set()
    head = raw_args.split("=>", 1)[0]
    if re.search(r"\[\s*(?:[\w.]+\.)?AllowAnonymous(?:Attribute)?\b", head):
        flags.add(ANONYMOUS)
    if re.search(r"\[\s*(?:[\w.]+\.)?Authorize(?:Attribute)?\b", head):
        flags.add(REQUIRED)
    return flags


def _minimal_routes(masked: str, out: FileRoutes) -> None:
    chains = parse_chains(masked, _CHAIN_START)
    groups: dict[str, _Group] = {}
    endpoint_vars: dict[str, _Endpoint] = {}
    endpoints: list[_Endpoint] = []

    for chain in chains:
        current_group: _Group | None = groups.get(chain.base)
        current_endpoint: _Endpoint | None = endpoint_vars.get(chain.base)
        if current_group is None and current_endpoint is None:
            current_group = _Group(prefix="", parent=None)
        for call in chain.calls:
            name = call.name
            if name == "MapGroup":
                if current_group is None:
                    break
                prefix = call.args.first_string("prefix")
                current_group = _Group(prefix=prefix, parent=current_group)
                current_endpoint = None
            elif name in MINIMAL_VERBS or name == "MapMethods" or name == "MapHub":
                if current_group is None:
                    break
                path = call.args.first_string("pattern")
                if name == "MapMethods":
                    methods_arg = call.args.named.get("httpMethods") or (
                        call.args.positional[1] if len(call.args.positional) > 1 else ""
                    )
                    methods = [m.upper() for m in string_literals(methods_arg)]
                elif name == "MapHub":
                    methods = ["ANY"]
                    if call.generic:
                        out.protocol_hints.append((f"signalr_hub:{call.generic}", call.name_at))
                else:
                    methods = [MINIMAL_VERBS[name]]
                kind = "hub" if name == "MapHub" else "minimal"
                specs = [] if path is None else [RouteSpec(path, m, call.name_at, kind) for m in methods]
                current_endpoint = _Endpoint(current_group, specs)
                current_endpoint.flags |= _lambda_flags(call.raw_args)
                if current_endpoint.flags:
                    current_endpoint.evidence.append("attribute on the route handler")
                endpoints.append(current_endpoint)
            elif name == "MapGrpcService":
                if call.generic:
                    out.protocol_hints.append((f"grpc_service:{call.generic}", call.name_at))
                current_endpoint = _Endpoint(current_group or _Group("", None), [])
            elif name in ("MapControllers", "MapRazorPages"):
                current_endpoint = _Endpoint(
                    current_group or _Group("", None), [],
                    target="controllers" if name == "MapControllers" else "razor",
                )
                endpoints.append(current_endpoint)
            elif name in ("MapControllerRoute", "MapAreaControllerRoute", "MapDefaultControllerRoute"):
                if name == "MapDefaultControllerRoute":
                    pattern = DEFAULT_CONVENTIONAL_ROUTE
                else:
                    pattern = call.args.named.get("pattern")
                    pattern = string_literal(pattern) if pattern is not None else None
                    if pattern is None:
                        literal_args = [string_literal(p) for p in call.args.positional]
                        literal_args = [p for p in literal_args if p is not None]
                        # (name, pattern) or (name, areaName, pattern)
                        pattern = literal_args[-1] if len(literal_args) >= 2 else None
                specs = [] if pattern is None else [RouteSpec(pattern, "ANY", call.name_at, "conventional")]
                current_endpoint = _Endpoint(current_group or _Group("", None), specs, target="controllers")
                endpoints.append(current_endpoint)
            elif name in ("RequireAuthorization", "AllowAnonymous"):
                flag = REQUIRED if name == "RequireAuthorization" else ANONYMOUS
                note = f".{name}()"
                if current_endpoint is not None:
                    current_endpoint.flags.add(flag)
                    current_endpoint.evidence.append(f"{note} on the endpoint")
                elif current_group is not None:
                    current_group.flags.add(flag)
                    current_group.evidence.append(f"{note} on group {current_group.full_prefix() or '?'}")
            # Any other call (WithName, WithTags, Produces, ...) keeps the builder.
        if chain.assigned_to:
            if current_endpoint is not None:
                endpoint_vars[chain.assigned_to] = current_endpoint
                groups.pop(chain.assigned_to, None)
            elif current_group is not None and current_group.parent is not None:
                groups[chain.assigned_to] = current_group
                endpoint_vars.pop(chain.assigned_to, None)

    # Resolve after the whole file: group conventions apply to every endpoint
    # in the group no matter where in the file they are added.
    for endpoint in endpoints:
        group_flags, group_evidence = endpoint.group.all_flags()
        flags = endpoint.flags | group_flags
        state = _effective(flags)
        if endpoint.target == "controllers" and REQUIRED in endpoint.flags and endpoint.specs == []:
            out.controllers_require_auth = True
        if endpoint.target == "razor" and REQUIRED in endpoint.flags:
            out.razor_pages_require_auth = True
        prefix = endpoint.group.full_prefix()
        if prefix is None:
            continue  # a group prefix we can't read: path unknown
        evidence = "; ".join(endpoint.evidence + group_evidence) or None
        for spec in endpoint.specs:
            if spec.kind == "conventional":
                spec.path = normalize(spec.path)
            else:
                spec.path = normalize(_join(prefix, spec.path))
            spec.auth = state
            spec.auth_evidence = evidence if state != UNKNOWN else None
            out.routes.append(spec)
        if endpoint.target == "controllers" and endpoint.specs and REQUIRED in endpoint.flags:
            out.controllers_require_auth = True


_FALLBACK_POLICY_RE = re.compile(
    r"(?:FallbackPolicy\s*=|SetFallbackPolicy\s*\()(?P<rest>[^;]*)", re.DOTALL
)


def _fallback_requires_auth(masked: str) -> bool:
    for m in _FALLBACK_POLICY_RE.finditer(masked):
        rest = m.group("rest")
        if re.search(r"RequireAuthenticatedUser|RequireRole|RequireClaim|RequireAssertion|DefaultPolicy", rest):
            return True
    return False


# ---------- Entry points ----------


def extract_cs_routes(content: str) -> FileRoutes:
    out = FileRoutes()
    masked = mask_comments(content)
    if "[" in masked:
        _attribute_routes(masked, out)
    if "Map" in masked or "RequireAuthorization" in masked or "AllowAnonymous" in masked:
        _minimal_routes(masked, out)
    out.fallback_policy_requires_auth = _fallback_requires_auth(masked)
    return out


_PAGE_DIRECTIVE_RE = re.compile(r'^[ \t]*@page(?:[ \t]+"([^"]*)")?[ \t]*\r?$', re.MULTILINE)


def extract_razor_page(content: str, relative: str) -> RouteSpec | None:
    """The route of a Razor Page (`@page` directive in a .cshtml file)."""
    m = _PAGE_DIRECTIVE_RE.search(content)
    if m is None:
        return None
    template = m.group(1)
    parts = PurePosixPath(relative).with_suffix("").parts
    if "Pages" in parts:
        index = len(parts) - 1 - parts[::-1].index("Pages")
        base_parts = list(parts[index + 1 :])
        area = parts[index - 1] if index >= 2 and parts[index - 2] == "Areas" else None
    else:
        base_parts = list(parts[-1:])
        area = None
    if base_parts and base_parts[-1] == "Index":
        base_parts = base_parts[:-1]
    base = "/" + "/".join(base_parts)
    if area:
        base = _join("/" + area, base)
    if template:
        path = normalize(template) if template.startswith("/") or template.startswith("~/") else normalize(_join(base, template))
    else:
        path = normalize(base)
    return RouteSpec(path, "ANY", m.start(), "razor")


__all__ = [
    "ANONYMOUS",
    "REQUIRED",
    "UNKNOWN",
    "FileRoutes",
    "RouteSpec",
    "combine",
    "extract_cs_routes",
    "extract_razor_page",
    "normalize",
    "replace_tokens",
]
