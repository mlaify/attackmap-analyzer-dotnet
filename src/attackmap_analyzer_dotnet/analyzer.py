"""C# / .NET ASP.NET Core ecosystem analyzer for AttackMap.

Coverage (v0.1):
- Web frameworks: ASP.NET Core minimal APIs (`app.MapGet`, `app.MapPost`, ...),
  ASP.NET Core attribute routing (`[HttpGet]`, `[HttpPost]`, with class-level
  `[Route]` prefix joining and `[controller]` token substitution)
- Databases: Entity Framework Core (DbContext + UseSqlServer/UseNpgsql/UseSqlite/
  UseMySql), Dapper, System.Data.SqlClient / Microsoft.Data.SqlClient (SQL Server),
  Npgsql (Postgres), MySql.Data / MySqlConnector, MongoDB.Driver, StackExchange.Redis,
  AWS SDK (S3, DynamoDB)
- Auth: Microsoft.AspNetCore.Authentication.JwtBearer (AddJwtBearer), Identity
  (UserManager, SignInManager, IdentityUser, PasswordHasher), `[Authorize]` attribute,
  AddOpenIdConnect, Duende IdentityServer
- HTTP clients (external calls): HttpClient (GetAsync/PostAsync/SendAsync), RestSharp
- Secrets: Environment.GetEnvironmentVariable, IConfiguration["..."] / Configuration
  bindings with secret-shaped keys
- Entrypoints: WebApplication.CreateBuilder + .Run(), Host.CreateDefaultBuilder
- Service hints: <RootNamespace> / <AssemblyName> from .csproj

Class-level [Route("api/[controller]")] is parsed and the `[controller]` token
is substituted with the controller class name (minus the "Controller" suffix)
to produce the final route path.
"""

from __future__ import annotations

import re
from pathlib import Path

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".cs"}
CONFIG_FILES = {"appsettings.json", "appsettings.Development.json"}
PROJECT_FILES = {".csproj", ".fsproj", ".sln"}
SKIP_DIRS = {
    "bin",
    "obj",
    ".vs",
    ".idea",
    ".git",
    "node_modules",
    "packages",
    "TestResults",
    "publish",
}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# Minimal APIs: app.MapGet("/x", handler), app.MapPost(...), etc.
MINIMAL_API_PATTERN = re.compile(
    r'\b\w+\.Map(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*"([^"]+)"',
)
# app.MapMethods("/x", new[] { "GET", "POST" }, handler)
MINIMAL_API_METHODS_PATTERN = re.compile(
    r'\b\w+\.MapMethods\s*\(\s*"([^"]+)"\s*,\s*new\[\]\s*\{\s*([^}]+)\s*\}',
)

# Attribute routing on controllers
HTTP_ATTRIBUTE_PATTERN = re.compile(
    r'\[\s*Http(Get|Post|Put|Delete|Patch|Head|Options)\s*(?:\(\s*"([^"]*)"\s*\))?\s*\]',
)
# Class-level [Route("api/[controller]")] or [Route("api/users")]
# `[^\{]*?` allows other attributes ([ApiController], [Authorize], etc.) between
# the [Route] and the class declaration, but not a class body start `{`.
CLASS_ROUTE_ATTRIBUTE_PATTERN = re.compile(
    r'\[\s*Route\s*\(\s*"([^"]+)"\s*\)\s*\][^\{]*?\bclass\s+(\w+)',
    re.DOTALL,
)
# Method-level [Route("/x")] (less common, but valid)
METHOD_ROUTE_ATTRIBUTE_PATTERN = re.compile(
    r'\[\s*Route\s*\(\s*"([^"]+)"\s*\)\s*\]',
)

# External HTTP calls. The receiver-name regex is intentionally permissive (any
# identifier can be a HttpClient field, often `_httpClient`); we anchor on the
# call shape (.GetAsync/.PostAsync/...) and require an http(s) URL literal.
OUTBOUND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\.(?:Get|Post|Put|Delete|Patch|Send)(?:Async|Json|String)?(?:Async)?\s*\(\s*"(https?://[^"]+)"', re.IGNORECASE),
    re.compile(r'\bnew\s+HttpRequestMessage\s*\(\s*HttpMethod\.\w+\s*,\s*"(https?://[^"]+)"'),
    re.compile(r'\bnew\s+RestClient\s*\(\s*"(https?://[^"]+)"'),
    re.compile(r'\bnew\s+Uri\s*\(\s*"(https?://[^"]+)"'),
]

# Database libs
DB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\.UseSqlServer\s*\('), "sqlserver"),
    (re.compile(r'\.UseNpgsql\s*\(|\bNpgsql\b'), "postgresql"),
    (re.compile(r'\.UseMySql\s*\(|\bMySqlConnector\b|\bMySql\.Data\b'), "mysql"),
    (re.compile(r'\.UseSqlite\s*\(|\bMicrosoft\.Data\.Sqlite\b'), "sqlite"),
    (re.compile(r'\.UseInMemoryDatabase\s*\('), "in_memory"),
    (re.compile(r'\bDbContext\b|\bDbSet<'), "sql"),
    (re.compile(r'\busing\s+Dapper\b|\bIDbConnection\b'), "sql"),
    (re.compile(r'\bSqlConnection\s*\('), "sqlserver"),
    (re.compile(r'\bMongoClient\s*\(|\bIMongoDatabase\b|\bMongoDB\.Driver\b'), "mongodb"),
    (re.compile(r'\bConnectionMultiplexer\.Connect\s*\(|\bStackExchange\.Redis\b'), "redis"),
    (re.compile(r'\bAmazonS3Client\b|\bAWSSDK\.S3\b'), "object_storage"),
    (re.compile(r'\bAmazonDynamoDBClient\b|\bAWSSDK\.DynamoDBv2\b'), "dynamodb"),
]

# Auth-related signals
AUTH_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r'\.AddJwtBearer\s*\(|\bMicrosoft\.AspNetCore\.Authentication\.JwtBearer\b'), "jwt", 0.85),
    (re.compile(r'\.AddOpenIdConnect\s*\(|\bOpenIdConnect\b'), "oidc", 0.85),
    (re.compile(r'\.AddOAuth\s*\(|\bOAuth\b', re.IGNORECASE), "oauth", 0.85),
    (re.compile(r'\bUserManager<|\bSignInManager<|\bIdentityUser\b'), "aspnet_identity", 0.85),
    (re.compile(r'\bPasswordHasher<|\bIPasswordHasher\b'), "password_hasher", 0.85),
    (re.compile(r'\bBCrypt\.Net\b|\bBCryptPasswordHasher\b'), "bcrypt", 0.9),
    (re.compile(r'\bArgon2\b'), "argon2", 0.9),
    (re.compile(r'\[\s*Authorize\b'), "authorize_attribute", 0.85),
    (re.compile(r'\.AddAuthorization\s*\('), "authorization_setup", 0.85),
    (re.compile(r'\bDuende\.IdentityServer\b|\bIdentityServer4\b'), "identityserver", 0.85),
    (re.compile(r'\bAuthorization\b'), "authorization_header", 0.6),
    (re.compile(r'\bBearer\b'), "bearer_token", 0.6),
    (re.compile(r'\bapi[_-]?key\b', re.IGNORECASE), "api_key", 0.6),
]

FRAMEWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bMicrosoft\.AspNetCore\.Builder\b|\bWebApplication\.CreateBuilder\b'), "aspnetcore"),
    (re.compile(r'\bMicrosoft\.AspNetCore\.Mvc\b|\[ApiController\]|\[Controller\]'), "aspnetcore-mvc"),
    (re.compile(r'\bMicrosoft\.AspNetCore\.Mvc\.RazorPages\b'), "aspnetcore-razor"),
    (re.compile(r'\bMicrosoft\.EntityFrameworkCore\b'), "efcore"),
    (re.compile(r'\bMicrosoft\.AspNetCore\.SignalR\b'), "signalr"),
    (re.compile(r'\bMicrosoft\.AspNetCore\.Authentication\b'), "aspnetcore-auth"),
    (re.compile(r'\bMicrosoft\.AspNetCore\.Identity\b'), "aspnetcore-identity"),
    (re.compile(r'\bGrpc\.Net\.Client\b|\bGrpc\.AspNetCore\b'), "grpc"),
]

ENTRYPOINT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bWebApplication\.CreateBuilder\s*\(|\bWebApplicationBuilder\b'), "webapplication_builder"),
    (re.compile(r'\bapp\.Run\s*\(\s*\)'), "webapp_run"),
    (re.compile(r'\bHost\.CreateDefaultBuilder\s*\('), "generic_host"),
    (re.compile(r'\bUseStartup<'), "use_startup"),
]

# Secrets — env vars + IConfiguration accesses with secret-shaped keys
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\bEnvironment\.GetEnvironmentVariable\s*\(\s*"([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)"',
    ),
    # IConfiguration indexer access — receiver name varies (cfg, _cfg, configuration,
    # builder.Configuration, etc.); we anchor on the secret-shaped key inside the brackets.
    re.compile(
        r'\b\w+(?:\.\w+)?\s*\[\s*"([A-Za-z0-9_:.]*(?:secret|token|key|password|pass|pwd)[A-Za-z0-9_:.]*)"',
        re.IGNORECASE,
    ),
    re.compile(
        r'\bGetConnectionString\s*\(\s*"([^"]+)"',
    ),
]


def _line_of(content: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return content.count("\n", 0, offset) + 1


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _join_paths(prefix: str, suffix: str) -> str:
    p = prefix.strip()
    s = suffix.strip()
    if not p:
        return s or "/"
    if not s:
        return p or "/"
    if p == "/":
        return s if s.startswith("/") else "/" + s
    if s == "/":
        return p
    return p.rstrip("/") + "/" + s.lstrip("/")


def _substitute_controller_token(route_template: str, controller_name: str) -> str:
    """Replace [controller] in route template with controller class name minus 'Controller'."""
    name = controller_name
    if name.endswith("Controller"):
        name = name[: -len("Controller")]
    return route_template.replace("[controller]", name).replace("[Controller]", name)


def _class_routes_in_file(content: str) -> list[tuple[int, str, str]]:
    """Return [(start_offset, route_template_after_substitution, controller_class), ...]
    for every class-level [Route(...)] annotation in the file.
    """
    results: list[tuple[int, str, str]] = []
    for match in CLASS_ROUTE_ATTRIBUTE_PATTERN.finditer(content):
        template, class_name = match.group(1), match.group(2)
        substituted = _substitute_controller_token(template, class_name)
        results.append((match.start(), substituted, class_name))
    return results


def _active_class_route(prefixes: list[tuple[int, str, str]], offset: int) -> str:
    """The most recent class-level [Route] preceding the offset, post-substitution."""
    active = ""
    for start, template, _ in prefixes:
        if start < offset:
            active = template
        else:
            break
    return active


def _extract_csproj_meta(csproj_path: Path) -> tuple[str | None, str | None]:
    """Return (root_namespace, assembly_name) from a .csproj file."""
    try:
        text = csproj_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None, None
    rn = re.search(r"<RootNamespace>([^<]+)</RootNamespace>", text)
    an = re.search(r"<AssemblyName>([^<]+)</AssemblyName>", text)
    return (rn.group(1).strip() if rn else None, an.group(1).strip() if an else None)


class DotnetAnalyzer:
    metadata = AnalyzerMetadata(
        name="dotnet",
        display_name="C# / .NET Analyzer",
        version="0.1.0",
        description="ASP.NET Core analyzer covering minimal APIs, attribute routing, EF Core, Identity, and JwtBearer.",
        scope=".NET solutions and projects (.csproj, .sln). Detects ASP.NET Core minimal APIs and controllers.",
        targets=["dotnet", "csharp", "aspnetcore"],
        languages=["csharp"],
        priority=20,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        # Project / solution markers
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.suffix in {".csproj", ".sln", ".fsproj"}:
                return True
            if path.suffix in CODE_SUFFIXES:
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        # Service-name hints from .csproj files
        for csproj in root.rglob("*.csproj"):
            if any(part in SKIP_DIRS for part in csproj.parts):
                continue
            root_ns, assembly = _extract_csproj_meta(csproj)
            relative = str(csproj.relative_to(root))
            if root_ns:
                self._append_unique_service(result, f"namespace:{root_ns}", relative)
            if assembly:
                self._append_unique_service(result, f"assembly:{assembly}", relative)

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue
            if file_path.suffix not in CODE_SUFFIXES:
                continue

            result.files_scanned += 1
            if "csharp" not in result.languages:
                result.languages.append("csharp")

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes(content, relative, result)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)
            self._infer_service_role(content, relative, result)

        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        # Minimal APIs: app.MapGet("/x", handler), etc.
        for match in MINIMAL_API_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # Minimal APIs: app.MapMethods("/x", new[] { "GET", "POST" }, handler)
        for match in MINIMAL_API_METHODS_PATTERN.finditer(content):
            path = match.group(1)
            verbs_raw = match.group(2)
            verbs = re.findall(r'"([A-Za-z]+)"', verbs_raw)
            line = _line_of(content, match.start())
            for verb in verbs:
                self._append_unique_route(result, path, verb.upper(), relative, line)

        # Attribute routing: class-level [Route("api/[controller]")] + method-level [HttpGet]
        class_routes = _class_routes_in_file(content)
        for match in HTTP_ATTRIBUTE_PATTERN.finditer(content):
            method = match.group(1).upper()
            method_path = match.group(2) or ""
            prefix = _active_class_route(class_routes, match.start())
            full_path = _join_paths(prefix, method_path) if prefix else (method_path or "/")
            self._append_unique_route(result, full_path, method, relative, _line_of(content, match.start()))

        # Method-level [Route("/x")] — emit with method ANY (rare but legal)
        for match in METHOD_ROUTE_ATTRIBUTE_PATTERN.finditer(content):
            # Skip class-level routes — those are handled as prefixes above.
            if any(start == match.start() for start, _, _ in class_routes):
                continue
            method_path = match.group(1)
            prefix = _active_class_route(class_routes, match.start())
            # Skip if the [HttpX(...)] attribute regex already would have matched this
            # (i.e. the regex is part of an [HttpGet("/x")] form). We detect that by
            # checking whether this offset's match overlaps with any HTTP_ATTRIBUTE_PATTERN
            # match — but cheaper: Routes inside [Http*] aren't matched by METHOD_ROUTE_ATTRIBUTE
            # because the latter requires "[Route(" specifically.
            full_path = _join_paths(prefix, method_path) if prefix else (method_path or "/")
            self._append_unique_route(result, full_path, "ANY", relative, _line_of(content, match.start()))

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
                confidence,
            )

    def _extract_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                groups = match.groups()
                name = groups[0] if groups and groups[0] else "unknown"
                self._append_unique_secret(
                    result, name, relative,
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                target = match.group(1)
                if not (target.startswith("http://") or target.startswith("https://")):
                    continue
                self._append_unique_external(
                    result, target, relative,
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _infer_service_role(self, content: str, relative: str, result: ScanResult) -> None:
        haystack = (relative + " " + content[:500]).lower()
        role: str | None = None
        if any(token in haystack for token in ("worker", "consumer", "queue", "background", "hostedservice")):
            role = "worker"
        elif any(token in haystack for token in ("controller", "api", "endpoint", "router")):
            role = "api"
        elif any(token in haystack for token in ("client", "sdk")):
            role = "client"
        if role:
            self._append_unique_service(result, f"service_role:{role}", relative)

    # ---------- Append helpers ----------

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int | None) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None, confidence: float) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file, line=line, evidence_text=evidence, confidence=confidence))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_framework(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.framework_hints):
            return
        result.framework_hints.append(FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_entrypoint(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.entrypoint_hints):
            return
        result.entrypoint_hints.append(EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.service_hints):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


__all__ = ["DotnetAnalyzer"]
