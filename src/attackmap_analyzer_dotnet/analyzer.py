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

Routes (see `routes.py`): attribute routing with ASP.NET template semantics
(absolute `/` and `~/` templates, `[controller]`/`[action]`/`[area]` tokens,
class prefixes scoped to the class body), minimal APIs with nested `MapGroup`
prefixes, `MapHub`, `MapControllerRoute` and Razor Pages `@page`. Every path
starts with `/`.

Per-route auth: each route's effective state (`[Authorize]`/`[AllowAnonymous]`,
`.RequireAuthorization()`/`.AllowAnonymous()`, fallback policies) is computed.
Core has no auth field on `Route` yet (mlaify/AttackMap#256); it attributes
`auth_hints` to routes by file and line, so a route that requires auth gets an
`aspnet_authorize:<METHOD> <path>` auth hint on its own line, and an
explicitly anonymous route gets an `aspnet_allow_anonymous:<METHOD> <path>`
entrypoint hint and no auth hint.
"""

from __future__ import annotations

import re
from pathlib import Path

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, read_source, rel

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    ProtocolHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)
from .routes import ANONYMOUS, REQUIRED, UNKNOWN, RouteSpec, extract_cs_routes, extract_razor_page

CODE_SUFFIXES = {".cs"}
RAZOR_SUFFIXES = {".cshtml"}
# appsettings.json, appsettings.Development.json, appsettings.Production.json, ...
CONFIG_FILE_RE = re.compile(r"^appsettings(?:\.[\w-]+)?\.json$", re.IGNORECASE)
PROJECT_FILES = {".csproj", ".fsproj", ".sln"}
# .NET-specific directories on top of the SDK defaults. Matched against
# directory names inside the repo only (mlaify/AttackMap#253).
SKIP_DIRS = DEFAULT_SKIP_DIRS | {"bin", "obj", ".vs", ".idea", "packages", "TestResults", "publish"}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

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
]
# GetConnectionString("Default") names a connection string; it isn't a secret
# (#2). Literal passwords in appsettings*.json ConnectionStrings are reported
# instead, see _extract_config_secrets.
_CONNECTION_STRINGS_RE = re.compile(r'"ConnectionStrings"\s*:\s*\{')
_CONNECTION_ENTRY_RE = re.compile(r'"([^"\\]+)"\s*:\s*"((?:[^"\\]|\\.)*)"')
_CONNECTION_PASSWORD_RE = re.compile(r"(?:^|;)\s*(?:password|pwd)\s*=\s*([^;]*)", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"^(?:\$?\{.*\}|<.*>|%.*%|#\{.*\}#?|__\w+__|\*+)$")


# Kept rather than attackmap.sdk.line_snippet: this takes a match offset and
# splits on "\n" only, so it stays consistent with line_of() on files that
# contain form feeds or other str.splitlines() separators, and it costs
# O(line) per match instead of O(file).
def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _connection_password(value: str) -> bool:
    """True when a connection string carries a literal, non-placeholder password."""
    m = _CONNECTION_PASSWORD_RE.search(value)
    if m is None:
        return False
    password = m.group(1).strip().strip("'\"")
    return bool(password) and _PLACEHOLDER_RE.match(password) is None


def _extract_csproj_meta(csproj_path: Path, root: Path | None = None) -> tuple[str | None, str | None]:
    """Return (root_namespace, assembly_name) from a .csproj file."""
    text = read_source(csproj_path, root=root)
    if text is None:
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
        markers = CODE_SUFFIXES | PROJECT_FILES
        return next(iter_repo_files(root, suffixes=markers, skip_dirs=SKIP_DIRS), None) is not None

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        # Service-name hints from .csproj files
        for csproj in iter_repo_files(root, suffixes={".csproj"}, skip_dirs=SKIP_DIRS):
            root_ns, assembly = _extract_csproj_meta(csproj, root)
            relative = rel(csproj, root)
            if root_ns:
                self._append_unique_service(result, f"namespace:{root_ns}", relative)
            if assembly:
                self._append_unique_service(result, f"assembly:{assembly}", relative)

        pending: list[tuple[RouteSpec, str, str]] = []  # (route, file, content)
        defaults = {"controllers": False, "razor": False, "fallback": False}

        for file_path in iter_repo_files(
            root, suffixes=CODE_SUFFIXES | RAZOR_SUFFIXES | {".json"}, skip_dirs=SKIP_DIRS
        ):
            suffix = file_path.suffix.lower()
            if suffix == ".json" and not CONFIG_FILE_RE.match(file_path.name):
                continue
            content = read_source(file_path, root=root)
            if content is None:
                continue

            result.files_scanned += 1
            relative = rel(file_path, root)
            if suffix == ".json":
                self._extract_config_secrets(content, relative, result)
                continue
            if "csharp" not in result.languages:
                result.languages.append("csharp")
            if suffix in RAZOR_SUFFIXES:
                spec = extract_razor_page(content, relative)
                if spec is not None:
                    pending.append((spec, relative, content))
                continue

            self._extract_routes(content, relative, result, pending, defaults)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)
            self._infer_service_role(content, relative, result)

        self._emit_routes(pending, defaults, result)
        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(
        self,
        content: str,
        relative: str,
        result: ScanResult,
        pending: list[tuple[RouteSpec, str, str]],
        defaults: dict[str, bool],
    ) -> None:
        found = extract_cs_routes(content)
        pending.extend((spec, relative, content) for spec in found.routes)
        defaults["controllers"] |= found.controllers_require_auth
        defaults["razor"] |= found.razor_pages_require_auth
        defaults["fallback"] |= found.fallback_policy_requires_auth
        # An [Authorize] that guards no extracted route (a class without
        # actions, a Razor PageModel, a hub) stays a file-level hint.
        for offset in found.unattached_authorize:
            self._append_unique_auth(
                result, "authorize_attribute", relative,
                line_of(content, offset), _line_snippet(content, offset), 0.85,
            )
        for hint, offset in found.protocol_hints:
            self._append_unique_protocol(
                result, hint, relative, line_of(content, offset), _line_snippet(content, offset),
            )

    def _emit_routes(
        self,
        pending: list[tuple[RouteSpec, str, str]],
        defaults: dict[str, bool],
        result: ScanResult,
    ) -> None:
        """Append routes plus their per-route auth signals.

        Runs after every file is read, because a fallback policy or
        `MapControllers().RequireAuthorization()` in Program.cs changes the
        default for routes declared in other files.
        """
        for spec, relative, content in pending:
            if spec.auth == UNKNOWN:
                if defaults["fallback"]:
                    spec.auth, spec.auth_evidence = REQUIRED, "authorization fallback policy"
                elif defaults["controllers"] and spec.kind in ("attribute", "conventional"):
                    spec.auth, spec.auth_evidence = REQUIRED, "MapControllers().RequireAuthorization()"
                elif defaults["razor"] and spec.kind == "razor":
                    spec.auth, spec.auth_evidence = REQUIRED, "MapRazorPages().RequireAuthorization()"
            line = line_of(content, spec.offset)
            # Route.auth / guards / guard_evidence (AttackMap#256): core trusts
            # this over its own resolution. An older core ignores the fields;
            # the hints below stay for one release for those cores.
            guards = [spec.auth_evidence or "[Authorize]"] if spec.auth == REQUIRED else []
            if not self._append_unique_route(
                result, spec.path, spec.method, relative, line,
                auth=spec.auth, guards=guards, guard_evidence=spec.auth_evidence,
            ):
                continue
            label = f"{spec.method} {spec.path}"
            evidence = f"{label}: {spec.auth_evidence}" if spec.auth_evidence else _line_snippet(content, spec.offset)
            if spec.auth == REQUIRED:
                self._append_unique_auth(result, f"aspnet_authorize:{label}", relative, line, evidence, 0.9)
            elif spec.auth == ANONYMOUS:
                self._append_unique_entrypoint(result, f"aspnet_allow_anonymous:{label}", relative, line, evidence)

    def _extract_config_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        """Literal passwords in an appsettings*.json `ConnectionStrings` section."""
        section = _CONNECTION_STRINGS_RE.search(content)
        if section is None:
            return
        end = content.find("}", section.end())
        body_end = len(content) if end == -1 else end
        for entry in _CONNECTION_ENTRY_RE.finditer(content, section.end(), body_end):
            if not _connection_password(entry.group(2)):
                continue
            # The evidence names the connection string, never the value.
            self._append_unique_secret(
                result, "connection_string_password", relative,
                line_of(content, entry.start()),
                f"ConnectionStrings:{entry.group(1)} contains a literal Password=",
                kind="config_literal",
            )

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                line_of(content, match.start()),
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
                    line_of(content, match.start()),
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
                    line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                line_of(content, match.start()),
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
    def _append_unique_route(
        result: ScanResult,
        path: str,
        method: str,
        file: str,
        line: int | None,
        *,
        auth: str = UNKNOWN,
        guards: list[str] | None = None,
        guard_evidence: str | None = None,
    ) -> bool:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return False
        result.routes.append(
            Route(
                path=path, method=method, file=file, line=line,
                auth=auth, guards=list(guards or []), guard_evidence=guard_evidence,
            )
        )
        return True

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
    def _append_unique_secret(
        result: ScanResult, name: str, file: str, line: int | None, evidence: str | None, kind: str = "env_reference"
    ) -> None:
        # Env references dedup per file; config literals per line, so two
        # connection strings with passwords in one file both show up.
        if kind == "env_reference":
            duplicate = any((item.name, item.file) == (name, file) for item in result.secret_hints)
        else:
            duplicate = any((item.name, item.file, item.line) == (name, file, line) for item in result.secret_hints)
        if duplicate:
            return
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85, kind=kind)
        )

    @staticmethod
    def _append_unique_protocol(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.protocol_hints):
            return
        result.protocol_hints.append(ProtocolHint(hint=hint, file=file, line=line, evidence_text=evidence))

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
