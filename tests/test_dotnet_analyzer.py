"""Tests for the DotnetAnalyzer plugin."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from attackmap_analyzer_dotnet import DotnetAnalyzer


# ---------- detect() ----------


def test_detect_picks_up_csproj(tmp_path: Path) -> None:
    (tmp_path / "demo.csproj").write_text("<Project></Project>", encoding="utf-8")
    assert DotnetAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_solution(tmp_path: Path) -> None:
    (tmp_path / "demo.sln").write_text("Microsoft Visual Studio Solution File\n", encoding="utf-8")
    assert DotnetAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_bare_cs_file(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text("class Program {}\n", encoding="utf-8")
    assert DotnetAnalyzer().detect(tmp_path) is True


def test_detect_skips_bin_obj(tmp_path: Path) -> None:
    (tmp_path / "bin" / "Debug").mkdir(parents=True)
    (tmp_path / "bin" / "Debug" / "leftover.cs").write_text("class X {}\n", encoding="utf-8")
    assert DotnetAnalyzer().detect(tmp_path) is False


# ---------- Minimal API routes ----------


def test_minimal_api_map_methods_extracted(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(
        'using Microsoft.AspNetCore.Builder;\n'
        '\n'
        'var builder = WebApplication.CreateBuilder(args);\n'
        'var app = builder.Build();\n'
        '\n'
        'app.MapGet("/hello", () => "world");\n'
        'app.MapPost("/users", (User u) => Results.Ok());\n'
        'app.MapDelete("/users/{id:int}", (int id) => Results.NoContent());\n'
        '\n'
        'app.Run();\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/hello", "GET") in pairs
    assert ("/users", "POST") in pairs
    assert ("/users/{id:int}", "DELETE") in pairs

    hello = next(r for r in result.routes if r.path == "/hello")
    assert hello.line == 6


def test_minimal_api_map_methods_with_explicit_methods(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(
        'using Microsoft.AspNetCore.Builder;\n'
        'var app = WebApplication.CreateBuilder(args).Build();\n'
        'app.MapMethods("/admin/maintenance", new[] { "GET", "POST" }, () => Results.Ok());\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/admin/maintenance", "GET") in pairs
    assert ("/admin/maintenance", "POST") in pairs


# ---------- Attribute routing ----------


def test_attribute_routing_with_class_route_and_controller_token(tmp_path: Path) -> None:
    src = tmp_path / "Controllers" / "UsersController.cs"
    src.parent.mkdir(parents=True)
    src.write_text(
        'using Microsoft.AspNetCore.Mvc;\n'
        '\n'
        'namespace Demo.Api;\n'
        '\n'
        '[ApiController]\n'
        '[Route("api/[controller]")]\n'
        'public class UsersController : ControllerBase\n'
        '{\n'
        '    [HttpGet("{id:int}")]\n'
        '    public IActionResult Get(int id) => Ok();\n'
        '\n'
        '    [HttpPost]\n'
        '    public IActionResult Create([FromBody] User u) => Ok();\n'
        '\n'
        '    [HttpDelete("{id:int}")]\n'
        '    public IActionResult Delete(int id) => NoContent();\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/api/Users/{id:int}", "GET") in pairs
    assert ("/api/Users", "POST") in pairs
    assert ("/api/Users/{id:int}", "DELETE") in pairs


def test_attribute_routing_with_explicit_class_path(tmp_path: Path) -> None:
    src = tmp_path / "OrdersController.cs"
    src.write_text(
        'using Microsoft.AspNetCore.Mvc;\n'
        '\n'
        '[ApiController]\n'
        '[Route("api/orders/v2")]\n'
        'public class OrdersController : ControllerBase\n'
        '{\n'
        '    [HttpGet]\n'
        '    public IActionResult List() => Ok();\n'
        '\n'
        '    [HttpPost("refund")]\n'
        '    public IActionResult Refund() => Ok();\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/api/orders/v2", "GET") in pairs
    assert ("/api/orders/v2/refund", "POST") in pairs


def test_attribute_routing_handles_two_controllers_in_one_file(tmp_path: Path) -> None:
    src = tmp_path / "MultipleControllers.cs"
    src.write_text(
        'using Microsoft.AspNetCore.Mvc;\n'
        '\n'
        '[Route("api/a")]\n'
        'public class AController : ControllerBase {\n'
        '    [HttpGet("x")]\n'
        '    public IActionResult X() => Ok();\n'
        '}\n'
        '\n'
        '[Route("api/b")]\n'
        'public class BController : ControllerBase {\n'
        '    [HttpGet("y")]\n'
        '    public IActionResult Y() => Ok();\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/api/a/x", "GET") in pairs
    assert ("/api/b/y", "GET") in pairs
    assert ("/api/a/y", "GET") not in pairs
    assert ("/api/b/x", "GET") not in pairs


# ---------- Databases ----------


def test_efcore_use_npgsql_emits_postgresql(tmp_path: Path) -> None:
    (tmp_path / "DbStartup.cs").write_text(
        'using Microsoft.EntityFrameworkCore;\n'
        'public class Startup {\n'
        '    public void ConfigureServices(IServiceCollection services) {\n'
        '        services.AddDbContext<MyContext>(opt => opt.UseNpgsql("..."));\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)


def test_mongo_redis_each_emit_distinct_kinds(tmp_path: Path) -> None:
    (tmp_path / "Mongo.cs").write_text(
        'using MongoDB.Driver;\npublic class M { IMongoDatabase Db; }\n',
        encoding="utf-8",
    )
    (tmp_path / "Redis.cs").write_text(
        'using StackExchange.Redis;\n'
        'public class R { void X() { ConnectionMultiplexer.Connect("localhost"); } }\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert "mongodb" in kinds
    assert "redis" in kinds


def test_dapper_emits_sql_hint(tmp_path: Path) -> None:
    (tmp_path / "Repo.cs").write_text(
        'using Dapper;\n'
        'using System.Data;\n'
        'public class Repo { public Repo(IDbConnection conn) { } }\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert any(d.kind == "sql" for d in result.databases)


# ---------- Auth ----------


def test_jwt_bearer_setup(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(
        'using Microsoft.AspNetCore.Authentication.JwtBearer;\n'
        'var builder = WebApplication.CreateBuilder(args);\n'
        'builder.Services.AddAuthentication().AddJwtBearer(options => { });\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert any(h.hint == "jwt" for h in result.auth_hints)


def test_authorize_attribute_emits_hint(tmp_path: Path) -> None:
    (tmp_path / "Sec.cs").write_text(
        'using Microsoft.AspNetCore.Authorization;\n'
        'using Microsoft.AspNetCore.Mvc;\n'
        '\n'
        '[Authorize(Roles = "Admin")]\n'
        'public class AdminController : ControllerBase { }\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert any(h.hint == "authorize_attribute" for h in result.auth_hints)


def test_identity_signals(tmp_path: Path) -> None:
    (tmp_path / "Auth.cs").write_text(
        'using Microsoft.AspNetCore.Identity;\n'
        'public class Service {\n'
        '    private readonly UserManager<IdentityUser> _userManager;\n'
        '    public Service(UserManager<IdentityUser> um) { _userManager = um; }\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert any(h.hint == "aspnet_identity" for h in result.auth_hints)


# ---------- Secrets ----------


def test_environment_getenv_secrets(tmp_path: Path) -> None:
    (tmp_path / "Cfg.cs").write_text(
        'public class Cfg {\n'
        '    string s = Environment.GetEnvironmentVariable("JWT_SECRET");\n'
        '    string p = Environment.GetEnvironmentVariable("DATABASE_PASSWORD");\n'
        '    string a = Environment.GetEnvironmentVariable("STRIPE_API_KEY");\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "JWT_SECRET" in names
    assert "DATABASE_PASSWORD" in names
    assert "STRIPE_API_KEY" in names

    jwt = next(s for s in result.secret_hints if s.name == "JWT_SECRET")
    assert jwt.line == 2


def test_iconfiguration_secret_keys(tmp_path: Path) -> None:
    (tmp_path / "Cfg.cs").write_text(
        'public class Cfg {\n'
        '    public Cfg(IConfiguration cfg) {\n'
        '        var s = cfg["Auth:JwtSecret"];\n'
        '        var k = builder.Configuration["Stripe:ApiKey"];\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    names_lower = {s.name.lower() for s in result.secret_hints}
    assert any("jwtsecret" in n.replace(":", "") for n in names_lower)
    assert any("apikey" in n.replace(":", "") for n in names_lower)


def test_get_connection_string_is_not_a_secret(tmp_path: Path) -> None:
    """GetConnectionString("X") names a connection string; it isn't a secret (#2)."""
    (tmp_path / "Cfg.cs").write_text(
        'public class Startup {\n'
        '    public void Configure(IConfiguration cfg) {\n'
        '        var conn = cfg.GetConnectionString("DefaultConnection");\n'
        '        var other = cfg.GetConnectionString("Default");\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "DefaultConnection" not in names
    assert "Default" not in names


# ---------- External calls ----------


def test_httpclient_getasync_extracted(tmp_path: Path) -> None:
    (tmp_path / "Client.cs").write_text(
        'using System.Net.Http;\n'
        'public class Client {\n'
        '    private readonly HttpClient _httpClient;\n'
        '    public async Task Fetch() {\n'
        '        await _httpClient.GetAsync("https://api.stripe.com/v1/charges");\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.stripe.com/v1/charges" in targets


# ---------- Frameworks + entrypoints ----------


def test_aspnetcore_application_markers(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(
        'using Microsoft.AspNetCore.Builder;\n'
        '\n'
        'var builder = WebApplication.CreateBuilder(args);\n'
        'var app = builder.Build();\n'
        'app.MapGet("/", () => "hello");\n'
        'app.Run();\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "aspnetcore" in fw

    ep = {e.hint for e in result.entrypoint_hints}
    assert "webapplication_builder" in ep
    assert "webapp_run" in ep


# ---------- Build metadata → service hints ----------


def test_csproj_root_namespace_picked_up(tmp_path: Path) -> None:
    (tmp_path / "Demo.Api.csproj").write_text(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n"
        "  <PropertyGroup>\n"
        "    <RootNamespace>Acme.Billing.Api</RootNamespace>\n"
        "    <AssemblyName>Acme.Billing.Api</AssemblyName>\n"
        "  </PropertyGroup>\n"
        "</Project>\n",
        encoding="utf-8",
    )
    (tmp_path / "Program.cs").write_text("class P {}\n", encoding="utf-8")
    result = DotnetAnalyzer().analyze(tmp_path)
    hints = {h.hint for h in result.service_hints}
    assert "namespace:Acme.Billing.Api" in hints
    assert "assembly:Acme.Billing.Api" in hints


# ---------- End-to-end sanity ----------


def test_full_aspnetcore_service_signal_set(tmp_path: Path) -> None:
    (tmp_path / "Demo.csproj").write_text(
        "<Project><PropertyGroup><RootNamespace>Demo</RootNamespace></PropertyGroup></Project>\n",
        encoding="utf-8",
    )

    (tmp_path / "Program.cs").write_text(
        'using Microsoft.AspNetCore.Authentication.JwtBearer;\n'
        'using Microsoft.AspNetCore.Builder;\n'
        'using Microsoft.EntityFrameworkCore;\n'
        '\n'
        'var builder = WebApplication.CreateBuilder(args);\n'
        'builder.Services.AddDbContext<MyContext>(opt => opt.UseNpgsql("..."));\n'
        'builder.Services.AddAuthentication().AddJwtBearer();\n'
        'var app = builder.Build();\n'
        'app.MapGet("/health", () => "ok");\n'
        'app.Run();\n',
        encoding="utf-8",
    )

    src = tmp_path / "Controllers" / "OrdersController.cs"
    src.parent.mkdir()
    src.write_text(
        'using Microsoft.AspNetCore.Mvc;\n'
        'using Microsoft.AspNetCore.Authorization;\n'
        '\n'
        '[ApiController]\n'
        '[Route("api/[controller]")]\n'
        '[Authorize]\n'
        'public class OrdersController : ControllerBase\n'
        '{\n'
        '    [HttpGet("{id:int}")]\n'
        '    public IActionResult Get(int id) => Ok();\n'
        '\n'
        '    [HttpPost("admin/refund")]\n'
        '    public IActionResult Refund() => Ok();\n'
        '\n'
        '    private readonly HttpClient _httpClient;\n'
        '    public async Task Charge() {\n'
        '        var key = Environment.GetEnvironmentVariable("STRIPE_API_KEY");\n'
        '        await _httpClient.GetAsync("https://api.stripe.com/v1/charges");\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )

    result = DotnetAnalyzer().analyze(tmp_path)

    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/health", "GET") in pairs
    assert ("/api/Orders/{id:int}", "GET") in pairs
    assert ("/api/Orders/admin/refund", "POST") in pairs

    assert any(d.kind == "postgresql" for d in result.databases)
    assert any(h.hint == "jwt" for h in result.auth_hints)
    # The controller's [Authorize] is now attributed to each of its routes (#2).
    auth = {h.hint: h.line for h in result.auth_hints}
    assert auth["aspnet_authorize:GET /api/Orders/{id:int}"] == 9
    assert auth["aspnet_authorize:POST /api/Orders/admin/refund"] == 12
    assert "STRIPE_API_KEY" in {s.name for s in result.secret_hints}
    assert any(e.target == "https://api.stripe.com/v1/charges" for e in result.external_calls)
    assert any(f.hint == "aspnetcore" for f in result.framework_hints)
    assert any(e.hint == "webapp_run" for e in result.entrypoint_hints)
    assert any(h.hint == "namespace:Demo" for h in result.service_hints)

    assert all(r.line is not None for r in result.routes)


# ---------- Repo walking (mlaify/AttackMap#253) ----------


def _write_minimal_api(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    program = repo / "Program.cs"
    program.write_text(
        'using Microsoft.AspNetCore.Builder;\n'
        '\n'
        'var builder = WebApplication.CreateBuilder(args);\n'
        'var app = builder.Build();\n'
        '\n'
        'app.MapGet("/hello", () => "world");\n'
        '\n'
        'app.Run();\n',
        encoding="utf-8",
    )
    return program


@pytest.mark.parametrize("parents", [("build", "out"), ("bin", "obj")])
def test_repo_under_skip_dir_names_is_still_analyzed(tmp_path: Path, parents: tuple[str, str]) -> None:
    # These are skip dirs; they must only count inside the repo.
    repo = tmp_path.joinpath(*parents, "repo")
    _write_minimal_api(repo)
    analyzer = DotnetAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned == 1
    assert ("/hello", "GET") in {(r.path, r.method) for r in result.routes}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_file_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    target = _write_minimal_api(tmp_path / "outside")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Linked.cs").symlink_to(target)
    analyzer = DotnetAnalyzer()
    assert analyzer.detect(repo) is False
    result = analyzer.analyze(repo)
    assert result.files_scanned == 0
    assert result.routes == []


# ---------- Route templates, groups and per-route auth (#2) ----------


def _pairs(result) -> set[tuple[str, str]]:
    return {(r.method, r.path) for r in result.routes}


def _required(result) -> set[str]:
    return {h.hint.split(":", 1)[1] for h in result.auth_hints if h.hint.startswith("aspnet_authorize:")}


def _anonymous(result) -> set[str]:
    return {h.hint.split(":", 1)[1] for h in result.entrypoint_hints if h.hint.startswith("aspnet_allow_anonymous:")}


_USERS_CONTROLLER = (
    'using Microsoft.AspNetCore.Authorization;\n'
    'using Microsoft.AspNetCore.Mvc;\n'
    '\n'
    'namespace Demo.Api;\n'
    '\n'
    '[ApiController]\n'
    '[Route("api/[controller]")]\n'
    '[Authorize]\n'
    'public class UsersController : ControllerBase\n'
    '{\n'
    '    [HttpGet("{id}", Name = "GetUser")]\n'
    '    public IActionResult Get(int id) => Ok();\n'
    '\n'
    '    [HttpPost("/public/signup")]\n'
    '    [AllowAnonymous]\n'
    '    public IActionResult Signup() => Ok();\n'
    '\n'
    '    [HttpGet("[action]")]\n'
    '    public async Task<IActionResult> SearchAsync(string q) => Ok();\n'
    '\n'
    '    [HttpGet("~/health"), AllowAnonymous]\n'
    '    public IActionResult Health() => Ok();\n'
    '\n'
    '    [HttpDelete(template: "{id}", Order = 1)]\n'
    '    public IActionResult Delete(int id) => Ok();\n'
    '}\n'
    '\n'
    'public class Helpers\n'
    '{\n'
    '    [HttpGet("helper")]\n'
    '    public IActionResult Helper() => null;\n'
    '}\n'
)


def test_attribute_named_args_absolute_templates_and_action_token(tmp_path: Path) -> None:
    (tmp_path / "UsersController.cs").write_text(_USERS_CONTROLLER, encoding="utf-8")
    result = DotnetAnalyzer().analyze(tmp_path)
    assert _pairs(result) == {
        ("GET", "/api/Users/{id}"),          # named arg after the template
        ("POST", "/public/signup"),          # `/` template is absolute
        ("GET", "/api/Users/Search"),        # [action], Async suffix dropped
        ("GET", "/health"),                  # `~/` template is absolute
        ("DELETE", "/api/Users/{id}"),       # template: named argument
        ("GET", "/helper"),                  # second class has no [Route]
    }
    lines = {(r.method, r.path): r.line for r in result.routes}
    assert lines[("GET", "/api/Users/{id}")] == 11
    assert lines[("POST", "/public/signup")] == 14


def test_attribute_effective_auth_allow_anonymous_overrides_class_authorize(tmp_path: Path) -> None:
    (tmp_path / "UsersController.cs").write_text(_USERS_CONTROLLER, encoding="utf-8")
    result = DotnetAnalyzer().analyze(tmp_path)
    assert _required(result) == {"GET /api/Users/{id}", "GET /api/Users/Search", "DELETE /api/Users/{id}"}
    assert _anonymous(result) == {"POST /public/signup", "GET /health"}
    # The required hints sit on their own route lines, where core attributes them.
    hint_lines = {h.hint: h.line for h in result.auth_hints}
    assert hint_lines["aspnet_authorize:GET /api/Users/{id}"] == 11
    # [Authorize] is now per-route, not a file-level hint.
    assert not any(h.hint == "authorize_attribute" for h in result.auth_hints)


def test_combined_attribute_list_and_method_level_authorize(tmp_path: Path) -> None:
    (tmp_path / "OrdersController.cs").write_text(
        'using Microsoft.AspNetCore.Mvc;\n'
        '[Route("api/orders")]\n'
        'public class OrdersController : ControllerBase\n'
        '{\n'
        '    [HttpGet, Authorize(Roles = "Admin")]\n'
        '    public IActionResult List() => Ok();\n'
        '\n'
        '    [HttpPost]\n'
        '    public IActionResult Create() => Ok();\n'
        '\n'
        '    [Route("export")]\n'
        '    public IActionResult Export() => Ok();\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert _pairs(result) == {("GET", "/api/orders"), ("POST", "/api/orders"), ("ANY", "/api/orders/export")}
    assert _required(result) == {"GET /api/orders"}
    assert _anonymous(result) == set()


def test_area_token_and_multiple_class_routes(tmp_path: Path) -> None:
    (tmp_path / "ReportsController.cs").write_text(
        'using Microsoft.AspNetCore.Mvc;\n'
        '[Area("Admin")]\n'
        '[Route("[area]/[controller]")]\n'
        '[Route("legacy/reports")]\n'
        'public class ReportsController : Controller\n'
        '{\n'
        '    [HttpGet("{id}")]\n'
        '    public IActionResult Show(int id) => View();\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert _pairs(result) == {("GET", "/Admin/Reports/{id}"), ("GET", "/legacy/reports/{id}")}


_PROGRAM = (
    'using Microsoft.AspNetCore.Builder;\n'
    'var builder = WebApplication.CreateBuilder(args);\n'
    'var app = builder.Build();\n'
    '\n'
    'var api = app.MapGroup("/api");\n'
    'var v2 = api.MapGroup("/v2")\n'
    '    .RequireAuthorization();\n'
    'v2.MapGet("/orders/{id}", (int id) => Results.Ok());\n'
    'v2.MapPost("/login", () => Results.Ok()).AllowAnonymous();\n'
    'api.MapGet("ping", () => "pong");\n'
    'api.MapDelete("/items/{id}", (int id) => Results.Ok())\n'
    '   .WithName("DeleteItem")\n'
    '   .RequireAuthorization("Admin");\n'
    'app.MapGroup("/inline").MapPut("/x", () => Results.Ok());\n'
    'app.MapGet("/me", [Authorize] (ClaimsPrincipal u) => u.Identity!.Name);\n'
    'var admin = app.MapGroup("/admin");\n'
    'admin.MapGet("/stats", () => Results.Ok());\n'
    'admin.RequireAuthorization();\n'
    'app.MapHub<ChatHub>("/chat");\n'
    'app.MapGrpcService<GreeterService>();\n'
    'app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");\n'
    'app.Run();\n'
)


def test_minimal_api_nested_map_group_prefixes(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(_PROGRAM, encoding="utf-8")
    result = DotnetAnalyzer().analyze(tmp_path)
    assert _pairs(result) == {
        ("GET", "/api/v2/orders/{id}"),
        ("POST", "/api/v2/login"),
        ("GET", "/api/ping"),
        ("DELETE", "/api/items/{id}"),
        ("PUT", "/inline/x"),
        ("GET", "/me"),
        ("GET", "/admin/stats"),
        ("ANY", "/chat"),
        ("ANY", "/{controller=Home}/{action=Index}/{id?}"),
    }
    lines = {(r.method, r.path): r.line for r in result.routes}
    assert lines[("GET", "/api/v2/orders/{id}")] == 8
    protocols = {h.hint for h in result.protocol_hints}
    assert {"signalr_hub:ChatHub", "grpc_service:GreeterService"} <= protocols


def test_minimal_api_effective_auth(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(_PROGRAM, encoding="utf-8")
    result = DotnetAnalyzer().analyze(tmp_path)
    assert _required(result) == {
        "GET /api/v2/orders/{id}",   # group .RequireAuthorization()
        "DELETE /api/items/{id}",    # endpoint .RequireAuthorization("Admin")
        "GET /me",                   # lambda [Authorize]
        "GET /admin/stats",          # admin.RequireAuthorization() after MapGet
    }
    assert _anonymous(result) == {"POST /api/v2/login"}  # .AllowAnonymous() beats the group


def test_map_controllers_require_authorization_applies_to_other_files(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(
        'var app = WebApplication.CreateBuilder(args).Build();\n'
        'app.MapControllers().RequireAuthorization();\n'
        'app.MapGet("/open", () => "ok");\n'
        'app.Run();\n',
        encoding="utf-8",
    )
    (tmp_path / "UsersController.cs").write_text(_USERS_CONTROLLER.replace("[Authorize]\npublic class", "public class"), encoding="utf-8")
    result = DotnetAnalyzer().analyze(tmp_path)
    assert "GET /api/Users/{id}" in _required(result)
    assert "GET /helper" in _required(result)
    assert "GET /open" not in _required(result)  # minimal APIs aren't controllers
    assert _anonymous(result) == {"POST /public/signup", "GET /health"}


def test_fallback_policy_requires_auth_for_unmarked_routes(tmp_path: Path) -> None:
    (tmp_path / "Program.cs").write_text(
        'var builder = WebApplication.CreateBuilder(args);\n'
        'builder.Services.AddAuthorization(options =>\n'
        '{\n'
        '    options.FallbackPolicy = new AuthorizationPolicyBuilder()\n'
        '        .RequireAuthenticatedUser()\n'
        '        .Build();\n'
        '});\n'
        'var app = builder.Build();\n'
        'app.MapGet("/data", () => "x");\n'
        'app.MapGet("/public", () => "x").AllowAnonymous();\n'
        'app.Run();\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert _required(result) == {"GET /data"}
    assert _anonymous(result) == {"GET /public"}


def test_razor_pages_routes(tmp_path: Path) -> None:
    pages = tmp_path / "Pages"
    (pages / "Admin").mkdir(parents=True)
    (pages / "Index.cshtml").write_text('@page\n<h1>Home</h1>\n', encoding="utf-8")
    (pages / "Admin" / "Edit.cshtml").write_text('@page "{id:int}"\n@model EditModel\n', encoding="utf-8")
    (pages / "Shared").mkdir()
    (pages / "Shared" / "_Layout.cshtml").write_text('<html>@RenderBody()</html>\n', encoding="utf-8")
    area = tmp_path / "Areas" / "Identity" / "Pages" / "Account"
    area.mkdir(parents=True)
    (area / "Login.cshtml").write_text('@page\n', encoding="utf-8")
    (tmp_path / "Pages" / "About.cshtml").write_text('@page "/about-us"\n', encoding="utf-8")
    result = DotnetAnalyzer().analyze(tmp_path)
    assert _pairs(result) == {
        ("ANY", "/"),
        ("ANY", "/Admin/Edit/{id:int}"),
        ("ANY", "/Identity/Account/Login"),
        ("ANY", "/about-us"),
    }


def test_all_emitted_paths_start_with_slash(tmp_path: Path) -> None:
    (tmp_path / "UsersController.cs").write_text(_USERS_CONTROLLER, encoding="utf-8")
    (tmp_path / "Program.cs").write_text(_PROGRAM, encoding="utf-8")
    (tmp_path / "Legacy.cs").write_text(
        'app.MapGet("no-slash", () => "x");\n'
        'app.MapMethods("also-none", new[] { "GET" }, () => "x");\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    assert result.routes
    assert all(r.path.startswith("/") for r in result.routes), [r.path for r in result.routes]
    assert ("GET", "/no-slash") in _pairs(result)


def test_appsettings_connection_string_password_is_a_secret_without_its_key_name(tmp_path: Path) -> None:
    (tmp_path / "appsettings.json").write_text(
        '{\n'
        '  // comments are allowed in .NET config\n'
        '  "ConnectionStrings": {\n'
        '    "Default": "Server=db;Database=app;User Id=sa;Password=Hunter2!;",\n'
        '    "Cache": "localhost:6379",\n'
        '    "Placeholder": "Server=db;Password={DB_PASSWORD}"\n'
        '  },\n'
        '  "Logging": { "LogLevel": { "Default": "Information" } }\n'
        '}\n',
        encoding="utf-8",
    )
    (tmp_path / "appsettings.Production.json").write_text(
        '{ "ConnectionStrings": { "Main": "Host=pg;Pwd=s3cret" } }\n', encoding="utf-8"
    )
    (tmp_path / "other.json").write_text(
        '{ "ConnectionStrings": { "X": "Password=nope" } }\n', encoding="utf-8"
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    secrets = [(s.name, s.file, s.line) for s in result.secret_hints]
    assert secrets == [
        ("connection_string_password", "appsettings.Production.json", 1),
        ("connection_string_password", "appsettings.json", 4),
    ]
    assert not any(s.name in {"Default", "Main", "Cache"} for s in result.secret_hints)
    assert all("Hunter2" not in (s.evidence_text or "") for s in result.secret_hints)
    assert all(s.kind == "config_literal" for s in result.secret_hints)
