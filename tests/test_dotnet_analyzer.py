"""Tests for the DotnetAnalyzer plugin."""

from __future__ import annotations

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
    assert ("api/Users/{id:int}", "GET") in pairs
    assert ("api/Users", "POST") in pairs
    assert ("api/Users/{id:int}", "DELETE") in pairs


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
    assert ("api/orders/v2", "GET") in pairs
    assert ("api/orders/v2/refund", "POST") in pairs


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
    assert ("api/a/x", "GET") in pairs
    assert ("api/b/y", "GET") in pairs
    assert ("api/a/y", "GET") not in pairs
    assert ("api/b/x", "GET") not in pairs


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


def test_connection_string_extracted(tmp_path: Path) -> None:
    (tmp_path / "Cfg.cs").write_text(
        'public class Startup {\n'
        '    public void Configure(IConfiguration cfg) {\n'
        '        var conn = cfg.GetConnectionString("DefaultConnection");\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = DotnetAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "DefaultConnection" in names


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
    assert ("api/Orders/{id:int}", "GET") in pairs
    assert ("api/Orders/admin/refund", "POST") in pairs

    assert any(d.kind == "postgresql" for d in result.databases)
    assert any(h.hint == "jwt" for h in result.auth_hints)
    assert any(h.hint == "authorize_attribute" for h in result.auth_hints)
    assert "STRIPE_API_KEY" in {s.name for s in result.secret_hints}
    assert any(e.target == "https://api.stripe.com/v1/charges" for e in result.external_calls)
    assert any(f.hint == "aspnetcore" for f in result.framework_hints)
    assert any(e.hint == "webapp_run" for e in result.entrypoint_hints)
    assert any(h.hint == "namespace:Demo" for h in result.service_hints)

    assert all(r.line is not None for r in result.routes)
