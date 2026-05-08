# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

## Scope
C# / .NET (ASP.NET Core) ecosystem coverage:

- **Web frameworks**: ASP.NET Core minimal APIs (`app.MapGet`/`MapPost`/`MapMethods`), attribute routing (`[HttpGet]`, `[HttpPost]`, with class-level `[Route]` prefix joining and `[controller]` token substitution)
- **Databases**: Entity Framework Core (driver-aware via `UseSqlServer` / `UseNpgsql` / `UseSqlite` / `UseMySql`), Dapper, raw SqlConnection, Npgsql, MySqlConnector, Microsoft.Data.Sqlite, MongoDB.Driver, StackExchange.Redis, AWS SDK (S3 + DynamoDB)
- **Auth**: `AddJwtBearer`, `AddOpenIdConnect`, ASP.NET Identity (`UserManager`/`SignInManager`/`IdentityUser`/`PasswordHasher`), `[Authorize]`, Duende IdentityServer, BCrypt.Net, Argon2
- **HTTP clients**: `HttpClient.*Async`, `HttpRequestMessage`, RestSharp, `new Uri(...)`
- **Secrets**: `Environment.GetEnvironmentVariable`, `IConfiguration["..."]`, `GetConnectionString`
- **Service hints**: `<RootNamespace>` + `<AssemblyName>` from `.csproj`

## Out of scope (for now)
- F# routing frameworks (Giraffe, Saturn) — `.fsproj` is detected but no F# routes extracted.
- Razor Pages (`@page`) and Blazor (`@page`) routing.
- WebSocket / SignalR hub mappings (`MapHub<T>`).
- Source-generator–based route registration (e.g., NSwag, custom analyzers).

## `[controller]` token substitution
Class-level `[Route("api/[controller]")]` is parsed with a regex that captures BOTH the route template AND the following `class FooController` declaration in the same lookahead. The `[controller]` token is then substituted with the class name minus the `Controller` suffix — e.g., `UsersController` → `Users`, producing `api/Users` as the prefix. Both `[controller]` and `[Controller]` casings are supported.

## Confidence policy
- Hash-based password hashers (BCrypt, Argon2) → 0.9
- Canonical ASP.NET Core auth setup (`AddJwtBearer`, `AddOpenIdConnect`, Identity types) → 0.85
- `[Authorize]` attribute, `AddAuthorization` → 0.85
- Keyword-only matches (`Authorization`, `Bearer`, `api_key`) → 0.6
- Secret env-var / IConfiguration extractions → 0.85

## Testing
Tests write realistic C# snippets to `tmp_path` and assert on the resulting `ScanResult`. Each new framework or extractor needs both:
- A positive test (signal fires on representative code).
- A negative test (e.g., `[Route]` on a non-class context shouldn't be treated as a class prefix).

## Multi-controller files
The class-level `[Route]` regex captures the immediately-following `class Foo` declaration, which means each controller in a file gets its own prefix. Tests verify that no cross-pollination occurs between two controllers in the same file.
