# attackmap-analyzer-dotnet

> [!NOTE]
> **Development is paused.** This project is not under active development.
> The code remains available for reference, and security reports are still
> welcome at [security@mlaify.io](mailto:security@mlaify.io).

C# / .NET (ASP.NET Core) ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This analyzer extracts structured signals from .NET solutions and projects:

- **Web frameworks** — ASP.NET Core minimal APIs (`app.MapGet`, `app.MapPost`, `app.MapMethods`), attribute routing on controllers (`[HttpGet]`, `[HttpPost]`, with class-level `[Route]` prefix joining and `[controller]` token substitution)
- **Databases** — Entity Framework Core (`UseSqlServer` / `UseNpgsql` / `UseMySql` / `UseSqlite`), Dapper, System.Data.SqlClient / Microsoft.Data.SqlClient, Npgsql, MySql.Data / MySqlConnector, MongoDB.Driver, StackExchange.Redis, AWS SDK (S3, DynamoDB)
- **Auth packages** — `AddJwtBearer` (Microsoft.AspNetCore.Authentication.JwtBearer), `AddOpenIdConnect`, ASP.NET Identity (`UserManager`, `SignInManager`, `IdentityUser`, `PasswordHasher`), `[Authorize]` attribute, Duende IdentityServer, BCrypt.Net, Argon2
- **HTTP clients (external calls)** — `HttpClient.GetAsync` / `PostAsync` / `SendAsync`, `HttpRequestMessage`, `RestClient` (RestSharp), `new Uri(...)`
- **Secrets** — `Environment.GetEnvironmentVariable("...")`, `IConfiguration["..."]` / `Configuration["..."]` / `builder.Configuration["..."]` with secret-shaped keys, `GetConnectionString(...)`
- **Service hints** — `<RootNamespace>` and `<AssemblyName>` from `.csproj`

All emissions populate AttackMap's Signal v2 fields (line numbers, evidence snippets, confidence scores) so downstream insights can cite `path/to/file.cs:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-dotnet.git
```

The analyzer is auto-discovered by AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

```bash
# Auto-discovered when installed:
attackmap analyze /path/to/dotnet/repo

# Or invoke explicitly:
attackmap analyze /path/to/dotnet/repo --module dotnet
```

## Detection

`detect()` returns true when any of the following are present, ignoring `bin/`, `obj/`, `.vs/`, `.idea/`, `.git/`, `node_modules/`, `packages/`, `TestResults/`, and `publish/`:

- A `.csproj`, `.fsproj`, or `.sln` file anywhere in the tree
- A `.cs` file anywhere in the tree

## Coverage notes

- **Class-level `[Route]` prefix joining**: a controller annotated with `[Route("api/[controller]")]` or `[Route("api/orders")]` causes its method-level `[HttpGet("{id:int}")]` to emit as `api/Orders/{id:int}` (with `[controller]` substituted with the class name minus the `Controller` suffix). Multiple controllers per file are tracked correctly.
- **Minimal API + controller routing in the same project**: both extractors run on every `.cs` file. The minimal-API regex looks for `app.Map*("...", handler)`; the controller regex looks for `[HttpX("...")]` attributes. They don't overlap.
- **Connection strings as secrets**: `GetConnectionString("DefaultConnection")` is treated as a secret reference because the connection string itself is a credential. The named key (`DefaultConnection`) is stored as the secret name.
- **F# (.fs) projects** are detected via `.fsproj` but route extraction is not yet implemented (Giraffe / Saturn).
- **Razor Pages** (`@page` directives in `.cshtml` / `.razor`) are not yet covered. Most security-critical APIs use minimal APIs or controllers.

## License

MIT
