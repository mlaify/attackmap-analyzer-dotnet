# attackmap-analyzer-dotnet

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

C# / .NET (ASP.NET Core) ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This analyzer extracts structured signals from .NET solutions and projects:

- **Web frameworks** — ASP.NET Core minimal APIs (`app.MapGet`, `app.MapPost`, `app.MapMethods`, nested `MapGroup` prefixes), attribute routing on controllers (`[HttpGet]`, `[HttpPost]`, `[Route]`, `[AcceptVerbs]`, with class-level `[Route]` prefix joining and `[controller]`/`[action]`/`[area]` token substitution), `MapHub<T>`, `MapControllerRoute`, Razor Pages `@page`; `MapGrpcService<T>` as a protocol hint
- **Databases** — Entity Framework Core (`UseSqlServer` / `UseNpgsql` / `UseMySql` / `UseSqlite`), Dapper, System.Data.SqlClient / Microsoft.Data.SqlClient, Npgsql, MySql.Data / MySqlConnector, MongoDB.Driver, StackExchange.Redis, AWS SDK (S3, DynamoDB)
- **Auth packages** — `AddJwtBearer` (Microsoft.AspNetCore.Authentication.JwtBearer), `AddOpenIdConnect`, ASP.NET Identity (`UserManager`, `SignInManager`, `IdentityUser`, `PasswordHasher`), per-route `[Authorize]` / `[AllowAnonymous]` / `.RequireAuthorization()` / `.AllowAnonymous()`, Duende IdentityServer, BCrypt.Net, Argon2
- **HTTP clients (external calls)** — `HttpClient.GetAsync` / `PostAsync` / `SendAsync`, `HttpRequestMessage`, `RestClient` (RestSharp), `new Uri(...)`
- **Secrets** — `Environment.GetEnvironmentVariable("...")`, `IConfiguration["..."]` / `Configuration["..."]` / `builder.Configuration["..."]` with secret-shaped keys, literal `Password=` in `appsettings*.json` `ConnectionStrings`
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

- **Route templates** follow ASP.NET semantics: a controller annotated with `[Route("api/[controller]")]` causes its `[HttpGet("{id:int}", Name = "GetUser")]` action to emit as `/api/Orders/{id:int}`. An action template starting with `/` or `~/` is absolute and replaces the controller prefix. `[controller]` (class name minus `Controller`), `[action]` (method name minus `Async`) and `[area]` (`[Area("...")]`) are substituted case-insensitively. A class prefix applies only inside that class's body. Every emitted path starts with `/`.
- **Minimal API groups**: `var api = app.MapGroup("/api"); var v2 = api.MapGroup("/v2"); v2.MapGet("/orders/{id}", ...)` emits `/api/v2/orders/{id}`. Inline chains (`app.MapGroup("/x").MapGet("/y", ...)`) work too. A group built in another file or by a custom extension method isn't followed.
- **Per-route auth**: each route's effective state is computed. `[AllowAnonymous]` (attribute) or `.AllowAnonymous()` (minimal API, on the endpoint or any enclosing group) wins over `[Authorize]` / `.RequireAuthorization()`, as in ASP.NET. An authorization fallback policy, or `MapControllers().RequireAuthorization()`, makes unmarked routes require auth. A route that requires auth gets an `aspnet_authorize:<METHOD> <path>` auth hint on its own line; an explicitly anonymous route gets an `aspnet_allow_anonymous:<METHOD> <path>` entrypoint hint and no auth hint. Core attributes auth hints to routes by a ±40-line window until `Route` carries an auth field ([mlaify/AttackMap#256](https://github.com/mlaify/AttackMap/issues/256)), so in a compact controller a neighbor's hint can still show up on an anonymous route. `[Authorize]` inherited from a base controller class isn't followed.
- **Connection strings**: `GetConnectionString("DefaultConnection")` names a connection string, so it isn't reported as a secret. A literal `Password=`/`Pwd=` inside an `appsettings*.json` `ConnectionStrings` entry is reported as `connection_string_password` (`kind="config_literal"`); the evidence names the entry, never the value.
- **F# (.fs) projects** are detected via `.fsproj` but route extraction is not yet implemented (Giraffe / Saturn).
- **Razor Pages**: `@page` in a `.cshtml` file emits an `ANY` route from the file's path under `Pages/` (or `Areas/<Area>/Pages/`), with `Index` mapped to its folder and an optional `@page "template"` appended (or used as-is when it starts with `/`). Page auth conventions (`AuthorizeFolder`, `[Authorize]` on the PageModel) aren't read yet. Blazor `.razor` components aren't covered.

## License

MIT
