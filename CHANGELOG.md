# Changelog

All notable changes to `attackmap-analyzer-dotnet` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Walk and read the repo with the shared `attackmap.sdk.fs` helpers
  (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a private
  `rglob` + `SKIP_DIRS` walk ([mlaify/AttackMap#253](https://github.com/mlaify/AttackMap/issues/253)).
  Skip dirs are now `DEFAULT_SKIP_DIRS` plus `bin`, `obj`, `.vs`, `.idea`, `packages`, `TestResults` and `publish` (a superset of the old list; it also skips `build/`, `dist/`, `out/`, `target/`, `vendor/` and AttackMap output dirs). `.csproj` files are read with `read_source` too.

### Fixed

- ASP.NET route templates follow ASP.NET semantics
  ([#2](https://github.com/mlaify/attackmap-analyzer-dotnet/issues/2)). Attribute
  argument lists are parsed, so `[HttpGet("{id}", Name = "GetUser")]`,
  `template:` arguments and combined `[HttpGet, Authorize]` lists produce
  routes. Templates starting with `/` or `~/` are absolute instead of being
  appended to the controller prefix. `[action]` (method name minus `Async`)
  and `[area]` are substituted along with `[controller]`, all
  case-insensitively. Every emitted path now starts with `/` (it was
  `api/Users/...`). A class prefix applies only inside its class body, so a
  second class without `[Route]` no longer inherits the first class's prefix.
  Comments, preprocessor lines and string literals are ignored when reading
  attributes.
- Minimal API `MapGroup` prefixes, including nested groups held in variables
  and inline `app.MapGroup("/x").MapGet(...)` chains, are joined onto the
  endpoint paths (`/api/v2/orders/{id}` instead of `/orders/{id}`).
- `GetConnectionString("Default")` is no longer reported as a secret named
  `Default`. Literal `Password=`/`Pwd=` values in `appsettings*.json`
  `ConnectionStrings` are reported as `connection_string_password` instead
  (the previously unused `CONFIG_FILES` is replaced by an `appsettings*.json`
  match).
- A repo checked out under a directory named like a skip dir (e.g. `/build/...`,
  `.../out/...`) was silently skipped entirely; skip dirs are now matched only
  inside the repo.
- Symlinked files pointing outside the repo are no longer analyzed.
- An unreadable file no longer raises out of `analyze()`, and cp1252/latin-1
  sources are analyzed instead of dropped. `files_scanned` counts only files
  that were actually read.
- `detect()` stops at the first `.cs`/`.csproj`/`.fsproj`/`.sln` file and prunes skipped directories instead of walking all of them.

### Added

- Per-route effective auth state ([#2](https://github.com/mlaify/attackmap-analyzer-dotnet/issues/2)).
  `[Authorize]`/`[AllowAnonymous]` on the action or controller,
  `.RequireAuthorization()`/`.AllowAnonymous()` on a minimal API endpoint or
  any enclosing group, lambda `[Authorize]`/`[AllowAnonymous]`, authorization
  fallback policies and `MapControllers().RequireAuthorization()` are
  resolved per route, with anonymous winning as in ASP.NET. A route that
  requires auth gets an `aspnet_authorize:<METHOD> <path>` auth hint on its
  own line. An explicitly anonymous route gets an
  `aspnet_allow_anonymous:<METHOD> <path>` entrypoint hint. `[Authorize]` is no
  longer a file-level `authorize_attribute` hint when it guards a route; it
  stays one only where it guards none (for example a class without actions).
- `MapHub<T>("/path")` routes (plus a `signalr_hub:<T>` protocol hint),
  `MapGrpcService<T>()` (`grpc_service:<T>` protocol hint), `MapControllerRoute`
  / `MapDefaultControllerRoute` conventional route patterns, `[AcceptVerbs]`,
  and Razor Pages `@page` routes from `.cshtml` files.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. C# / .NET (ASP.NET Core) ecosystem analyzer plugin for AttackMap (minimal APIs, attribute routing, EF Core, Identity, JwtBearer).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-dotnet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-dotnet/releases/tag/v0.1.0
