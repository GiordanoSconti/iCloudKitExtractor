# AnisetteServer.Licensed

Headless Anisette HTTP API with Package-C license gate (Ed25519 + SQLite).

See [docs/ANISETTE_LICENSED.md](../../docs/ANISETTE_LICENSED.md).

```powershell
dotnet run --project src/AnisetteLicenseGen -- init-keys
$env:ANISETTE_SERVER_BACKEND = "frida"
$env:FRIDA_ANISETTE_HOST = "192.168.x.y:27042"
dotnet run --project src/AnisetteServer.Licensed -- --port 6971
```

Generate your own keys. Never commit `keys/` or issued licenses.
