# AnisetteServer.Licensed

Headless Anisette API with Package-C license gate (Ed25519 + SQLite). Default listen: `http://0.0.0.0:6971` (no certs). Optional HTTPS: `ANISETTE_TLS_ENABLE=1` or `ANISETTE_SERVER_URLS=https://0.0.0.0:6971`.

See [docs/ANISETTE_LICENSED.md](../../docs/ANISETTE_LICENSED.md).

```powershell
dotnet run --project src/AnisetteLicenseGen -- init-keys
$env:ANISETTE_SERVER_BACKEND = "frida"
$env:FRIDA_ANISETTE_HOST = "192.168.x.y:27042"
dotnet run --project src/AnisetteServer.Licensed -- --port 6971
```

Generate your own keys. Never commit `keys/` or issued licenses.
