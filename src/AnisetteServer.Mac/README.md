# AnisetteServer.Mac → **Anisette Middleware** (Windows / macOS)

Avalonia **desktop** UI for both **Windows and macOS** (the `.Mac` folder name is historical).

Frida → jailbroken iPhone + Package-C license panel + local HTTP/HTTPS gate.

Published binary name: **`AnisetteMiddleware`** (`AnisetteMiddleware.exe` on Windows).

See [docs/ANISETTE_LICENSED.md](../../docs/ANISETTE_LICENSED.md).

```bash
# either OS
dotnet run --project src/AnisetteServer.Mac -c Release

# publish examples
dotnet publish src/AnisetteServer.Mac -c Release -r win-x64 --self-contained false
dotnet publish src/AnisetteServer.Mac -c Release -r osx-arm64 --self-contained false
```

Generate your own keys under the data root (UI creates them on first Start/Save if missing).
