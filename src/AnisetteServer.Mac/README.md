# AnisetteServer.Mac

Avalonia desktop middleware: Frida → jailbroken iPhone + Package-C license panel.

See [docs/ANISETTE_LICENSED.md](../../docs/ANISETTE_LICENSED.md).

```bash
dotnet run --project src/AnisetteServer.Mac -c Release
dotnet publish src/AnisetteServer.Mac -c Release -r osx-arm64 --self-contained false
```

Generate your own keys under the data root (UI creates them on first Start/Save if missing).
