# Contributing to iCloudKit Extractor

Thanks for considering a contribution. This project is **experimental research /
forensic lab software** that talks to Apple services through undocumented
protocols. Please read this guide before opening an issue or pull request.

## Ground rules

1. **Authorized use only.** Contributions and discussion must assume use against
   Apple IDs / devices **you own or are explicitly authorized** to examine.
   Do not submit, request, or discuss assistance for unauthorized access.
2. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
3. Prefer small, reviewable PRs over large mixed dumps.
4. If you use coding agents / LLMs, **always review** generated code before
   submitting. Do not paste third-party code without a compatible license and
   attribution.
5. Accepted contributions are licensed under the project **MIT** license (see
   [`LICENSE`](LICENSE)). Copyright / possession remains with **Giordano Sconti**,
   with a use/collaboration grant to Forensis-Lab as described in the README.

## What helps most

* Bug reports with repro steps (OS, .NET SDK, Anisette mode, ADP on/off)
* Fixes with failing-case notes and a short “how tested”
* Documentation clarifications (README, protocol diary, build notes)
* Hardening around logging redaction, case packaging, and integrity manifests

## What to avoid

* Secrets, session tokens, Recovery Keys, passcodes, or live account dumps in
  issues/PRs
* Large capture corpora, private lab dumps, or AppleDouble (`._*`) noise
* Drive-by refactors unrelated to the stated change
* Feature requests that amount to unauthorized account compromise tooling

## Development setup

* **.NET 10 SDK** — see [README → How to Build](README.md#how-to-build)
* **macOS:** Avalonia desktop (`src/iCloudKitExtractor.Desktop`)
* **Windows:** WPF (`src/iCloudKitExtractor`) — may need
  `EnableWindowsTargeting=true` when cross-compiling from non-Windows hosts
* Core library: `src/iCloudKitExtractor.Core`

Useful build checks:

```bash
dotnet build src/iCloudKitExtractor.Core/iCloudKitExtractor.Core.csproj -c Release
dotnet build src/iCloudKitExtractor.Desktop/iCloudKitExtractor.Desktop.csproj -c Release
```

## Pull request process

1. Fork (or use a branch) and keep commits focused.
2. Describe **why** the change exists and how you tested it.
3. Fill in the [pull request template](.github/pull_request_template.md).
4. Do not commit credentials, `.env`, license keys, or personal Anisette state.
5. Expect careful review — protocol surfaces break often; maintainers may ask for
   narrower diffs or extra evidence.

## Issues

Use the GitHub issue templates under [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/):

* **Bug report** — unexpected failures, crashes, protocol regressions
* **Feature request** — lab / forensic capabilities within authorized-use scope
* **Security** concerns — prefer the process in [`SECURITY.md`](SECURITY.md)
  instead of a public issue when disclosure is sensitive

## Contact

* **Email:** [giordano.sconti@gruppoinformaticiforensi.it](mailto:giordano.sconti@gruppoinformaticiforensi.it)
* **Project:** https://github.com/GiordanoSconti/iCloudKitExtractor
