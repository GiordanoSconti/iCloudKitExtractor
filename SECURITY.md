# Security policy

## Supported versions

iCloudKit Extractor is **experimental research software**. Security fixes are
applied on a best-effort basis to the latest `main` branch and the most recent
published GitHub Release when feasible.

| Version / channel | Supported |
|-------------------|-----------|
| Latest `main` | Yes (best effort) |
| Latest GitHub Release | Yes (best effort) |
| Older releases / forks | No guarantee |

## Scope

Please report vulnerabilities that affect:

* Credential or token leakage in logs, HAR captures, UI persistence, or reports
* Path traversal / unsafe writes outside the chosen case package root
* Insecure handling of license material or Anisette bridge configuration
* Dependency issues with a realistic exploit path in this project’s usage

Out of scope (unless you can show a concrete project bug):

* Apple service outages, account locks, or protocol changes on Apple’s side
* Issues that require already-compromised host credentials
* Requests to help access accounts without authorization

## Reporting a vulnerability

**Do not open a public GitHub issue for sensitive reports.**

Email the maintainer:

* **Giordano Sconti** — [giordano.sconti@gruppoinformaticiforensi.it](mailto:giordano.sconti@gruppoinformaticiforensi.it)
* Optional CC: [giordano.sconti@gmail.com](mailto:giordano.sconti@gmail.com)

Include, where possible:

1. Description and impact
2. Affected commit / release
3. Steps to reproduce (minimal)
4. Suggested fix, if you have one
5. Whether you plan a public write-up and preferred timeline

You may also use GitHub’s **Private vulnerability reporting** on this repository
if it is enabled for the project.

## Response expectations

* **Acknowledgement:** aim within **7 days**
* **Triage / status update:** aim within **14 days** after acknowledgement
* **Fix / advisory:** best effort; timelines depend on severity and whether the
  issue is in project code vs. an upstream dependency

Please give us a reasonable window before public disclosure when the issue is
not already being actively exploited.

## Safe handling reminders for users

* Use only on **authorized** Apple IDs / devices
* Treat `%AppData%` / Application Support logs, HAR files, and case packages as
  sensitive — they may contain account-adjacent metadata even when tokens are
  redacted from the LE report
* Rotate credentials if you suspect accidental exposure in a shared log dump
