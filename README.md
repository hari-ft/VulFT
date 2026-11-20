# VulFT – vulnerability tracker for your apps

Android app (Kotlin, Jetpack Compose, Room, WorkManager) that lists known CVEs for the apps you pick.

## Data sources
| Source | Used for | Key |
|---|---|---|
| NVD API 2.0 | CVEs, CVSS, affected version ranges, product (CPE) search | entered in Settings |
| CISA KEV | "Actively exploited" flag | none |
| FIRST EPSS | Exploit probability | none |
| GitHub Advisory DB | Optional lookup on the CVE detail screen | entered in Settings (optional) |
| OSV.dev | Open-source packages (PyPI, npm, Maven, Go, NuGet…) with exact fixed versions; Android Security Bulletins for the phone's own OS (patch level) | none |
| Microsoft MSRC (Security Update Guide) | Windows, Office, Edge, Teams, .NET… with the KB update and fixed build | none |

## Setup
No keys are compiled into the app. After installing, open Settings → Data sources and enter:
- NVD API key (free: https://nvd.nist.gov/developers/request-an-api-key). Without it sync is ~10x slower.
- GitHub token (optional, read-only, no permissions needed) for the advisory lookup.

Keys are stored in the app's private storage on the device only (backup disabled).

Build: `gradlew assembleDebug` → `app/build/outputs/apk/debug/app-debug.apk`

## How it works
1. **Settings → Apps to monitor**: tick apps. Each app needs an NVD product (`vendor:product`); ~40 popular apps are pre-mapped, others: tap → search NVD.
   "Add product" tracks software that isn't on the phone.
2. **Sync** (manual or every 6/12/24/48 h) downloads CVEs per product, then KEV + EPSS.
3. **List**: filter by app / severity / KEV / "my version affected"; sort by severity, app name, date or EPSS;
   long-press to select; export CSV/JSON or email the selection.
4. **Detail**: CVSS vector, EPSS, KEV info, affected version ranges vs. installed version, CWE, references, GitHub advisories.
5. **Alerts**: SMTP settings + rules (severity, category, apps, KEV only, affected only). New CVEs found by a sync that match the rules are emailed.
   The first sync of a product is treated as a baseline (no flood of old CVEs) – use "Email matching CVEs now" for a full digest.

## Notes
- Uses `QUERY_ALL_PACKAGES` to list installed apps: fine for personal/sideloaded use, restricted on Google Play.
- No API keys are compiled into the APK; each user enters their own in Settings.
- SMTP password is stored in app-private storage (backup disabled).
- NVD lists every platform for a product (e.g. Chrome desktop CVEs show for Chrome Android). Use the "My version affected" filter to narrow.
