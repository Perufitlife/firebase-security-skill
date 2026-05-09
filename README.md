# Firebase Firestore Rules Security Auditor

> Detect the infamous Firebase data-leak patterns (`match /{document=**} { allow read, write: if true; }`, expired test-mode rules, auth-without-ownership) in any `firestore.rules` file. Optional active probe sends an anonymous GET to the Firestore REST endpoint to PROVE the leak with real data.

> ▶ **Run it without installing anything →** [apify.com/renzomacar/firebase-security-auditor](https://apify.com/renzomacar/firebase-security-auditor) (paste your firestore.rules + optional project ID, get HTML report)

> ⚡ Want me to run it for you and send back a written report? **$99, 24h delivery →** https://perufitlife.github.io/supabase-security-skill/ (one landing covers all five — Supabase, PocketBase, Appwrite, Hasura, Firebase)

## Why this exists

Firebase Firestore rules are easy to get wrong, and the failure mode is the worst possible: silent + total. The patterns I see over and over:

- **`match /{document=**} { allow read, write: if true; }`** — leftover from `firebase init`. Anyone with the project ID can dump every collection. Made HN multiple times.
- **`request.time < timestamp.date(2026, 6, 1)`** — Firebase generates this in test mode. Expires on a date but is wide-open BEFORE that date.
- **`if request.auth != null`** without ownership check — same anti-pattern as PocketBase `@request.auth.id != ""`. Any anonymous-auth user can read/write everything.
- **Read open + write closed catch-all** — devs lock writes but forget reads stay public.
- **Storage `allow read: if true`** on user uploads — exposes private files (PII docs, payment proofs).

## Install + run

Run against a local rules file (no auth needed):

```bash
npx firebase-security firestore.rules
```

With active probe (sends anonymous GET to your project's REST endpoint):

```bash
npx firebase-security firestore.rules --project-id my-firebase-project --html report.html
```

Probe-only mode (no rules file, just verify whether anonymous reads work against the deployed DB):

```bash
npx firebase-security --project-id my-firebase-project --html report.html
```

## What it checks

| # | Check | Severity |
|---|---|---|
| 1 | `match /{document=**}` with `if true` (the infamous wide-open pattern) | **CRITICAL** |
| 2 | `if true` literal anywhere in rules | **CRITICAL** |
| 3 | `if request.auth != null` without ownership check | HIGH |
| 4 | Test-mode timestamp rule (open until expiry date) | HIGH |
| 5 | Catch-all read open + write closed | MEDIUM |
| 6 | Storage rules with open read on user uploads | HIGH |
| 7 | Missing explicit default-deny block | INFO |

Each finding ships with a fix snippet you paste back into `firestore.rules`.

## Active probe

The probe sends an unauthenticated GET to:

```
https://firestore.googleapis.com/v1/projects/{project-id}/databases/(default)/documents
```

If documents come back, the project's default DB is leaking and the finding is `confirmed: true` with document count + bytes returned + sample paths.

`--no-probe` disables the network call.

## How to find your project ID

In the Firebase console: **Project Settings → General → Project ID** (looks like `my-app-1a2b3` or whatever you named it).

The probe only sends an unauthenticated GET — same thing any random visitor with your project ID could send. We don't need (or want) your service account key.

## Output

- **HTML report** — Tailwind + Chart.js, ~25KB self-contained. Top banner shows X of Y suspected leaks confirmed live.
- **JSON** — full structured findings (default stdout if no `--html`).

## License + source

MIT. Open source: https://github.com/Perufitlife/firebase-security-skill

For the BaaS family, see:
- Supabase: https://github.com/Perufitlife/supabase-security-skill
- PocketBase: https://github.com/Perufitlife/pocketbase-security-skill
- Appwrite: https://github.com/Perufitlife/appwrite-security-skill
- Hasura/Nhost: https://github.com/Perufitlife/nhost-security-skill
