# PhishGuard

A phishing **link and email** checker that shows its work, protects the whole org from
one person's report, and covers the India-specific scams global tools miss.

It is a working application, not a mockup: **79 passing tests**, live RDAP/DNS/TLS
lookups, real DKIM verification, real BEC and bank-fraud detection.

```bash
./run.sh                           # macOS/Linux
run.bat                            # Windows (double-click)
# → http://localhost:8000
```

New to this? **See [RUN-LOCAL.md](RUN-LOCAL.md)** — laptop setup, troubleshooting table, and
what to check before pointing it at real mail.

---

## UI

A public-first product landing page, then a signed-in workspace with persistent
navigation, evidence-first verdicts, a receipt drawer, a near-black magenta/violet/blue
visual system, and a mobile layout that holds up at 390 px. The workspace sidebar can be
hidden when it isn't needed.

![PhishGuard link verdict](docs/screenshot-link.png)

**Structure**
- **Public landing page** — explains link checks, email forensics, reputation keys,
  safe-preview behavior, evidence receipts, and current limitations before sign-in.
- **Workspace sidebar** — routes (Overview / Saved scans / Check a link / Check an email /
  Campaigns), recent checks persisted in `localStorage`, and a hide/show control.
- **Verdict hero** — score gauge, plain-language headline, categorical evidence strength
  (not a statistically calibrated probability), honesty chips (`naming evidence only —
  payload not observed`, `degraded — lexical only`), and a facts strip (domain, age, DNS,
  TLS, intel).
- **Progressive rendering** — skeleton → instant lexical verdict → full corroboration,
  with a five-stage pipeline that lights up as each stage completes.
- **Evidence chain** — severity rail per signal, weight + category metadata, filter
  chips (all / critical / high / medium / low), and the teach-in-the-moment line.
- **Email view** — auth pills (SPF/DKIM/DMARC/ARC colour-coded, `none` ≠ `fail`),
  identity diff that flags Reply-To and Return-Path mismatches, links table with
  per-link *Deep scan*, attachment flags, payment identifiers with the trusted-baseline
  note, and Report → sweep.
- **Receipt drawer** — the audit JSON in a scrollable, copyable sheet.
- **Org sweep** — four KPI tiles (₹ value protected is the first one), campaign cluster
  cards with reports/clicked counts.

**Interaction**
- `/` or `⌘K` focuses the URL field · `1` `2` `3` jump between views · `Esc` closes the drawer.
- Drag-and-drop `.eml`, or paste raw source.
- Sample buttons for instant evaluation, no typing.
- Toasts for every async outcome; nothing fails silently.

**Design tokens** live at the top of `public/static/style.css` (`--danger`, `--warn`, `--ok`,
surfaces, radii, shadows) with a full `[data-theme="light"]` override — change the accent
in one place and the whole app follows. No external fonts, CSS or JS: the app renders
identically inside a sandboxed preview iframe and offline.

**Accessibility**
- Semantic `nav`/`main`/`aside`, `aria-current` on the active route, `aria-pressed` on
  toggles, `aria-live` on both result regions, labelled icon-only buttons, visible
  `:focus-visible` rings, and a `prefers-reduced-motion` kill switch.
- Colour is never the only carrier: every severity also has a text badge.

---

## What makes it different (and why that's sensible)

| Differentiator | Why it matters | Where it lives |
|---|---|---|
| **Compromised-sender / bank-change detection** | The dominant loss vector is a *real* account sending a *real* invoice with changed account details. Globally clean reputation, zero blocklist hits — blocklist tools cannot see it by design. | `store.check_vendor_account`, `emailscan._extract_accounts` |
| **Trusted-baseline rule** | A bank value taken from an unverified message never becomes the baseline. Otherwise one fraudulent invoice poisons the reference and the *second* attempt looks clean — exactly how double-invoicing fraud wins. | `store.py` |
| **Pre-click "blast radius"** | Not "is it bad" but "here's what happens if you click": login form, where the password POSTs, redirect chain. A demonstrated consequence beats a red icon. | `net.fetch_page`, `urlscan._preview_signals` |
| **Server-side preview, SSRF-guarded** | The user's browser never touches the hostile host. Private/loopback/metadata targets are refused, JS is never executed, nothing is submitted. | `net.is_public_host` |
| **Report-to-sweep** | Email reports cluster by message/link signals; standalone link reports cluster by normalized host/path and warn workspace members. Link reports retain the host plus a fingerprint—not query strings or fragments. | `store.add_report`, `/api/report`, `/api/report/url` |
| **Time-of-click re-check** | Links are clean at delivery and hostile by lunchtime. Every URL is fingerprinted; if it flips from clean to bad, that is itself a signal. | `store.check_url_snapshot` |
| **First-contact / org baseline** | Scores against *your* normal instead of a global feed — the structural fix for the false-positive problem that gets tools switched off. | `store.observe_domain/sender` |
| **A real "Unknown"** | If infrastructure can't corroborate, the answer is "unverified", not a green tick. A shortener we can't expand is `unknown` by construction. | `verdict.judge(force_unknown=…)` |
| **Verdict receipts** | Every verdict exports the exact signals, weights and thresholds that produced it. Defensible in an incident review, not just a red light. | `verdict.build_receipt`, `/api/receipt/<id>` |
| **India-first corpus** | UPI collect-request fraud, KYC-expiry, electricity-disconnection, digital arrest, fake courier/customs, part-time task scams, loan apps, fake govt schemes, IRCTC, IFSC/VPA abuse. | `data.INDIA_RULES` |
| **Teach-in-the-moment** | Every signal carries the transferable lesson, so the checker trains people on real attacks they actually received. | `data.TEACH`, `verdict._tips` |
| **Progressive verdicts** | Lexical answer in ~5 ms, corroboration streams in. A slow checker gets bypassed. | `/api/check/url?mode=quick` then `mode=full` |
| **Never clickable** | Every URL is defanged (`hxxps://evil[.]com`). | `lexical.defang` |
| **BYO-key, privacy-first reputation** | Google Safe Browsing v5, VirusTotal, URLhaus, and PhishTank are optional signals. URL sharing is opt-in per full scan; unavailable/no-match providers never clear a URL as safe. | `intel.py`, `urlscan.py` |

---

## Architecture

```
app.py                  Flask routes: /api/check/url, /api/check/email, /api/report,
                        /api/clusters, /api/receipt/<id>, /api/vendor/confirm, /api/sample/<n>
engine/
  data.py               knowledge base: 180+ brands, legit-domain allowlist, TLD abuse,
                        homoglyphs, BEC lexicon, India scam corpus, teach-lines
  lexical.py            no-network URL analysis (the fast half of every verdict)
  net.py                SSRF-guarded fetch, RDAP domain age, DNS, TLS, HTML parsing
  intel.py              Safe Browsing v5, VirusTotal, URLhaus, PhishTank (optional keys)
  mailer.py             optional low-volume Mailjet API delivery for OTPs and summaries
  push.py               optional VAPID Web Push delivery
  urlscan.py            orchestration: lexical → infrastructure → consented reputation → preview
  emailscan.py          SPF/DKIM/DMARC, Received-chain, BEC, India rules, attachments
  verdict.py            scoring, confidence, the honest "unknown", receipts
  store.py              SQLite/Postgres: baselines, auth, OTPs, subscriptions, clusters
templates/index.html    single-page UI (vanilla JS, no build step)
public/static/style.css
samples/*.eml           4 demo messages (3 attacks, 1 clean control)
tests/test_engine.py    40 tests, dominated by false-positive assertions
scripts/seed_demo.py    seeds vendor baselines + report clusters
```

### Verdict model

1. Every signal = `{id, severity, weight, evidence, category, tip}`.
2. Score = weighted sum with **positional decay** (1.0, 0.75, 0.6, …) so one critical
   signal is not diluted by ten weak ones, and ten weak ones can't add up to "malicious".
3. Tier: `≥65 malicious · ≥30 suspicious · ≥12 low · else safe`.
4. Independent signal categories agreeing can raise evidence strength. Without
   infrastructure data, confidence stays `low`; thin evidence may be labelled
   `unknown` rather than cleared. A decisive signal can still produce a warning
   while corroboration is unavailable.
5. Everything is written to an audit receipt.

The score is a rule-based risk indicator, not a probability. Evidence-strength
categories are qualitative heuristics, not calibrated likelihood estimates.

---

## What it does on real inputs

| Input | Verdict | Score |
|---|---|---|
| `paypal.com.secure-login-verify.top/account/verify` | malicious — brand in subdomain, high-abuse TLD | 76 |
| `hdfcbank.com.secure-verify.top/kyc` | malicious — brand in subdomain + lure path | 66 |
| `paypa1.com/login` | suspicious→malicious — digit substitution | 48 |
| `microsoft.com@evil-login.ru` | brand in userinfo decoy → critical | 42 |
| `inv…pdf.exe` | critical — double extension | 42 |
| `javascript:…` / `data:…` | critical — dangerous scheme | 40 |
| `bit.ly/…` (unexpandable) | **unknown**, not safe | 37 |
| `google.com`, `sbi.co.in`, `icicibank.com`, `incometax.gov.in`, `amazonaws.com` | likely safe | 0–2 |
| BEC sample: DMARC fail + Reply-To swap + bank change + `.docm` | malicious, strong corroboration | 100 |
| India UPI/KYC sample | malicious, strong evidence | 94 |
| Digital-arrest sample | malicious, strong evidence | 100 |
| Clean internal mail | likely safe | 0 |

---

## Steps to run it

### Secure account login

The dashboard has separate Create account and Log in screens. New accounts save a
unique username, an optional Gmail address, a normalized Indian mobile number, and
a one-way password hash. During signup, the user also chooses a password recovery
question and answer. The answer is normalized and stored only as a one-way hash.
Passwords are never saved as plain text. Successful login creates an HttpOnly,
SameSite session cookie. Failed logins are rate-limited for 15 minutes.

The login screen includes **Forgot password?**. A user can either answer the
saved recovery question or request a one-time code sent to their verified email
address. Email codes expire after 10 minutes; delivery requires the optional
server-side email provider configuration. Recovery attempts and code requests are
rate-limited. A successful reset revokes older login sessions and signs the user
in on the current device. The recovery question is a convenient alternative, not
proof of email or mobile ownership. Existing accounts without a recovery question
can add one from Settings after confirming their current password.

#### Optional Google sign-in

The login screen can also use Google OpenID sign-in. It requests only `openid`,
`email`, and `profile`; it does not ask for access to Gmail, Drive, or other Google
data, and the basic OAuth sign-in flow does not require a paid Google API plan. A
verified Google email links to an existing PhishGuard account with that email, or
creates a new account. New Google accounts receive an automatically generated
PhishGuard username and can add other profile details later. PhishGuard stores the
Google account identifier and verified email, not Google access or refresh tokens.

To configure it:

1. In Google Cloud Console, create/select a project and configure the OAuth consent
   screen (Google Auth Platform). For initial testing, add your Google account as a
   test user if the consent screen is in Testing mode.
2. Create an OAuth Client ID with application type **Web application**.
3. Add these **Authorized JavaScript origins**:
   - Production: `https://phisguard-five.vercel.app`
   - Local Docker (optional): `http://localhost:8000`
4. Add these **Authorized redirect URIs**:
   - Production: `https://phisguard-five.vercel.app/auth/google/callback`
   - Local Docker (optional): `http://localhost:8000/auth/google/callback`
5. Copy the Client ID and Client Secret into the server environment—never into
   browser code or a message. On Vercel, add new `GOOGLE_CLIENT_ID`,
   `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, and `FLASK_SECRET_KEY` environment
   variables for Production. Set `GOOGLE_REDIRECT_URI` to the Production callback
   above. Generate a long random `FLASK_SECRET_KEY` locally, for example with
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Do not change any
   Neon-managed database variables.
6. For local Docker, put the same Client ID/Secret and a separate stable Flask
   secret in your uncommitted `.env`; set `GOOGLE_REDIRECT_URI` to the localhost
   callback. Then restart with `docker compose up -d --build`.

The Google button appears on the login and registration screens. If server
credentials are missing, sign-in safely returns to the login screen with a setup
message. Keep `.env` out of Git. `FLASK_SECRET_KEY` must remain stable across
restarts so the short-lived OAuth state/nonce can be checked when Google returns.

#### Optional Microsoft sign-in

The same login and registration screens also support Microsoft OpenID Connect for
work/school and personal Microsoft accounts. It requests only `openid`, `profile`,
and `email`; it does not request Microsoft Graph access. Register a Microsoft Entra
Web application with this redirect URI:

- Production: `https://phisguard-five.vercel.app/auth/microsoft/callback`
- Local Docker: `http://localhost:8000/auth/microsoft/callback`

The optional server-side settings are `MICROSOFT_CLIENT_ID`,
`MICROSOFT_CLIENT_SECRET`, `MICROSOFT_REDIRECT_URI`, and `MICROSOFT_TENANT_ID`
(`common` allows personal and work/school accounts; a tenant ID can restrict access).
Keep client secrets server-side and leave integration-managed database settings
unchanged. Microsoft email and preferred-username claims are not assumed to be
verified: PhishGuard never links a Microsoft identity to an existing account just
because the addresses match. An email is retained only if Microsoft explicitly
marks it verified; otherwise sign-in still works, but email-based recovery is not
available for that account.

Copy `.env.example` to `.env`. Keep `AUTH_COOKIE_SECURE=0` for local HTTP use and
set it to `1` when serving through HTTPS. Mobile numbers are format-validated only;
phone ownership is not verified because PhishGuard does not send SMS codes. Email
verification and email password-reset codes are separate, optional email features.

The top-right profile menu shows the active username and mobile number, opens
settings, and provides Add account and Log out actions. The **Privacy &
authentication** section can add/change the Gmail address, mobile number, or
password. Every sensitive change requires the current password; changing the
password signs out other sessions. Multiple accounts can be
remembered on one browser by username only; switching accounts logs out the
current session and requires the selected account's password.

Settings opens with a choice-first hub: **Profile**, **Security**, **Notifications**,
**Privacy & data**, **Appearance**, and **Device & accounts**. Selecting a category
shows only its relevant controls. Security actions are progressive: choose an
account-security group, then choose a specific action such as updating Gmail or
mobile, changing a password, managing a recovery question, or reviewing login
activity. Privacy & data includes export, clearing personal activity, and
password-confirmed account deletion. Clearing personal data keeps the account and
security login history; deleting the account removes the account and its personal
activity permanently. Browser notifications can be enabled for completed scans, with optional sound.
Foreground notifications work while the app is open; optional VAPID Web Push can
also deliver scan alerts and weekly aggregate cluster notices when the site is closed.

The public landing page is shown before sign-in. The signed-in **Overview** page
shows recent checks on this device, saved scans, items flagged for review, and
clear next actions—there is no speculative account or website security score.
Link and email verdicts can be saved into named folders from the **Saved scans**
library. Saved scans are kept per username in that browser's local storage;
passwords and session tokens are never stored there.

The visual system uses a near-black base with magenta, violet, and blue accents.
The appearance control switches between the standard and soft-contrast treatments.

Gmail is optional during registration. An account can add an address later from
Settings → Sign-in & security and verify it with a one-time code when email delivery
is configured. A verified address can be used for password recovery and opted-in
notifications. Existing accounts are upgraded without requiring an email address.

Profile settings also support customizable display name and initials, notification
preferences, last password-change information, recent login history with browser,
operating system and IP address, personal JSON data export, and password-confirmed
account deletion. Profile and authentication fields are migrated automatically for
existing databases.

### Help guide

The sign-in screens and workspace include a built-in, app-scoped Help Guide. It selects
answers from a PhishGuard FAQ about account creation and recovery, settings, link and
email checks, saved data, and optional reputation signals. Common synonyms, fuzzy
word matching, and everyday descriptions help it understand less exact phrasing. If
a question is too vague, it asks what you mean and offers tappable sample questions.
It is not a cloud-hosted generative LLM: questions are not sent to an AI or web-search
provider, and no AI API key or paid service is required. Pre-login questions are not
saved to account help history. Out-of-scope questions get a refusal rather than a
general answer. The rest of PhishGuard can still use the internet for user-requested checks.

### 1. Local (2 minutes)
```bash
cd phishguard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 scripts/seed_demo.py --reset     # demo vendor baseline + report clusters
python3 app.py                           # or ./run.sh
```
Open <http://localhost:8000>, then:
- **Check a link** → paste `http://paypal.com.secure-login-verify.top/account/verify`
- **Check an email** → *load sample: BEC bank-change* → note the critical
  "Bank details CHANGED vs this vendor's previous invoice"
- **Org sweep** → see value protected + campaign clusters

### 2. Optional reputation keys

Set provider keys only in server-side environment variables (`.env` locally or the
Vercel project settings). The local PhishGuard engines remain primary. The optional
Google Safe Browsing v5, VirusTotal, URLhaus, and PhishTank checks are additional
signals; unavailable providers and no-match responses do not establish safety.
Full scans ask for explicit per-scan consent before sending a URL to whichever
providers have been configured. Quick scans never make those calls. Review each
provider's non-commercial terms, rate limits, and data-retention rules before use.

```bash
cp .env.example .env
# Set only the keys for providers you choose to enable:
GSB_API_KEY=
VT_API_KEY=
URLHAUS_AUTH_KEY=
PHISHTANK_APP_KEY=
```

Missing keys are normal: the rest of PhishGuard continues to work without them.

### 3. Optional Mailjet email and background push

Mailjet delivery stays off until the server-side API key, secret key, and verified
sender address are configured. Email is limited to password-reset / address-verification
codes and an opt-in monthly summary of an account's flagged domains. Immediate scan
emails, weekly campaign emails, marketing, full URLs, and submitted email contents are
not sent. Monthly scan storage is opt-in, stores only the account, month, domain, scan
type, verdict, score, and count, and is deleted when the user turns the setting off or
deletes the account. Each domain is aggregated to one row per account per month.

```text
MAILJET_API_KEY=<Mailjet API key>
MAILJET_SECRET_KEY=<Mailjet secret key>
MAILJET_FROM_EMAIL=<sender address verified in Mailjet>
MAILJET_FROM_NAME=PhishGuard
CRON_SECRET=<long random value for scheduled Vercel jobs>
```

Keep the API and secret keys server-side only; never put them in browser code, a
`.env` committed to Git, or a message. A Gmail sender can be verified in Mailjet,
though sender-domain alignment may improve deliverability. Users must verify their
Gmail address before receiving password-reset codes or monthly summaries. The monthly
summary runs on the first day of each month and reports the previous month's flagged
domains; it is skipped when there are no flagged domains. Code requests retain their
existing per-address/IP and global rate limits.

For background browser notifications, generate one VAPID key pair and configure
`VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, and `VAPID_SUBJECT` (for example,
`mailto:your-sender@gmail.com`). With project dependencies installed, this prints
a matching base64url key pair locally:

```bash
python - <<'PY'
from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid
from py_vapid.utils import b64urlencode
v = Vapid()
v.generate_keys()
private = v.private_key.private_numbers().private_value.to_bytes(32, "big")
public = v.public_key.public_bytes(serialization.Encoding.X962,
    serialization.PublicFormat.UncompressedPoint)
print("VAPID_PRIVATE_KEY=" + b64urlencode(private))
print("VAPID_PUBLIC_KEY=" + b64urlencode(public))
PY
```

Treat the private key output as a secret and set it only server-side. Users subscribe
per browser; disabling browser notifications removes that device's subscription.
No paid push vendor is required. Vercel Cron sends weekly browser-push campaign notices
and runs the opted-in flagged-domain email summary once a month; both jobs share the
server-side `CRON_SECRET`.


### 4. Deploy with Docker (the recommended way to keep a stable link)

Docker runs the Flask application as one service: it serves the UI and `/api/*`
backend from the same origin, so no browser-side localhost API address or CORS setup
is needed. A named Docker volume keeps the local SQLite database—including accounts
and scan history—across container rebuilds and restarts. The port is bound to your
laptop only by default; the token-secured hosted preview link does not apply inside
a container.

```bash
cd phishguard

# build once (~40s, deps are layer-cached)
docker build -t phishguard:0.9.0 .

# run it
docker run -d --name phishguard \
  -p 127.0.0.1:8000:8000 \
  -v phishguard-data:/app/data \
  --restart unless-stopped \
  phishguard:0.9.0

# open
#   → http://localhost:8000
```

Check it came up cleanly:

```bash
docker logs -f phishguard          # entrypoint seeds the DB, then gunicorn access log
docker ps --filter name=phishguard # wait for STATUS: healthy
curl -s localhost:8000/api/health  # {"ok":true,...}
```

**With docker compose** (handles the volume, healthcheck and env for you):

```bash
docker compose up -d --build
docker compose logs -f
docker compose down          # stops app; named volume retains accounts and history
```

**Optional reputation keys:**

```bash
docker run -d --name phishguard -p 127.0.0.1:8000:8000 -v phishguard-data:/app/data \
  -e GSB_API_KEY=your-key -e VT_API_KEY=your-key \
  -e URLHAUS_AUTH_KEY=your-key -e PHISHTANK_APP_KEY=your-key \
  phishguard:0.9.0
```

or put them in a `.env` next to `docker-compose.yml` and use `docker compose up -d`.

#### What the container does on start (`docker-entrypoint.sh`)

1. Ensures `/app/data` is writable by the unprivileged user (uid `10001`). If a
   host bind-mount is root-owned it falls back to `/tmp` **and says so loudly**,
   rather than dying with sqlite's “unable to open database file”.
2. Seeds demo baselines/clusters only when no database exists yet, so restarts keep
   your real data.
3. Prints whether reputation keys were detected (`BYO-key` mode is fully functional).
4. `exec`s gunicorn (2 workers × 8 threads) — no shell wrapper left holding PID 1.

#### Docker troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `port is already allocated` | something already on 8000 | use `PHISHGUARD_PORT=8080 docker compose up -d --build`, then open `localhost:8080` |
| Page loads, banner says *falling back to /tmp* | root-owned bind mount | `mkdir -p ./data && sudo chown -R 10001:10001 ./data`, then mount `-v "$PWD/data:/app/data"` |
| `unhealthy` but the page works | healthcheck hits `127.0.0.1` inside the container | confirm you didn't override `PORT` — if you did, pass the same value to the healthcheck |
| Lookups (domain age, DNS) are empty | container has no outbound network | check the daemon's DNS/proxy policy; the app degrades to lexical-only and labels it |
| `exec format error` on Apple silicon | image built for another arch | `docker build --platform linux/amd64 -t phishguard .` (or build natively on the Mac) |
| Data gone after `docker rm` | ran without the volume | always pass `-v phishguard-data:/app/data` |

**Not exposed to the internet.** The container binds `0.0.0.0` inside, but you only
publish it to your host. To share it on a LAN, publish to all interfaces
(`-p 0.0.0.0:8000:8000`) and reach it at `http://<your-ip>:8000` — and put an
authenticating reverse proxy in front of it first, because there is no login by design.


### 5. Make it yours
- Add brands to `engine/data.py → BRANDS` and, crucially, real ones to `LEGIT_DOMAINS`
  (the allowlist is what keeps false positives at zero).
- Add local scam patterns to `INDIA_RULES` — `{id, pattern, title, evidence, weight, tip}`.
  Then run the tests; `test_india_rules_have_all_fields` forces the documentation fields.
- Add a teach-line to `TEACH` for every new signal id you introduce.
- Wire `POST /api/report` from your mail gateway so reporting happens before anyone clicks.
- Feed `report.json` clusters into your SIEM/SOAR; `GET /api/receipt/<id>` is the artifact.

### 6. Production operations and future research

PhishGuard is already deployed on Vercel with persistent Postgres, authenticated
accounts, rate-limited recovery, security headers, and isolated Preview database
configuration. Use the beginner-friendly [Production readiness checklist](docs/PRODUCTION-READINESS.md)
for routine, read-only checks. Do not reset or seed the live database.

For a larger organizational deployment, the remaining research/engineering work is
separate: independently evaluate detection precision/recall against representative
benign and malicious datasets; broaden adversarial coverage (cloaking, delayed
payloads, QR codes, and `.msg`); and review data-retention requirements with the
operators. Those are not prerequisites for the current personal, non-commercial
production site.

---

## Deliberate non-features

- **No opaque risk score.** Scores derive from named, weighted, auditable signals.
- **No JS execution or form submission** in the preview. It reads HTML and describes it.
- **No AI chat bubble.** An evidence chain with citations beats a paragraph of prose.
- **No silent green ticks.** Degraded mode is labelled every time.

## Known limits (stated, not hidden)

- `.eml` only; `.msg` needs one more parser.
- Images/QR codes are not decoded (attachment hashes are reported instead).
- The public-suffix list is deliberately small and India-heavy — swap in the full PSL for
  wider coverage.
- Preview is a single HTML GET; it will not catch JS-only or logged-in gating.
- SQLite is fine for a desk/team; move to Postgres for multi-tenant use.

## Deploy to Vercel

Vercel's serverless filesystem is temporary, so the live app requires a persistent
Postgres database (for example, Neon connected through Vercel Marketplace). The
integration supplies its database connection variables; **do not manually edit,
remove, or rotate integration-managed Neon variables**. The app keeps SQLite as its
local-development default and uses Postgres when a supported database URL is present.
If the database is not configured, the Vercel function returns a setup-required
response rather than storing account data in ephemeral storage.

Static browser assets are in `public/static/`, which Vercel serves as static public
files through its edge CDN at the existing `/static/*` paths. The Flask app is also
configured to serve the same directory locally, and `/sw.js` remains a Flask route
for the service worker's root-scope response header. This does not move the API,
Python runtime, or persistent database.
