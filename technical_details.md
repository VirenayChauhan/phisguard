# PhishGuard Technical Reference

> **Purpose:** coder-facing map of the current PhishGuard implementation, its UI, analysis engines, persistence, security boundaries, and deployment. Treat the source files as authoritative when behavior changes.
>
> **Snapshot:** branch `arena/80a1b848-phisguard`, source commit `b7e7ac0` (November 2026). This document describes the PhishGuard implementation as it stands in November 2026.

## Contents

1. [Product and architecture](#1-product-and-architecture)
2. [Repository map](#2-repository-map)
3. [Runtime and request lifecycle](#3-runtime-and-request-lifecycle)
4. [Frontend and UI construction](#4-frontend-and-ui-construction)
5. [URL analysis pipeline](#5-url-analysis-pipeline)
6. [Email analysis pipeline](#6-email-analysis-pipeline)
7. [Verdict and evidence model](#7-verdict-and-evidence-model)
8. [Backend API reference](#8-backend-api-reference)
9. [Authentication and account security](#9-authentication-and-account-security)
10. [Persistence and data model](#10-persistence-and-data-model)
11. [External services and configuration](#11-external-services-and-configuration)
12. [Deployment and operations](#12-deployment-and-operations)
13. [Tests and development workflow](#13-tests-and-development-workflow)
14. [Known implementation constraints and improvement guide](#14-known-implementation-constraints-and-improvement-guide)

---

## 1. Product and architecture

PhishGuard is a same-origin Flask application for analyzing suspicious URLs and raw email messages. It is not a separate JavaScript SPA plus API service: Flask serves the HTML template and JSON endpoints from one origin, while Vercel can serve files from `public/` through its static edge CDN. Locally, Flask serves those same assets from `public/static/` at the unchanged `/static/*` URLs. The browser UI is written in vanilla JavaScript and CSS; there is no frontend package manager, transpiler, bundler, or client-side framework.

The backend combines deterministic local analysis with optional network corroboration. Its design goals are:

- Give an immediate URL-structure result, followed by a fuller corroborated result.
- Show the signals and evidence behind a result instead of returning only a red/green badge.
- Preserve `unknown` as a valid result when data is insufficient; provider no-match is not a safety guarantee.
- Keep untrusted page fetching on the server, with destination checks and JavaScript disabled.
- Parse email source in memory and surface authentication, identity, link, attachment, business-email-compromise (BEC), and India-specific scam clues.
- Persist account/auth state, selected scan evidence, baselines, receipts, and report clusters in SQLite for local use or PostgreSQL for hosted use.
- Make optional integrations fail/degrade without preventing the core lexical/email analysis.

### Major request paths

```text
Browser
  ├─ GET /, /login, /ui-trial
  │    └─ Flask → templates/index.html
  ├─ GET /static/*
  │    ├─ Vercel static edge CDN in deployment
  │    └─ Flask app.static_folder locally / fallback
  └─ same-origin fetch('/api/...')
       └─ app.py route/auth gate
            ├─ engine/auth.py       account and session operations
            ├─ engine/urlscan.py    URL orchestration
            │    ├─ lexical.py      deterministic, no-network URL signals
            │    ├─ net.py           guarded DNS/RDAP/TLS/page inspection
            │    ├─ intel.py         optional reputation providers
            │    ├─ store.py         baselines/snapshots/receipts
            │    └─ verdict.py       score, label, confidence, evidence
            ├─ engine/emailscan.py  RFC email parsing and signal extraction
            ├─ engine/assistant.py  offline FAQ answer selection
            └─ engine/store.py      SQLite/PostgreSQL persistence
```

### Trust boundaries

- The browser submits URL/email input to PhishGuard's own Flask origin. The app's server performs URL intelligence and page fetches; the browser does not fetch a submitted destination.
- Email text and MIME parts are parsed by Python. The scanner does not execute attachments or email HTML JavaScript. Attachments are represented by metadata/hash and risk flags, not executed.
- Third-party URL reputation is optional and is separately gated by the user's per-scan sharing checkbox in the full URL flow.
- The server database is separate from browser `localStorage`. Some convenience UI state and saved scan payloads are browser-local; see [Browser storage](#browser-storage-and-retention).
- Environment variables and API keys are read server-side. Do not place integration secrets in HTML, JavaScript, CSS, or this document.

---

## 2. Repository map

```text
app.py                         Flask app, route handlers, auth gate, response headers
api/index.py                   Vercel Python-function entry point / database setup guard
engine/
  assistant.py                 Offline PhishGuard FAQ matcher and rate limit
  auth.py                      Account validation, password/session/OTP/OAuth operations
  data.py                      Static detection knowledge base and teach-in-the-moment tips
  database_config.py           Selects database URL for Production vs Preview vs local
  emailscan.py                 RFC email parsing, BEC, auth, links, attachments, bank-change
  intel.py                     Optional Safe Browsing, VirusTotal, URLhaus, PhishTank clients
  lexical.py                   URL normalization and deterministic structural signals
  mailer.py                    Optional Mailjet HTTPS sending
  net.py                       DNS, RDAP, TLS and SSRF-guarded page fetch/parsing
  push.py                       Optional VAPID/Web Push support
  store.py                      Schema, SQLite/PostgreSQL adapter, data access functions
  urlscan.py                    Quick/full URL-analysis orchestration and public result shaping
  verdict.py                    Signal aggregation, label/confidence, next steps, receipts
templates/
  index.html                    Single Jinja template for landing, login, trial and workspace
public/static/
  app.js                        Frontend state, client routing, forms, API calls, renderers
  style.css                     Base tokens and shared workspace/auth components
  landing.css                   Public landing-page layout and effects
  spectrum-theme.css            Palette and theme overrides
  depth-scene.js                Lazy Three.js scenes and cursor spotlight/virus reveal
  depth.css                     Depth/3D CSS enhancements
  amber-theme.css               Shared amber/Geist token layer
  brand-refresh.css             Brand and auth visual layer
  workspace-polish.css          Workspace refinements
  motion.css                    Shared motion and reduced-motion rules
  mobile-workspace.css          Narrow viewport workspace adjustments
  google-auth.css               Google sign-in component styling
  theme-picker.css              Appearance/theme selector styling
  ui-trial.css                  Isolated `/ui-trial` presentation
  sw.js                         Push notification display/click behavior
  phisguard-logo.png            Local product mark
  vendor/                       Locally bundled Three.js modules and license
samples/                        Four sample .eml files for demonstration/tests
scripts/seed_demo.py            Optional local demonstration database seed
 tests/                         unittest coverage by subsystem/feature
requirements.txt                Python runtime dependencies
vercel.json                     Vercel function duration and scheduled cron routes
Dockerfile, docker-compose.yml  Container image and persistent named data volume
.env.example                    Names and comments for optional/runtime configuration
RUN-LOCAL.md                    Human-oriented Python/Docker setup
README.md                       Product, local-run, UX and feature overview
```

`templates/index.html` is intentionally one large document: Flask renders the same DOM contract for multiple states, and `public/static/app.js` hides/shows the public landing page, auth panel, and dashboard. Keep IDs referenced by JavaScript stable when editing markup.

### Static-asset delivery boundary

Browser assets live in `public/static/`, Vercel's static-public directory, and keep their existing `/static/*` URLs. In a Vercel deployment, these public files are static outputs available through Vercel's edge CDN; they do not need to run through the Flask Python function. `app.py` also points Flask's `static_folder` at `public/static` and sets `static_url_path="/static"`, preserving the same asset URLs for local Python/Docker use and a Flask fallback. The API routes, HTML routes, runtime, and persistent database are unchanged. No separate CDN vendor, bucket, or environment variable is needed. `/sw.js` deliberately remains a Flask endpoint so it can set the `Service-Worker-Allowed: /` header for root scope.

---

## 3. Runtime and request lifecycle

### Flask application startup

`app.py` constructs the Flask application, loads `.env` locally when `python-dotenv` is installed, configures request-size and cookie settings, registers Authlib's Google OIDC client, and imports the `engine` modules. Database schema creation is lazy: importing the app and rendering a static page does not call `store.init()`. The first data operation initializes the schema for the active database configuration.

The root process supports:

```bash
python app.py                 # Flask development server, 0.0.0.0:8000 by default
PORT=8000 python app.py       # explicit port
```

The Docker command uses Gunicorn rather than Flask's development server. Vercel invokes the Flask object via `api/index.py`.

### Request middleware order

1. `start_request_timer` records a monotonic start time in Flask `g`.
2. `require_authentication` applies to `/api/*` paths:
   - The explicit `PUBLIC_API_PATHS` remain reachable without a PhishGuard login.
   - `/api/assistant` has a special pre-login offline-FAQ path; authenticated mutations still require the request header described below.
   - Other API calls require a valid `pg_session` or `__Host-pg_session` cookie.
   - Authenticated `POST`, `PUT`, `PATCH`, and `DELETE` calls require `X-Requested-With: XMLHttpRequest`.
3. Route logic runs, then `headers` adds security/diagnostic response headers.

The response layer currently adds `Server-Timing: app;dur=<ms>`, an endpoint/method/status/app-time log line, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a restrictive Content Security Policy, and `Cache-Control: no-store` for API responses. HSTS is added when `AUTH_COOKIE_SECURE` is enabled.

The timing measures time inside the Flask request, not browser download/render time or full Vercel queue/cold-start time. Request logs deliberately avoid URL query values and user payloads.

### Web entry routes

- `GET /` — public landing page; the dashboard is initially hidden until a session check succeeds.
- `GET /login` — same template with the login/auth section initially shown.
- `GET /ui-trial` — same template with the editorial split-screen trial state.
- `GET /auth/google/start`, `GET /auth/google/callback` — optional OIDC flow.
- `GET /sw.js` — serves the service worker with root scope and no-cache behavior.
- `api/index.py` returns a setup-required JSON `503` if running on Vercel without the required persistent database URL; otherwise it imports `app.app`.

---

## 4. Frontend and UI construction

### Page composition and view model

The browser receives `templates/index.html`, which contains these top-level modes:

1. **Landing page (`#landing-page`)** — masthead, hero with account CTAs, and capabilities information/cards.
2. **Auth (`#auth-screen`)** — login, create-account, recovery, email verification, and Google sign-in states.
3. **Workspace (`#dashboard`)** — sidebar, top bar, and five hash-routed views:
   - `#view-overview`
   - `#view-saved`
   - `#view-link`
   - `#view-email`
   - `#view-sweep`
4. Shared panels: Help Guide dialog, account/settings panel, receipt drawer, scrims, and toast region.

The Flask render flags determine the initial visibility for `/`, `/login`, and `/ui-trial`. `public/static/app.js` then calls `checkSession()` and selects landing/auth/workspace based on the cookie-backed `/api/auth/session` result. A successful login enters the dashboard client-side; it does not require a separate frontend build or a second API host.

### Client-side implementation

`public/static/app.js` is a classic script loaded at the end of the document, after its DOM. It uses small DOM helpers (`$`, `$$`), a central `api()` wrapper, `postJSON()`, and HTML escaping (`esc()`) for data inserted into render strings. It binds form/button handlers and renders result cards with template strings. Do not interpolate untrusted API/user data without `esc()`; the scanner UI intentionally has many dynamic result fields.

Client routing is in `ROUTES` and `go(route)`. It toggles `.view` visibility, updates the active navigation's `aria-current`, title and breadcrumb, handles route-specific refreshes, writes `#overview`/`#saved`/etc. into browser history, scrolls to the top, and focuses the URL field on the link route. Keyboard shortcuts include number keys for link/email/sweep and Escape for close actions; input fields are excluded from normal shortcuts.

Major UI controller groups/functions in `app.js`:

- Auth/session: saved usernames, registration steps, login, forgot-password, switch-account, `checkSession`, `enterDashboard`, `leaveDashboard`.
- Account/settings: profile, categories, security actions, notification preferences, data export/clear/delete, login history.
- Presentation: theme selection, sidebar collapse, landing reveal timeline, toasts, assistant panel.
- Saved/recent state: recent scans, per-account saved scans/folders, overview summaries.
- URL analysis: staged pipeline, quick result, full result, evidence cards, receipt action.
- Email analysis: upload/paste/sample source, auth strip, identity, links/deep-scan, attachments, payment details, report action.
- Campaign view: `/api/clusters` and `/api/money-deterred` loading and campaign cards.

### UI states and result composition

#### Landing and sign-in

The public landing is built around a large headline, short explanation, create-account/sign-in actions, a community check count, and a below-the-fold capabilities section. The current hero uses a locally bundled Three.js animated ribbon canvas. Five small SVG digital-virus instances appear in the hero and five in the capabilities section; they share one SVG symbol and brighten/glow near the pointer. The section backgrounds are matched to avoid a hard boundary. These are decorative and are marked `aria-hidden`.

`depth-scene.js` installs cursor spotlight/reveal only when the device reports hover plus a fine pointer. Touch input does not run the cursor-reveal path. It also imports the bundled Three.js module only when the canvas approaches the viewport. A `ResizeObserver`, `IntersectionObserver`, page visibility checks, and WebGL context-loss handling control sizing and animation work. Pixel ratio is capped at `1.4`, and the canvas uses alpha transparency and low-power rendering.

The sign-in route supports a dedicated screen rather than requiring the landing section to remain visible. `/ui-trial` is a separate design experiment; keep trial-specific styles isolated from the ordinary mode.

#### Workspace navigation

- **Overview:** account greeting, start actions, scan count/status, this-device recent activity, saved scan entry points, and current next-step guidance. It is not a fabricated account-security score.
- **Saved scans:** client-local scan library with folders/filtering and open/delete operations.
- **Check a link:** URL input, sample links, optional third-party reputation-sharing checkbox, five-stage pipeline/status, result details, and save/receipt actions.
- **Check an email:** `.eml` upload or raw-source paste, built-in sample messages, and the rich email evidence renderer.
- **Campaigns:** report clusters, reports/clicked counts, estimated-value tiles, and refresh.

#### URL result cards

The result renderer composes `verdictHero`, `signalsCard`, `blastCard`, `nextStepsCard`, `infraCard`, `previewCard`, `tipsCard`, filter chips, and receipt actions. Signal filters are client-side. URL links are generally displayed defanged, and page preview outputs are shaped by the server. The result explains score/tier/confidence as evidence strength, not calibrated probability.

The link page shows an initial empty scan meter, then updates stage states (`lexical`, `infra`, `rep`, `preview`, `baseline`). On a full-scan failure it renders the quick lexical response as degraded rather than presenting it as fully corroborated.

#### Email result cards

The email renderer composes verdict, blast radius/next steps, sender identity, authentication strip, signals, extracted links, attachments, payment/account hints, tips, and report-to-sweep controls. Each extracted link can trigger its own URL analysis. A vendor-account change can be promoted only through the explicit human-confirmation endpoint after out-of-band verification.

### CSS layers, tokens and responsive behavior

Stylesheets are linked in `templates/index.html` in this order (later layers may intentionally override earlier rules):

1. `style.css` — base tokens, controls, forms, cards, auth and workspace structure.
2. `brand-refresh.css` — brand/auth details.
3. `landing.css` — landing-specific layout, hero, capabilities, and virus styling.
4. `workspace-polish.css` — workspace refinements.
5. `motion.css` — entrance/interaction motion and reduced-motion treatment.
6. `ui-trial.css` — isolated trial-screen styling.
7. `amber-theme.css` — default/shared warm accent token layer.
8. `depth.css` — 3D depth/card enhancements.
9. `spectrum-theme.css` — palette variables and UI theme variants.
10. `mobile-workspace.css` — narrow-screen workspace treatment.
11. `google-auth.css` — Google button/panel styling.
12. `theme-picker.css` — appearance picker.

The CSS token system includes background/surface levels, border strengths, text contrast, accent/accent-soft colors, severity colors (`danger`, `warn`, `ok`, `info`, `unknown`), radii, shadows, sans and monospace stacks. `public/static/spectrum-theme.css` supplies palette variants. Theme IDs handled by JS are `signature`, `violet`, `blue`, and `soft`; the legacy stored value `light` maps to `soft`. `soft` sets `data-theme="light"`; the other palettes set `data-theme="dark"` and use `data-palette` for token overrides. Despite its name, the soft theme remains a dark, contrast-oriented treatment rather than a white page.

Responsive behavior is distributed through stylesheets rather than a component framework. Important breakpoints include `1080`, `960`, `920`, `820`, `800`, `760`, `640`, `600`, `560`, `480`, `430`, `400`, `390`, and `380` pixels. Motion is reduced using `prefers-reduced-motion`; fine-pointer hover effects are restricted to hover-capable devices. Focus-visible outlines, semantic navigation/sections, ARIA labels/live regions, and non-color text badges are used in important flows.

The template currently references Geist and JetBrains Mono from Google Fonts in addition to local fallback stacks. The Flask CSP currently limits `style-src` and `font-src` to same-origin (with inline styles allowed); verify browser CSP reports if those external font requests appear blocked. Local fallbacks keep layout usable if network fonts do not load.

### Browser storage and retention

Browser storage is convenience state, not the account database:

| Key | Purpose | Scope/notes |
|---|---|---|
| `pg-saved-accounts` | Up to eight saved usernames | Device-local; usernames only, not passwords/tokens. |
| `pg-notification-settings:<username-or-guest>` | Browser alert/sound/push UI preferences | Device-local; server account preferences are separate fields. |
| `pg-theme` | Theme ID | Device-local appearance preference. |
| `pg-sidebar-hidden` | Sidebar state | Device-local layout preference. |
| `pg-recent` | Recent checks | Device-local, bounded to seven. Current paste-email flow passes the raw source string as the recent item payload, so pasted email contents can be written here. |
| `pg-saved-scans:<username>` | Saved scans and named folders | Device-local per username; not synced between devices or encrypted by this app. Explicitly saved pasted-email scans can also retain their raw source payload. |

Passwords and session tokens are not put into localStorage. The server returns a session cookie instead. Review the exact scan item payloads in `pushRecent()`/`saveScan()` before making privacy/retention claims; browser storage remains accessible to same-origin JavaScript and the browser profile owner.

---

## 5. URL analysis pipeline

The URL analyzer is split between `engine/lexical.py` (deterministic/local parsing) and `engine/urlscan.py` (orchestration/result shaping).

### Quick pass (`POST /api/check/url?mode=quick`)

1. Validate non-empty input and maximum URL string length (`4,000` characters in the route).
2. Parse/canonicalize host, registrable domain, suffix, path/query facts, and defanged display form.
3. Run local structural/lexical checks; no reputation-provider lookup, RDAP, DNS, TLS, or page-preview request is intended by quick mode.
4. Update workspace domain-observation baseline when a registrable domain is available.
5. Add a first-contact signal when applicable.
6. Call `verdict.judge(..., intel_ok=False)` and return a provisional quick result with `speed="quick"` and public facts.

The quick pass may still use the database to observe the domain. “Quick/no network” refers to analysis lookups, not necessarily zero persistence latency.

### Full pass (`POST /api/check/url`, default mode)

1. Run the same lexical analyzer.
2. In parallel, query DNS, RDAP registration data, and TLS facts for a hostname (not a raw IP). These calls use `ThreadPoolExecutor(max_workers=3)`.
3. Convert infrastructure facts into attributed signals (very new domain, no resolution, brand claim with no MX/DMARC, invalid/new certificate, etc.).
4. If and only if `include_reputation` is true, query configured providers in parallel. Providers are Safe Browsing v5, VirusTotal URL lookup, URLhaus, and PhishTank. Provider hits become separate `reputation` signals; no match does not increase confidence or assert safety.
5. If preview is enabled (route default `preview=true`) fetch the page from the server, with redirect/DNS checks and JavaScript disabled. Inspect redirect chain, title/text, login forms and external form actions; never submit a form.
6. Update the domain baseline and URL snapshot (normalized URL key, score/tier/content hash). A previously clean URL that now looks bad can add a time-of-click signal.
7. If a short link cannot be expanded, force an `unknown` outcome rather than treating an opaque destination as safe.
8. Build the verdict, public facts/preview, save a durable audit receipt, and return `speed="full"` and `receipt_id`.

The browser orchestrator deliberately calls quick mode first, displays the lexical response/stage progress, then calls the full endpoint. If full fails, it keeps the quick result visibly degraded.

### Lexical rule families

`engine/lexical.py` is a rule engine, not a trained classifier. Data lists and regex corpora live in `engine/data.py`. Rule families include:

- Malformed/unsupported URLs, raw IP host, userinfo before `@`, unusual schemes/ports.
- Unicode IDN/punycode and homoglyph skeleton comparison.
- Brand impersonation in subdomains, typosquatted registrable domains, brand-plus-lure labels.
- High-abuse TLDs, shorteners, free/shared hosting, deep/long hostnames, hyphens.
- Credential/payment language in path/query; redirect wrappers and encoded payload patterns.
- Dangerous direct-download/double extensions and high-entropy path/domain components.
- Defanging, normalized URL keys, public parsed facts, and signal evidence/tips.

The data module includes a brand and legitimate-domain corpus, suffix/hosting/shortener lists, dangerous extensions, sensitive words, redirect parameters, homoglyph and keyboard-adjacency maps, BEC patterns, India scam rules, and `TEACH` explanations. Extend the data tables with regression tests; do not add a rule without checking legitimate-domain false positives.

### Network and SSRF safeguards (`engine/net.py`)

- `resolve_ips()` resolves all returned addresses. `is_public_host()` requires every resolution to be globally routable; empty, private, loopback, link-local, metadata, or otherwise non-global resolutions fail closed.
- DNS facts include A, MX, NS, SPF TXT and DMARC TXT presence. Resolver exceptions are returned as degraded facts rather than bubbling through the scan.
- TLS uses Python's default validating SSL context, hostname verification, timeout-limited connection, issuer and certificate age.
- RDAP uses `https://rdap.org/domain/{domain}` for registration age/registrar.
- `fetch_page()` follows a bounded redirect chain, validates the destination along the way, caps downloaded bytes, uses connect/read timeouts, and parses a bounded subset of HTML. The parser does not execute scripts or submit forms.
- DNS/TLS/RDAP helper results use a small in-process TTL cache. This is per process and not shared across serverless instances.

Treat this as defense-in-depth, not a complete sandbox boundary. Production changes to fetching should preserve DNS rebinding resistance, redirect revalidation, metadata/IP deny behavior, byte limits, timeouts, and no-browser-execution semantics.

### Optional reputation (`engine/intel.py`)

- API keys are captured from server environment at module import.
- Results are cached in-process with a lock and bounded cache size; each provider has its own TTL/result handling.
- Safe Browsing, VirusTotal, URLhaus, and PhishTank have distinct request formats and provider-specific failure messages.
- Provider timeouts/rate limits/unconfigured keys are `ok=false` or no-hit states, not safe verdicts.
- Reputation calls are gated at the route/orchestrator level by `include_reputation`; quick mode does not invoke them.

---

## 6. Email analysis pipeline

`engine/emailscan.py` parses raw RFC email bytes using Python's `email` package (`BytesParser` with the default policy). The route accepts either multipart file field `file` or JSON `{ "raw": "..." }`, with a `12 MiB` maximum.

The scan is an evidence extractor; it does not render the original email in a browser or execute its parts. Main stages:

1. **Headers and identities:** parse From/display name, Reply-To, Return-Path/Sender, To, Date, Message-ID, subject and Received chain.
2. **Authentication:** normalize `Authentication-Results` SPF/DKIM/DMARC/ARC-like results and verify an included DKIM signature cryptographically when possible. `none`/missing stays distinct from `fail`.
3. **Identity mismatch signals:** Reply-To/Return-Path domain mismatch, brand in display name, embedded alternate email in display name, Message-ID mismatch, date anomalies.
4. **Received path:** inspect hop count/order and suspicious relay features; code is in `_received_chain()`.
5. **Body, BEC, India rules:** extract text/HTML links and text, run `BEC_PATTERNS` and `INDIA_RULES`, and attach explanatory snippets/tips.
6. **Links:** extract HTML and plain-text links; run lexical URL analysis on each, compare visible anchor text with destination, sender domain and scores. The UI can deep-scan an individual link with the full URL endpoint.
7. **Bank/account integrity:** extract IBAN/account/IFSC-like values and compare with the sender/vendor's trusted baseline. An unverified changed account is held as `offered`; it does not replace the baseline until a human confirms out of band.
8. **Attachments:** record defanged filename, size, content type, extension, SHA-256, macro-enabled/double-extension/encrypted-ZIP flags; add risk signals. The code does not execute or extract arbitrary attachment content.
9. **Workspace baselines and cluster key:** observe sender/domain, add first-contact/known-sender signals, and create a stable hash from normalized subject, sender and extracted link domains.
10. **Verdict/receipt:** judge all signals, add email metadata/links/attachment/account summaries, report cluster information, and save a receipt.

The scan result includes a limited text excerpt and selected header values; receipts may include evidence/result content. Treat receipts as sensitive. Opted-in monthly summary storage is narrower: flagged domains and scan metadata only, not raw email, full URLs, subject or attachment contents.

---

## 7. Verdict and evidence model

`engine/verdict.py` is shared by URL and email scans.

### Signal shape

Signals are dictionaries constructed by `lexical.sig()` or equivalent and normally carry:

```json
{
  "id": "stable_rule_id",
  "title": "Human-readable signal",
  "severity": "critical|high|medium|low|info",
  "weight": 24,
  "evidence": "Input-derived explanation",
  "category": "lexical|infrastructure|reputation|content|header|...",
  "tip": "Transferable safety lesson (optional)"
}
```

IDs, categories and shape are consumed by scoring, UI rendering, tips, post-click/out-of-band logic, and tests. Preserve compatibility when changing them.

### Score and tier

- Severity ordering: critical 4, high 3, medium 2, low 1, info 0.
- Sort by severity then weight, descending.
- Weighted sum uses positional diminishing returns: `1.0, .75, .6, .5, .45, .4, .35, .3, .25, .2`, then `.15` for later signals.
- A leading critical signal has a floor equal to its own weight, so it is not diluted by the decay calculation.
- Rounded integer score is capped at 100.
- Thresholds in `verdict.THRESHOLDS`: malicious `>=65`, suspicious `>=30`, low `>=12`, otherwise safe tier.

The user-visible label is separate from the numerical tier: `malicious`, `suspicious`, `unknown`, or `likely_safe`. Insufficient corroboration can map safe/low evidence to `unknown`. Shorteners that cannot be expanded are explicitly forced unknown. `confidence` is `high|medium|low` qualitative evidence strength, not a calibrated probability. The result carries thresholds, signal counts, top explanation, next steps, teach-in-the-moment tips, and a generated timestamp.

A verdict receipt is serialized by `verdict.build_receipt()` and persisted by `store.save_receipt()`. It records engine/version, evidence and thresholds sufficient to inspect how a result was reached. `GET /api/receipt/<rid>` retrieves the persisted JSON.

---

## 8. Backend API reference

All JSON routes are same-origin. Unless noted, errors are JSON `{ "error": "..." }`. The global API gate protects all endpoints except the explicit public list and the special offline Help Guide path. “Protected” below means a valid PhishGuard session cookie is required.

### Page, health and session

| Method + path | Access | Purpose |
|---|---|---|
| `GET /` | Public | Landing page / dashboard shell. |
| `GET /login` | Public | Dedicated authentication view. |
| `GET /ui-trial` | Public | UI experiment view. |
| `GET /sw.js` | Public | Root-scope service worker. |
| `GET /auth/google/start` | Public | Start Google OIDC; stores short-lived state/nonce in Flask session. |
| `GET /auth/google/callback` | Public | Verify callback and create/login account. |
| `GET /api/health` | Public | `ok`, configured provider booleans and aggregate store stats. |
| `GET /api/public-check-count` | Public | Aggregate receipt count for landing page; no receipt payload. |
| `GET /api/auth/session` | Public | `{authenticated, user}` session probe. |

### Account and authentication

| Method + path | Access | Purpose / notable body fields |
|---|---|---|
| `POST /api/auth/register` | Public | `username`, `password`, `mobile`, optional `email`, recovery question/answer, `monthly_summary`. Sets auth cookie. |
| `POST /api/auth/login` | Public | `username`, `password`. Sets auth cookie. |
| `POST /api/auth/forgot-password/question` | Public | `username`; returns configured recovery question. |
| `POST /api/auth/forgot-password/reset` | Public | `username`, `recovery_answer`, `new_password`; rotates sessions and signs in. |
| `POST /api/auth/forgot-password/email/request` | Public | `username`; response intentionally avoids revealing whether an account exists. Requires configured Mailjet to send. |
| `POST /api/auth/forgot-password/email/reset` | Public | `username`, `code`, `new_password`; one-time email OTP. |
| `POST /api/auth/email/request-verification` | Protected | Send OTP to account's unverified Gmail address. |
| `POST /api/auth/email/verify` | Protected | `code`; marks account email verified. |
| `POST /api/auth/change-password` | Protected | `current_password`, `new_password`; revokes sessions and returns a fresh session. |
| `POST /api/auth/change-mobile` | Protected | `current_password`, `mobile`. |
| `POST /api/auth/change-email` | Protected | `current_password`, `email`. |
| `POST /api/auth/recovery-question` | Protected | Current password plus replacement recovery question/answer. |
| `POST /api/auth/logout` | Public route | Revoke the presented cookie if present and expire cookie. |
| `POST /api/account/profile` | Protected | Current password, `display_name`, `avatar_initials`. |
| `POST /api/account/preferences` | Protected | Notification preference fields. |
| `GET /api/account/login-history` | Protected | Recent session/device history. |
| `GET /api/account/export` | Protected | JSON account export attachment; `no-store`. |
| `POST /api/account/clear-data` | Protected | Current password and exact confirmation `CLEAR`; clears selected personal activity but keeps account/security history. |
| `POST /api/account/delete` | Protected | Current password and exact confirmation `DELETE`; removes account data and clears cookie. |

### Scanning, analysis and report-to-sweep

| Method + path | Access | Purpose / notable request details |
|---|---|---|
| `POST /api/check/url?mode=quick` | Protected | JSON `{url}`; lexical response for the immediate first pass. |
| `POST /api/check/url` | Protected | JSON `{url, preview?, include_reputation?}`; full analysis. `include_reputation` should only be true after explicit per-scan consent. |
| `POST /api/check/email` | Protected | Multipart `file` or JSON `{raw}`; max input 12 MiB. |
| `GET /api/sample/<name>` | Protected | Returns one of the bundled `.eml` examples as text. |
| `POST /api/report` | Protected | Campaign cluster, subject/sender/links, reporter, clicked flag, verdict and score; returns updated cluster stats. |
| `GET /api/clusters` | Protected | List report clusters for the workspace. |
| `GET /api/receipt/<rid>` | Protected | Retrieve saved audit receipt JSON. |
| `POST /api/vendor/confirm` | Protected | `vendor_key`, optional confirmer label; promotes a pending account value after human out-of-band check. |
| `GET /api/stats` | Protected | Aggregate store stats. |
| `GET /api/money-deterred` | Protected | Campaign/report KPIs and clearly labelled INR estimate/method. |

### Assistant and notifications

| Method + path | Access | Purpose |
|---|---|---|
| `POST /api/assistant` | Public offline FAQ; protected users are rate-limited/logged | JSON `{question}`. Never calls an LLM/search API. |
| `GET /api/notifications/push/key` | Protected | Returns configured flag and the public VAPID key, if enabled. |
| `POST /api/notifications/push/subscribe` | Protected | Stores validated browser subscription endpoint/key material for the account. |
| `POST /api/notifications/push/unsubscribe` | Protected | Removes a validated subscription endpoint. |
| `GET /api/cron/cluster-digest` | Bearer secret | Weekly push aggregate; checks `Authorization: Bearer <CRON_SECRET>`. |
| `GET /api/cron/monthly-scan-summary` | Bearer secret | Sends opted-in users last month's domain-only flagged-scan summary; checks the same bearer secret. |

Cron routes are intentionally in the API auth gate's public allowlist so Vercel's scheduler can call them; the handlers themselves require `CRON_SECRET` and constant-time compare. They are not anonymous public operations.

### Request/response conventions

- `postJSON()` in the browser sets `Content-Type: application/json` and `X-Requested-With: XMLHttpRequest`.
- Full URL scan can take multiple seconds; use the quick/full client sequence and do not assume one response means a full result.
- External-provider configuration is reported as booleans, never key values.
- API responses use `Cache-Control: no-store` from the Flask response hook.
- URL scan exceptions currently return error details with their exception type/message (and print server-side traceback); review this behavior before exposing additional internals.

---

## 9. Authentication and account security

`engine/auth.py` owns account/session business rules; `app.py` owns the HTTP cookie and Google OIDC callback.

### Local credentials

- Username normalization lowercases and allows 3–32 letters/digits/underscores, starting with a letter.
- Mobile normalization accepts a 10-digit Indian number (optional `+91`/`91` prefix) and stores normalized `+91...` form. It is validation, not phone ownership verification.
- Optional email accepts Gmail/Googlemail only and normalizes to lowercase.
- Passwords and recovery answers use Werkzeug password hashing; raw values are not stored.
- Login failure tracking is keyed by username and request IP with a 15-minute window and default maximum 10 failures (overridable by environment).
- Session TTL defaults to eight hours (`AUTH_SESSION_TTL_SECONDS`). Login issues a high-entropy bearer value, stores only its SHA-256 hash in the database, and returns the raw token only as an HttpOnly cookie.
- Recent login records include IP address, user-agent, and a derived device label.

### Cookie and request protection

- In local HTTP, cookie name is `pg_session` and Secure is false by default.
- When `AUTH_COOKIE_SECURE` is true, cookie name is `__Host-pg_session`, with `Secure`, `HttpOnly`, `SameSite=Lax`, and `/` path.
- Flask's own signed session is used for transient Google OAuth state/nonce; `FLASK_SECRET_KEY` should be configured and stable in deployed environments.
- Authenticated mutating API calls require `X-Requested-With: XMLHttpRequest`. This is a custom request guard, not a synchronizer CSRF token. Preserve SameSite and review CSRF defenses if introducing cross-origin clients or additional cookie-auth mutations.

### Recovery and verification

- Recovery-question answers are normalized and hashed. Failed recovery attempts have a separate rate limit.
- Email verification/password-reset OTPs are six digits, hashed at rest, expire after 600 seconds, allow at most five verification attempts, three requests per email/IP per 15 minutes, and 100 total requests/day.
- A new OTP invalidates outstanding challenges for the same email/purpose.
- Password-reset-by-email responses intentionally avoid account enumeration.
- Mail delivery is optional; requests return a setup/configuration error when Mailjet is absent, with account existence kept out of the response where relevant.

### Google OIDC

Google sign-in is enabled only when `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, and a configured `FLASK_SECRET_KEY` are present. Authlib discovery uses Google's OpenID metadata and requests `openid email profile`. The callback validates the nonce and verified-email claim, links by verified email when appropriate, stores the provider subject mapping, then issues the same local PhishGuard session. Google access/refresh tokens are not used as PhishGuard login sessions.

---

## 10. Persistence and data model

### Database selection

- Local default: SQLite at `data/phishguard.db`, overridable with `PHISHGUARD_DB`.
- Hosted: PostgreSQL through `psycopg` when a supported database URL is resolved.
- `engine/database_config.py` selects in this order outside Preview: `DATABASE_URL`, `DATABASE_POSTGRES_PRISMA_URL`, `DATABASE_URL_UNPOOLED`.
- Vercel Preview is fail-closed: it reads only `PHISGUARD_PREVIEW_DATABASE_URL`; the generic Production integration URLs are not used as Preview fallback. `store.py` raises during startup if `VERCEL_ENV=preview` and that isolated URL is absent.
- `store._PostgresConnection` adapts existing qmark SQL (`?`) to psycopg `%s` placeholders and exposes `execute`/`executescript` compatibility.

### Initialization and transactions

`SCHEMA` in `engine/store.py` creates tables/indexes idempotently. `init()` applies forward-compatible column migrations for existing databases; there is no separate migration framework/version table. Schema initialization is lazy and keyed to the configured `(DATABASE_URL, DB_PATH)`. `_INIT_LOCK` prevents concurrent first-use initialization within one process; `_LOCK` serializes store operations within that process. Connections are generally opened for individual store operations and used as context-managed transactions. These locks are process-local and do not coordinate separate Gunicorn workers/serverless instances.

### Tables and responsibilities

| Table | Main responsibility |
|---|---|
| `domains` | First/last sighting, count, and worst observed tier for a domain baseline. |
| `senders` | Sender-address first/last sighting and hit count. |
| `vendors` | Trusted account value, proposed changed value, timestamps and change count. |
| `url_snapshots` | Normalized URL score/tier/content hash and first/last observation. |
| `reports` | User-submitted report details, click flag, verdict/score, campaign cluster key. |
| `receipts` | Durable JSON verdict audit payload. |
| `auth_accounts` | Username, password hash, mobile/email, profile/recovery and preference fields. |
| `auth_login_sessions` | Hashed bearer-session tokens, expiry/revocation and device/IP metadata. |
| `auth_login_attempts` | Rate-limit and audit counters for login attempts. |
| `auth_recovery_attempts` | Recovery-question attempt throttling. |
| `auth_otp_challenges` | Hashed OTP, purpose, expiry, attempt count and request metadata. |
| `auth_oauth_identities` | Provider subject to PhishGuard user mapping. |
| `auth_users`, `auth_sessions` | Legacy/email-oriented auth tables retained by the current schema/functions. |
| `account_flagged_scans` | Monthly opt-in summary rows; domain and scan metadata only. |
| `notification_deliveries` | Idempotency/event-deduplication markers for scheduled notices. |
| `push_subscriptions` | Account-owned browser push subscriptions. |
| `assistant_requests` | Authenticated Help Guide rate-limit/audit rows. |

Store function names are the data-access API; route/engine code should avoid embedding SQL. Use isolated SQLite files for local tests. Do not point tests at the live database or create throwaway Production accounts.

### Baseline semantics

- `observe_domain` and `observe_sender` track first contact and sightings; domain `worst_tier` only moves toward more severe tiers.
- `check_vendor_account` records the first account as a baseline, but later changed values are stored as `offered`. `confirm_vendor_account` promotes a pending value after explicit human verification. This prevents an attacker-controlled invoice from poisoning the baseline.
- `check_url_snapshot` compares current score/tier/content hash with previous observations and can surface a clean-to-bad transition.
- `add_report` stores a report and groups by deterministic cluster key; `cluster_stats` aggregates report/clicked counts and maximum-scoring verdict.
- `save_receipt` writes JSON and returns a `RCPT-...` ID. Public landing count only returns a count, not receipt details.

---

## 11. External services and configuration

All values below are variable **names**, not values. Keep credentials in environment/deployment settings; never commit actual keys.

| Variable | Used by | Required? / notes |
|---|---|---|
| `DATABASE_URL` | Store/database config | Persistent PostgreSQL URL outside Preview; preferred generic name. |
| `DATABASE_POSTGRES_PRISMA_URL` | Store/database config | Fallback hosted Postgres URL. |
| `DATABASE_URL_UNPOOLED` | Store/database config | Final non-Preview fallback. |
| `PHISGUARD_PREVIEW_DATABASE_URL` | Store/database config | Separate Preview-only database URL; no fallback to Production URLs. |
| `PHISHGUARD_DB` | SQLite store | Local SQLite path. |
| `AUTH_COOKIE_SECURE` | Flask | Enable Secure/`__Host-` cookie on HTTPS deployments. |
| `FLASK_SECRET_KEY` | Flask/Authlib | Stable secret for Flask-signed OAuth state/session. |
| `AUTH_SESSION_TTL_SECONDS` | Auth | Defaults to 28,800 seconds. |
| `AUTH_LOGIN_WINDOW_SECONDS` | Auth | Login-throttle window, default 900 seconds. |
| `AUTH_LOGIN_MAX_FAILURES` | Auth | Default 10 failures per username/IP window. |
| `AUTH_RECOVERY_MAX_FAILURES` | Auth | Recovery-attempt cap; see `engine/auth.py`. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` | Authlib | Optional Google OIDC. |
| `GSB_API_KEY` | Safe Browsing v5 | Optional URL reputation; only when user opts in. |
| `VT_API_KEY` | VirusTotal | Optional URL lookup; rate/retention terms apply. |
| `URLHAUS_AUTH_KEY` | URLhaus | Optional community lookup. |
| `PHISHTANK_APP_KEY` | PhishTank | Optional exact URL check. |
| `MAILJET_API_KEY`, `MAILJET_SECRET_KEY`, `MAILJET_FROM_EMAIL`, `MAILJET_FROM_NAME` | Mailer | Optional HTTPS API delivery; verified sender required. |
| `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT` | Push | Optional standards-based Web Push; private key stays server-side. |
| `CRON_SECRET` | Cron endpoints | Bearer secret required for scheduled routes. |
| `PORT` | Local/Docker | Defaults to 8000. |

DNS, RDAP and TLS checks use Python/network libraries directly. Optional reputation APIs and Mailjet use HTTPS requests with bounded timeouts. VAPID uses the optional `pywebpush` dependency. Google sign-in uses Authlib. Three.js is locally bundled under `public/static/vendor/` rather than installed into browser code from a CDN.

---

## 12. Deployment and operations

### Vercel

`vercel.json` sets `api/index.py` maximum function duration to 60 seconds and schedules:

- `/api/cron/cluster-digest` at `0 9 * * 1` (weekly).
- `/api/cron/monthly-scan-summary` at `0 9 1 * *` (monthly).

The app expects a persistent PostgreSQL provider on hosted deployments. Preview uses its own URL variable and must not silently access Production storage. Optional features remain disabled when their keys are absent. A successful Vercel build is not proof that all optional network integrations are configured; check `/api/health` for boolean configuration state and inspect deployment/runtime logs without printing secrets.

### Docker

`Dockerfile` uses Python 3.12 slim, runs as the unprivileged `phishguard` user (UID 10001), installs `requirements.txt`, exposes port 8000, and starts Gunicorn with two workers/eight threads and a 60-second timeout. `/app/data` is declared as a volume and `docker-compose.yml` maps it to the named `phishguard-data` volume. `docker compose down` leaves that volume intact; remove the named volume only when intentionally destroying persisted data.

### Local

`RUN-LOCAL.md` documents Python and Docker paths. The Python launcher creates `.venv`, installs dependencies, optionally seeds demo data, runs tests unless `--no-test`, then launches the local app. The SQLite DB is ignored by Git. Use a dedicated temporary DB path for tests.

---

## 13. Tests and development workflow

Tests use Python `unittest` and cover assistant matching, OTP/auth, database environment selection, URL/email analysis, flagged-scan retention, Google auth/routes, intelligence provider behavior, mailer, cron summaries, public count, request timing, and URL consent.

Typical isolated test command:

```bash
PHISHGUARD_DB=/tmp/phisguard-tests.sqlite \
  python -m unittest discover -s tests -q
```

Other useful checks:

```bash
python -m py_compile app.py engine/*.py
node --check public/static/app.js
node --check public/static/depth-scene.js
git diff --check
```

Use Python's built-in test runner in environments without pytest. Some tests of sample message reading may emit existing `ResourceWarning`s for unclosed fixture reads; distinguish those from failures.

### Safe change loop

1. Identify source-of-truth layer: rule data vs analyzer vs API contract vs UI renderer vs persistence.
2. Add/update a focused test in the existing feature suite.
3. Run targeted tests, then full `unittest` discovery with an isolated DB.
4. Run Python/JS syntax and whitespace checks.
5. Exercise representative samples and error/degraded modes locally.
6. Inspect API response shapes and confirm front-end escaping/ARIA state remains intact.
7. For DB changes, test both fresh schema and an older SQLite/isolated Postgres schema path.
8. Update this document and README when architecture/API contracts change.

---

## 14. Known implementation constraints and improvement guide

This section records implementation boundaries that are important during future work; it is not a promise that every item is a defect.

### Architectural constraints

- The HTML template and `public/static/app.js` are large, shared files. Extracting components/modules could improve maintainability, but preserve the single-origin routes, DOM IDs and no-build deployment assumptions unless a migration is deliberate.
- Store locks are in-process only; they do not provide cross-worker coordination. Postgres constraints/transactions should carry correctness under multi-worker/serverless concurrency.
- The PostgreSQL adapter is intentionally small and translates `?` to `%s`; keep SQL compatible or replace the adapter with an explicit database abstraction before adding complex dialect-specific SQL.
- Schema changes rely on idempotent creation and additive column migrations in `store.init()`, not a versioned migration framework. Larger schema changes should introduce an explicit migration strategy.
- In-process network/provider caches are not distributed and disappear on cold starts. Do not assume globally consistent cache behavior.

### Privacy and security review points

- Receipts and report rows can contain sensitive analysis details. Define retention, access control, export and deletion behavior whenever new sensitive fields are added.
- Browser recent/saved scan state is localStorage, not encrypted storage. Carefully review payload fields and retention before including raw message source, URLs or identifiers.
- `X-Requested-With` is a custom mutation guard, not a complete CSRF token design. Re-evaluate when auth flows, browser origins, or embedding change.
- Preserve SSRF restrictions and redirect revalidation in `net.py`; add tests for localhost, private IPv4/IPv6, link-local/metadata, DNS changes, redirects and disallowed schemes before altering fetch behavior.
- Do not interpret provider no-hit, a passing individual mail-auth header, an old domain, or a valid TLS certificate as proof of safety. Keep verdict explanations explicit about evidence limits.
- The pasted-email path currently passes the raw source text into recent/saved client state; this can persist message content in localStorage. If raw email is meant to be transient, remove/redact `payload` before `pushRecent()` and before saved-scan serialization, and add a storage regression test. Multipart file payloads are `FormData` and do not serialize like the raw string.
- The multipart email frontend request currently calls `api('/api/check/email', { method: 'POST', body: payload })` without `X-Requested-With`; the authenticated API gate requires that header for mutations. Verify/fix this path when changing upload behavior (for example, set the header while leaving the browser-generated multipart boundary intact).
- The error handlers for scanner paths currently include exception type/message in JSON and print tracebacks; review information disclosure and log hygiene if new exception types or sensitive payloads are introduced.
- The template includes external Google Fonts links while the server CSP currently restricts external stylesheet/font sources. Confirm CSP/browser behavior and either serve fonts locally, permit only the exact trusted origins, or rely intentionally on local fallbacks.
- The template has a small inline script for the `?ui=trial` query flag while `script-src` is `'self'` without a nonce or `'unsafe-inline'`; browsers may block that query-triggered script. `/ui-trial` uses a server-rendered flag, but the query-only route should be checked in the browser console.

### Feature extension map

| Change wanted | Likely files to change | Tests to add/update |
|---|---|---|
| New URL signal or knowledge-list entry | `engine/data.py`, `engine/lexical.py`, possibly `engine/verdict.py` | `tests/test_engine.py`, `tests/test_intel.py` if provider-related |
| New URL infrastructure signal | `engine/net.py`, `engine/urlscan.py` | `tests/test_engine.py`; mock network and cover failure/degraded paths |
| New reputation source | `engine/intel.py`, `engine/urlscan.py`, consent UI and `.env.example` | `tests/test_intel.py`, `tests/test_urlscan_consent.py` |
| New email signal or attachment type | `engine/emailscan.py`, `engine/data.py`, result renderer in `public/static/app.js` | `tests/test_engine.py` with safe `.eml` fixtures |
| New account setting | `engine/store.py` schema/migration, `engine/auth.py`, routes in `app.py`, settings DOM and handlers | Auth/account route tests and isolated DB tests |
| New API route | `app.py` auth allowlist/policy, frontend caller | Route tests for unauthenticated, authenticated and missing-header cases |
| New persistent entity | `engine/store.py`, DB migration strategy, export/delete semantics | fresh and existing-schema tests; no live-account fixtures |
| New theme/layout behavior | `templates/index.html`, appropriate CSS layer, `public/static/app.js` only if stateful | responsive/reduced-motion/keyboard checks |
| New notification type | `engine/push.py`/`mailer.py`, cron or scan caller, delivery idempotency store | provider mocks and duplicate-delivery tests |

### Non-goals to preserve unless product requirements change

- Do not store or log submitted passwords, session token values, provider keys, or Google OAuth tokens.
- Do not call external reputation providers in quick mode or without the full-scan consent setting.
- Do not execute untrusted page JavaScript, submit a scanned form, or open user-provided destinations in the browser.
- Do not promote invoice-provided account changes automatically.
- Do not turn “not found in a feed” into a clean verdict or present heuristic scores as calibrated probability.
- Do not substitute disposable persistence for the configured durable account/scan store.
