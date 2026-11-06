# PhishGuard production readiness checklist

A short, **read-only-first** routine for the live PhishGuard site. It is written for
the owner of the production site, not as a database administration guide.

Live site: <https://phisguard-five.vercel.app>

## Before you start

- Use your own existing account for sign-in checks. **Do not create a disposable
  account in the connected production database.**
- Do not paste passwords, Google credentials, email-provider keys, database URLs,
  session cookies, or one-time codes into chat, screenshots, or support tickets.
- Do not edit, remove, or rotate Neon-managed database variables in Vercel.
- Do not use **Clear personal data**, **Delete account**, or a password-reset flow
  as a routine test. Those actions change live user data.
- No paid service or new environment variable is needed for the checks below.

## After a deployment

1. In Vercel, open the PhishGuard project and confirm the latest **Production**
   deployment says **Ready** and is serving the production alias.
2. Open the live site in a private/incognito window. Confirm the public page loads,
   the completed-check count appears, and **Sign in → Continue with Google** returns
   you to the signed-in workspace. If Microsoft sign-in has been configured, verify
   **Continue with Microsoft** using an account you own.
3. While signed in, run a harmless check such as `https://example.com`. Confirm the
   result shows the evidence and any unavailable/degraded checks honestly; a provider
   “no match” is not proof that a site is safe.
4. Open <https://phisguard-five.vercel.app/api/health>. A healthy response includes
   `"ok": true`. This endpoint reports basic aggregate service status; it does not
   prove that every optional provider or email/push delivery path is configured.
5. Sign out and sign back in once, then confirm your saved account history is still
   present. Do not clear or delete any data while checking persistence.

## Periodic operations review

- **Database recovery:** in the connected database provider's dashboard, review the
  Production project's backup/restore information and make sure you know where its
  recovery instructions live. This is a review only: do not change integration-owned
  connection settings, and never test a restore by overwriting Production. If you
  need to rehearse recovery, ask for a separate isolated test plan first.
- **Scheduled jobs:** in Vercel, review the scheduled function/cron invocation logs
  for `/api/cron/cluster-digest` and `/api/cron/monthly-scan-summary`. These optional
  jobs require `CRON_SECRET`; monthly email also requires the email provider to be
  configured. If they are not configured, these optional deliveries may be skipped
  or report a configuration error. Do not share secret values when asking for help.
- **Account recovery:** verify that the UI offers both the recovery-question option
  and, for accounts with a verified email when email delivery is configured, a
  one-time email code. Do not request a code for an account you do not own.
- **Privacy:** check that optional third-party reputation sharing remains off by
  default. A full URL is sent to configured providers only when the user opts in;
  PhishGuard's own analysis still runs without that sharing.

## Accessibility and scan-result review

When convenient, test with a keyboard and a phone:

- Tab through the landing page, sign-in flow, workspace navigation, scan forms, and
  settings. Focus should remain visible; Enter and Space should activate controls.
- Try a narrow phone viewport and a browser's reduced-motion setting.
- Check that dynamic scan results are announced, form fields have meaningful names,
  and color is not the only way a verdict or warning is communicated.
- Read the verdict's **evidence strength** and the evidence chain together. The score
  is a rule-based risk score, not a probability. Evidence strength is qualitative,
  not a statistically calibrated likelihood. If evidence is thin or analysis is
  degraded, treat the result as unverified rather than as a clearance.

If anything looks wrong, note the page, approximate time, and a plain-language
symptom. Do not include secrets, raw email contents, or full sensitive URLs.
