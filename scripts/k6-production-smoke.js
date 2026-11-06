// Low-volume, read-only production smoke test for PhishGuard on Vercel.
// Run from your own machine with: k6 run scripts/k6-production-smoke.js
// This sends GET requests only to the public homepage; it does not call scan/auth APIs.
import http from 'k6/http';
import { check, sleep } from 'k6';

const PRODUCTION_URL = 'https://phisguard-five.vercel.app/';

export const options = {
  vus: 2,
  duration: '30s',
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<2000'],
  },
};

export default function () {
  const response = http.get(PRODUCTION_URL, {
    redirects: 2,
    timeout: '10s',
    tags: { test: 'production-homepage-smoke' },
  });

  check(response, {
    'homepage responds with HTTP 200': (res) => res.status === 200,
    'homepage includes the PhishGuard title': (res) =>
      res.body !== null && res.body.includes('PhishGuard'),
  });

  // Keep the request rate low: two VUs, each pausing after every response.
  sleep(1);
}
