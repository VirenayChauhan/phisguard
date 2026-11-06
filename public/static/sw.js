'use strict';

self.addEventListener('push', (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch { /* use defaults */ }
  const title = String(payload.title || 'PhishGuard notification').slice(0, 120);
  const body = String(payload.body || 'Open PhishGuard to review.').slice(0, 500);
  const target = new URL(typeof payload.url === 'string' ? payload.url : '/', self.location.origin);
  const sameOriginPath = target.origin === self.location.origin ? `${target.pathname}${target.search}${target.hash}` : '/';
  event.waitUntil(self.registration.showNotification(title, {
    body,
    tag: 'phishguard-update',
    data: { url: sameOriginPath },
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = new URL(event.notification.data?.url || '/', self.location.origin);
  const path = target.origin === self.location.origin ? target.href : self.location.origin + '/';
  event.waitUntil((async () => {
    const windows = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of windows) {
      if (new URL(client.url).origin === self.location.origin) {
        if ('navigate' in client) await client.navigate(path);
        return client.focus();
      }
    }
    return clients.openWindow(path);
  })());
});
