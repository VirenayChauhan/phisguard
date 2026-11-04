/* ============================================================================
   PhishGuard UI — vanilla JS, no build step, no external dependencies.
   Rendering is string-based and escaped through esc(); nothing here trusts
   server output with innerHTML.
   ========================================================================== */
'use strict';

/* ------------------------------------------------------------------- utils */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));
const num = (n) => Number(n || 0).toLocaleString('en-IN');

async function api(path, opts) {
  const res = await fetch(path, opts);
  let body;
  try { body = await res.json(); } catch { body = {}; }
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}
const postJSON = (path, data) => api(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
  body: JSON.stringify(data),
});

/* --------------------------------------------------------------- auth flow */
let activeUser = null;
const SAVED_ACCOUNTS_KEY = 'pg-saved-accounts';

function getSavedAccounts() {
  try {
    const value = JSON.parse(localStorage.getItem(SAVED_ACCOUNTS_KEY) || '[]');
    return Array.isArray(value) ? value.filter((a) => a && typeof a.username === 'string') : [];
  } catch { return []; }
}

function rememberAccount(user) {
  if (!user?.username) return;
  const accounts = getSavedAccounts().filter((a) => a.username !== user.username);
  accounts.unshift({ username: user.username });
  localStorage.setItem(SAVED_ACCOUNTS_KEY, JSON.stringify(accounts.slice(0, 8)));
  renderSavedAccounts();
}

function accountChoicesMarkup(accounts) {
  return accounts.map((account) => `
    <button class="saved-account-choice" type="button" data-account-username="${esc(account.username)}">
      <span class="saved-account-avatar">${esc(account.username.slice(0, 1).toUpperCase())}</span>
      <span>${esc(account.username)}</span>
      <span class="saved-account-arrow">→</span>
    </button>`).join('');
}

function renderSavedAccounts() {
  const accounts = getSavedAccounts();
  const loginBox = $('#saved-accounts');
  const loginList = $('#saved-account-list');
  if (loginBox && loginList) {
    loginBox.hidden = !accounts.length;
    loginList.innerHTML = accountChoicesMarkup(accounts);
  }
  ['#profile-saved-list', '#settings-saved-list'].forEach((selector) => {
    const el = $(selector);
    if (el) el.innerHTML = accounts.length ? accountChoicesMarkup(accounts) : '<div class="profile-empty">No saved accounts yet.</div>';
  });
  $$('.saved-account-choice').forEach((button) => {
    button.onclick = () => switchAccount(button.dataset.accountUsername);
  });
}

function setAuthMessage(message = '', kind = '') {
  const el = $('#auth-message');
  el.textContent = message;
  el.className = `auth-message ${kind}`.trim();
}

function setAuthBusy(button, busy, label) {
  button.disabled = busy;
  if (busy) {
    button.dataset.originalLabel = button.innerHTML;
    button.textContent = label;
  } else if (button.dataset.originalLabel) {
    button.innerHTML = button.dataset.originalLabel;
  }
}

function setSettingsMessage(message = '', kind = '') {
  const el = $('#settings-message');
  el.textContent = message;
  el.className = `settings-message ${kind}`.trim();
}

function notificationPrefsKey() {
  return `pg-notification-settings:${activeUser?.username || 'guest'}`;
}

function getNotificationPrefs() {
  const defaults = { browser: false, scanComplete: true, sound: false, push: false };
  try {
    const value = JSON.parse(localStorage.getItem(notificationPrefsKey()) || '{}');
    return { ...defaults, ...value };
  } catch { return defaults; }
}

function setNotificationPrefs(prefs) {
  const next = { ...getNotificationPrefs(), ...prefs };
  localStorage.setItem(notificationPrefsKey(), JSON.stringify(next));
  syncNotificationUI();
}

function syncNotificationUI() {
  const status = $('#notification-status');
  const browserBox = $('#notify-browser');
  const scanBox = $('#notify-scan-complete');
  const soundBox = $('#notify-sound');
  if (!status || !browserBox || !scanBox || !soundBox) return;
  const prefs = getNotificationPrefs();
  const supported = typeof window.Notification !== 'undefined';
  const permission = supported ? Notification.permission : 'unsupported';
  browserBox.checked = Boolean(prefs.browser && permission === 'granted');
  scanBox.checked = Boolean(prefs.scanComplete);
  soundBox.checked = Boolean(prefs.sound);
  status.className = 'notification-status';
  if (!supported) {
    status.textContent = 'This browser does not support system notifications.';
    status.classList.add('blocked');
  } else if (permission === 'granted' && prefs.browser) {
    status.textContent = prefs.push
      ? 'Browser notifications and background push are enabled for this account.'
      : 'Browser notifications work in this session; background push is not configured here.';
    status.classList.add('ready');
  } else if (permission === 'denied') {
    status.textContent = 'Notifications are blocked. Allow them in your browser site settings.';
    status.classList.add('blocked');
  } else {
    status.textContent = 'Click Enable browser notifications to allow scan-complete messages.';
  }
}

function vapidKeyBytes(value) {
  const padded = `${value}${'='.repeat((4 - value.length % 4) % 4)}`;
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function registerBackgroundPush() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return false;
  const keyInfo = await api('/api/notifications/push/key');
  if (!keyInfo.configured || !keyInfo.public_key) return false;
  const registration = await navigator.serviceWorker.register('/sw.js');
  let subscription = await registration.pushManager.getSubscription();
  if (!subscription) {
    subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: vapidKeyBytes(keyInfo.public_key),
    });
  }
  await postJSON('/api/notifications/push/subscribe', { subscription: subscription.toJSON() });
  return true;
}

async function disableBrowserNotifications() {
  try {
    const registration = await navigator.serviceWorker?.getRegistration('/');
    const subscription = await registration?.pushManager?.getSubscription();
    if (subscription) {
      try { await postJSON('/api/notifications/push/unsubscribe', { endpoint: subscription.endpoint }); } catch { /* still disable the browser device */ }
      await subscription.unsubscribe();
    }
  } catch { /* local notifications can still be disabled if server cleanup fails */ }
  setNotificationPrefs({ browser: false, push: false });
}

async function enableBrowserNotifications() {
  if (typeof window.Notification === 'undefined') {
    toast('This browser does not support notifications', 'err');
    return;
  }
  const permission = await Notification.requestPermission();
  if (permission === 'granted') {
    let pushEnabled = false;
    try { pushEnabled = await registerBackgroundPush(); } catch { /* foreground notifications remain available */ }
    setNotificationPrefs({ browser: true, scanComplete: true, push: pushEnabled });
    toast(pushEnabled ? 'Browser and background push enabled' : 'Browser notifications enabled for this session');
    try { new Notification('PhishGuard notifications enabled', { body: pushEnabled ? 'You can receive campaign alerts when this browser is closed.' : 'Background push is not configured on this deployment.' }); } catch { /* permission may be unavailable in this context */ }
  } else {
    setNotificationPrefs({ browser: false, push: false });
    toast('Browser notifications were not enabled', 'err');
  }
}

function playNotificationSound() {
  if (!getNotificationPrefs().sound) return;
  try {
    const context = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = context.createOscillator();
    const gain = context.createGain();
    oscillator.frequency.value = 660;
    gain.gain.setValueAtTime(0.0001, context.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.06, context.currentTime + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, context.currentTime + 0.18);
    oscillator.connect(gain).connect(context.destination);
    oscillator.start();
    oscillator.stop(context.currentTime + 0.2);
  } catch { /* audio may be blocked until a user gesture */ }
}

function notifyScanComplete(kind, verdict, subject = '') {
  const prefs = getNotificationPrefs();
  if (!prefs.scanComplete) return;
  const tier = tierOf(verdict?.label);
  const label = kind === 'email' ? 'Email scan' : 'Link scan';
  const body = `${subject || 'Your scan'} · ${tier.label}`;
  playNotificationSound();
  if (typeof window.Notification !== 'undefined' && Notification.permission === 'granted' && prefs.browser) {
    try { new Notification(`${label} complete`, { body, tag: `phishguard-${kind}-complete` }); } catch { /* browser notification may be unavailable */ }
  }
  if (document.hidden) document.title = `✓ ${label} complete · PhishGuard`;
  toast(`${label} complete: ${tier.label}`);
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) document.title = 'PhishGuard — link & email checker with receipts';
});

function formatAccountDate(value) {
  if (!value) return '–';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

function renderLoginHistory(history = []) {
  const box = $('#settings-login-history');
  if (!history.length) {
    box.innerHTML = '<div class="profile-empty">No login history yet.</div>';
    return;
  }
  box.innerHTML = history.map((item) => `
    <div class="settings-login-item">
      <div class="settings-login-main">
        <span>${esc(item.device || 'Unknown device')}</span>
        <span class="settings-login-status${item.active ? '' : ' signed-out'}">${item.active ? 'Active' : 'Signed out'}</span>
      </div>
      <div class="settings-login-meta">${esc(formatAccountDate(item.login_at))} · ${esc(item.ip_address || 'Unknown IP')}</div>
    </div>`).join('');
}

async function loadLoginHistory() {
  const box = $('#settings-login-history');
  box.innerHTML = '<div class="profile-empty">Loading login history…</div>';
  try {
    const result = await api('/api/account/login-history');
    renderLoginHistory(result.login_history || []);
  } catch (error) {
    box.innerHTML = `<div class="profile-empty">${esc(error.message)}</div>`;
  }
}

function forgetSavedAccount(username) {
  const accounts = getSavedAccounts().filter((account) => account.username !== username);
  localStorage.setItem(SAVED_ACCOUNTS_KEY, JSON.stringify(accounts));
  renderSavedAccounts();
}

function updateProfileUI(user) {
  activeUser = user;
  const displayName = user?.display_name || user?.username || 'Account';
  const initial = user?.avatar_initials || displayName.slice(0, 1).toUpperCase();
  $('#sidebar-profile-avatar').textContent = initial;
  $('#sidebar-profile-name').textContent = displayName;
  $('#sidebar-profile-email').textContent = user?.email || 'Email not added';
  $('#sidebar-profile-username').textContent = user?.username || '–';
  $('#sidebar-profile-email-status').textContent = user?.email_verified ? 'Verified' : (user?.email ? 'Not verified' : 'No email');
  $('#sidebar-profile-mobile').textContent = user?.mobile || 'Not added';
  $('#sidebar-profile-created').textContent = formatAccountDate(user?.created_at);
  $('#sidebar-profile-password-changed').textContent = formatAccountDate(user?.password_changed_at);
  $('#settings-avatar').textContent = initial;
  $('#settings-name').textContent = displayName;
  $('#settings-email').textContent = user?.email || 'Gmail not added';
  $('#settings-username').textContent = user?.username || '–';
  $('#settings-email-value').textContent = user?.email || 'Not added';
  $('#settings-email-verified').textContent = user?.email_verified ? 'Verified' : (user?.email ? 'Not verified' : 'No email');
  $('#settings-email-verified').classList.toggle('is-verified', Boolean(user?.email_verified));
  $('#settings-email-send-code').hidden = !user?.email || Boolean(user?.email_verified);
  $('#settings-email-verify-form').hidden = !user?.email || Boolean(user?.email_verified);
  $('#settings-mobile-value').textContent = user?.mobile || '–';
  $('#settings-email-title').textContent = user?.email ? 'Change Gmail address' : 'Add Gmail address';
  $('#settings-email-submit').textContent = user?.email ? 'Save Gmail address' : 'Add Gmail address';
  $('#settings-email-input').value = user?.email || '';
  $('#settings-display-name').value = user?.display_name || '';
  $('#settings-avatar-input').value = user?.avatar_initials || '';
  $('#settings-password-changed').textContent = formatAccountDate(user?.password_changed_at);
  $('#settings-account-created').textContent = formatAccountDate(user?.created_at);
  $('#notify-security').checked = user?.notifications?.security !== false;
  $('#notify-email').checked = user?.notifications?.email === true;
  $('#notify-tips').checked = user?.notifications?.tips !== false;
  const notificationPrefs = getNotificationPrefs();
  localStorage.setItem(notificationPrefsKey(), JSON.stringify({
    ...notificationPrefs,
    scanComplete: user?.notifications?.push_scan !== false,
  }));
  syncNotificationUI();
}

async function loadPublicCheckCount() {
  const count = $('#public-check-count');
  if (!count) return;
  try {
    const data = await api('/api/public-check-count');
    count.textContent = num(data.checks_completed);
  } catch {
    count.textContent = '—';
  }
}

function setupLandingReveals() {
  const landing = $('#landing-page');
  if (!landing) return;
  setupCapabilitiesTimeline(landing);
  const motionPreference = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  if (!motionPreference || motionPreference.matches || !('IntersectionObserver' in window)) return;

  const targets = $$('[data-motion-reveal]', landing);
  if (!targets.length || landing.dataset.motionObserved === 'true') return;
  landing.dataset.motionObserved = 'true';
  landing.classList.add('landing-motion-ready');

  const observer = new IntersectionObserver((entries, currentObserver) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('is-visible');
      currentObserver.unobserve(entry.target);
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -7% 0px' });

  requestAnimationFrame(() => targets.forEach((target) => observer.observe(target)));
}

function setupCapabilitiesTimeline(landing) {
  const section = $('#landing-capabilities', landing);
  if (!section || section.dataset.capTimelineReady === 'true') return;
  section.dataset.capTimelineReady = 'true';

  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  if (reducedMotion?.matches || typeof Element.prototype.animate !== 'function') return;

  const runMasterTimeline = () => {
    if (section.dataset.capTimelineStarted === 'true') return;
    section.dataset.capTimelineStarted = 'true';

    // One master schedule: each effect uses the same document timeline and
    // backwards fill, with offsets composed here in reading order.
    const effects = [
      ['.pg-cap-index', [{ opacity: 0, transform: 'translateY(9px)' }, { opacity: 1, transform: 'translateY(0)' }], 480, 0],
      ['.pg-cap-strip-name', [{ opacity: 0, transform: 'translateY(9px)' }, { opacity: 1, transform: 'translateY(0)' }], 480, 65],
      ['.pg-cap-strip-state', [{ opacity: 0, transform: 'translateY(9px)' }, { opacity: 1, transform: 'translateY(0)' }], 480, 120],
      ['.pg-cap-rule', [{ transform: 'scaleX(0)' }, { transform: 'scaleX(1)' }], 520, 45],
      ['.pg-cap-title-mask h2', [{ opacity: 0, transform: 'translateY(105%)' }, { opacity: 1, transform: 'translateY(0)' }], 720, 160],
      ['.pg-cap-clarity', [{ opacity: 0, transform: 'translateY(8px)' }, { opacity: 1, transform: 'translateY(0)' }], 680, 235],
      ['.pg-cap-lede', [{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'translateY(0)' }], 620, 300],
      ['.pg-cap-card:nth-child(1)', [{ opacity: 0, transform: 'translateY(18px)' }, { opacity: 1, transform: 'translateY(0)' }], 640, 370],
      ['.pg-cap-card:nth-child(2)', [{ opacity: 0, transform: 'translateY(18px)' }, { opacity: 1, transform: 'translateY(0)' }], 640, 470],
      ['.pg-cap-card:nth-child(3)', [{ opacity: 0, transform: 'translateY(18px)' }, { opacity: 1, transform: 'translateY(0)' }], 640, 570],
      ['.pg-cap-radar', [{ opacity: 0, transform: 'scale(.72)' }, { opacity: 1, transform: 'scale(1)' }], 620, 500],
      ['.pg-cap-chart', [{ clipPath: 'inset(100% 0 0 0)' }, { clipPath: 'inset(0 0 0 0)' }], 760, 625],
      ['.pg-cap-reports', [{ clipPath: 'inset(0 100% 0 0)' }, { clipPath: 'inset(0 0 0 0)' }], 760, 750],
    ];

    effects.forEach(([selector, keyframes, duration, delay]) => {
      const element = $(selector, section);
      if (!element) return;
      element.animate(keyframes, {
        duration,
        delay,
        easing: 'cubic-bezier(.23, 1, .32, 1)',
        fill: 'backwards',
        iterations: 1,
      });
    });
  };

  if (!('IntersectionObserver' in window)) {
    requestAnimationFrame(runMasterTimeline);
    return;
  }
  const observer = new IntersectionObserver((entries) => {
    if (!entries.some((entry) => entry.isIntersecting)) return;
    observer.disconnect();
    runMasterTimeline();
  }, { threshold: 0.18 });
  observer.observe(section);
}

const wideSidebarMedia = window.matchMedia ? window.matchMedia('(min-width: 921px)') : null;
function syncAssistantVisibility() {
  const dashboardVisible = !$('#dashboard').hidden;
  const available = !$('#auth-screen').hidden || dashboardVisible;
  const sidebarHasHelpLink = dashboardVisible
    && !$('#dashboard').classList.contains('sidebar-hidden')
    && Boolean(wideSidebarMedia?.matches);
  // Keep one visible Help entry point: in the wide sidebar, otherwise the floating button.
  $('#help-ai-fab').hidden = !available || sidebarHasHelpLink;
  if (!available) closeAssistant();
}
if (wideSidebarMedia) {
  if (wideSidebarMedia.addEventListener) wideSidebarMedia.addEventListener('change', syncAssistantVisibility);
  else wideSidebarMedia.addListener(syncAssistantVisibility);
}

function showLanding() {
  $('#landing-page').hidden = false;
  $('#auth-screen').hidden = true;
  $('#dashboard').hidden = true;
  syncAssistantVisibility();
  setupLandingReveals();
  window.scrollTo({ top: 0, behavior: 'instant' });
}

function showLogin(tab = 'login', username = '') {
  $('#landing-page').hidden = true;
  $('#auth-screen').hidden = false;
  $('#dashboard').hidden = true;
  syncAssistantVisibility();
  if (location.pathname !== '/ui-trial') {
    const loginUrl = tab === 'register' ? '/login?mode=register' : '/login';
    if (location.pathname !== '/login' || location.search !== (tab === 'register' ? '?mode=register' : '')) {
      history.replaceState(null, '', loginUrl);
    }
  }
  const isRegister = tab === 'register';
  $('#auth-title').textContent = 'Sign in to PhishGuard';
  $('#auth-lede').textContent = 'Create a secure account or log in to access the phishing protection workspace.';
  $('#auth-tabs').hidden = false;
  $('#google-auth-option').hidden = false;
  $('#login-form').hidden = isRegister;
  $('#register-form').hidden = !isRegister;
  $('#forgot-lookup-form').hidden = true;
  $('#forgot-reset-form').hidden = true;
  $('#forgot-email-reset-form').hidden = true;
  $('#tab-login').classList.toggle('active', !isRegister);
  $('#tab-register').classList.toggle('active', isRegister);
  $('#tab-login').setAttribute('aria-selected', String(!isRegister));
  $('#tab-register').setAttribute('aria-selected', String(isRegister));
  if (!isRegister && username) $('#login-username').value = username;
  $('#login-password').value = '';
  $('#register-email').value = '';
  $('#register-mobile').value = '';
  $('#register-password').value = '';
  $('#register-password-confirm').value = '';
  $('#register-recovery-question').value = '';
  $('#register-recovery-answer').value = '';
  setRegisterStep(1);
  renderSavedAccounts();
}

function showForgotPassword(username = '') {
  $('#landing-page').hidden = true;
  $('#auth-screen').hidden = false;
  $('#dashboard').hidden = true;
  syncAssistantVisibility();
  if (location.pathname !== '/login' && location.pathname !== '/ui-trial') history.replaceState(null, '', '/login');
  $('#auth-title').textContent = 'Reset your password';
  $('#auth-lede').textContent = 'Answer the recovery question you chose when creating your account.';
  $('#auth-tabs').hidden = true;
  $('#google-auth-option').hidden = true;
  $('#login-form').hidden = true;
  $('#register-form').hidden = true;
  $('#forgot-lookup-form').hidden = false;
  $('#forgot-reset-form').hidden = true;
  $('#forgot-email-reset-form').hidden = true;
  $('#forgot-username').value = username;
  $('#forgot-answer').value = '';
  $('#forgot-new-password').value = '';
  $('#forgot-confirm-password').value = '';
  $('#forgot-email-code').value = '';
  $('#forgot-email-new-password').value = '';
  $('#forgot-email-confirm-password').value = '';
  setAuthMessage('');
  if (username) $('#forgot-username').focus();
}

let registerStep = 1;

function setRegisterStep(step) {
  registerStep = Math.max(1, Math.min(3, step));
  $$('.register-step').forEach((section) => {
    const isCurrent = Number(section.dataset.registerStep) === registerStep;
    section.hidden = !isCurrent;
    section.classList.toggle('active', isCurrent);
  });
  $$('.register-progress-step').forEach((item) => {
    const value = Number(item.dataset.progressStep);
    item.classList.toggle('active', value === registerStep);
    item.classList.toggle('complete', value < registerStep);
  });
}

function validateRegisterStep(step) {
  const section = $(`.register-step[data-register-step="${step}"]`);
  const field = $$('input, select', section).find((control) => !control.checkValidity());
  if (field) {
    field.reportValidity();
    return false;
  }
  if (step === 2 && $('#register-password').value !== $('#register-password-confirm').value) {
    setAuthMessage('Passwords do not match.', 'error');
    $('#register-password-confirm').focus();
    return false;
  }
  setAuthMessage('');
  return true;
}

function enterDashboard(user) {
  $('#landing-page').hidden = true;
  $('#auth-screen').hidden = true;
  $('#dashboard').hidden = false;
  syncAssistantVisibility();
  updateProfileUI(user);
  rememberAccount(user);
  setSettingsMessage('');
  renderSavedAccounts();
  loadHeader();
  const requestedRoute = location.hash.slice(1);
  go(ROUTES[requestedRoute] ? requestedRoute : 'overview');
}

const SETTINGS_CATEGORIES = {
  profile: { title: 'Profile details', copy: 'Update how your account appears in PhishGuard.', section: 'profile' },
  security: { title: 'Sign-in & security', copy: 'Choose a specific sign-in or recovery setting to manage.', section: 'privacy' },
  notifications: { title: 'Notifications', copy: 'Choose which browser and account notifications you want.', section: 'privacy' },
  privacy: { title: 'Privacy & data', copy: 'Review, export, or remove information linked to your account.', section: 'privacy' },
  appearance: { title: 'Appearance', copy: 'Switch between two near-black spectrum contrast levels.', section: 'profile' },
  devices: { title: 'Accounts on this device', copy: 'Manage remembered usernames on this browser.', section: 'profile' },
};

function resetSecurityActionPicker() {
  $('#security-action-menu').hidden = false;
  $('#security-action-detail').hidden = true;
  $$('[data-security-action-card]').forEach((card) => { card.hidden = true; });
}

function openSettingsCategory(category) {
  const settings = SETTINGS_CATEGORIES[category];
  if (!settings) return;
  $('#settings-home').hidden = true;
  $('#settings-detail').hidden = false;
  $('#settings-detail-title').textContent = settings.title;
  $('#settings-detail-copy').textContent = settings.copy;
  $('#settings-profile-section').hidden = settings.section !== 'profile';
  $('#settings-privacy-section').hidden = settings.section !== 'privacy';
  $$('#settings-detail [data-settings-category]').forEach((item) => {
    item.hidden = item.dataset.settingsCategory !== category;
  });
  $$('#settings-detail details.privacy-group').forEach((group) => { group.open = false; });
  resetSecurityActionPicker();
  setSettingsMessage('');
  $('#account-panel').scrollTop = 0;
  if (category === 'notifications') syncNotificationUI();
  if (category === 'devices') renderSavedAccounts();
}

function showSettingsHome() {
  $('#settings-home').hidden = false;
  $('#settings-detail').hidden = true;
  $('#settings-profile-section').hidden = true;
  $('#settings-privacy-section').hidden = true;
  resetSecurityActionPicker();
  setSettingsMessage('');
  $('#account-panel').scrollTop = 0;
}

function openSettings() {
  showSettingsHome();
  $('#account-panel').hidden = false;
  $('#account-scrim').hidden = false;
  renderSavedAccounts();
}

function closeSettings() {
  $('#account-panel').hidden = true;
  $('#account-scrim').hidden = true;
}

async function leaveDashboard(nextTab = 'login', username = '') {
  try { await postJSON('/api/auth/logout', {}); } catch { /* local state still resets */ }
  activeUser = null;
  closeSettings();
  showLogin(nextTab, username);
}

function switchAccount(username) {
  if (!username) return;
  closeSettings();
  leaveDashboard('login', username);
  setAuthMessage(`Enter the password for ${username}.`);
}

$('#btn-settings').onclick = openSettings;
$('#account-panel-close').onclick = closeSettings;
$('#account-scrim').onclick = closeSettings;
$('#settings-back').onclick = showSettingsHome;
$$('[data-settings-open]').forEach((button) => {
  button.onclick = () => openSettingsCategory(button.dataset.settingsOpen);
});
$$('[data-security-action]').forEach((button) => {
  button.onclick = () => {
    const action = button.dataset.securityAction;
    const card = $(`[data-security-action-card="${action}"]`);
    if (!card) return;
    $('#security-action-menu').hidden = true;
    $('#security-action-detail').hidden = false;
    $('#security-action-title').textContent = button.dataset.securityTitle || button.textContent.trim();
    $$('[data-security-action-card]').forEach((item) => { item.hidden = item !== card; });
    $('#account-panel').scrollTop = 0;
    setSettingsMessage('');
    if (action === 'activity') loadLoginHistory();
  };
});
$('#security-action-back').onclick = () => {
  resetSecurityActionPicker();
  setSettingsMessage('');
  $('#account-panel').scrollTop = 0;
};
$('#settings-enable-notifications').onclick = enableBrowserNotifications;
$('#notify-browser').onchange = (event) => {
  if (event.target.checked) enableBrowserNotifications();
  else disableBrowserNotifications();
};
$('#notify-scan-complete').onchange = async (event) => {
  const enabled = event.target.checked;
  setNotificationPrefs({ scanComplete: enabled });
  if (!activeUser) return;
  try {
    const result = await postJSON('/api/account/preferences', { push_scan: enabled });
    updateProfileUI(result.user);
  } catch (error) {
    setNotificationPrefs({ scanComplete: !enabled });
    setSettingsMessage(error.message, 'error');
  }
};
$('#notify-sound').onchange = (event) => setNotificationPrefs({ sound: event.target.checked });

$('#settings-profile-form').onsubmit = async (event) => {
  event.preventDefault();
  const button = $('#settings-profile-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Saving…');
  try {
    const result = await postJSON('/api/account/profile', {
      display_name: $('#settings-display-name').value.trim(),
      avatar_initials: $('#settings-avatar-input').value.trim(),
      current_password: $('#settings-profile-password').value,
    });
    updateProfileUI(result.user);
    $('#settings-profile-password').value = '';
    setSettingsMessage('Profile updated successfully.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-preferences-form').onsubmit = async (event) => {
  event.preventDefault();
  const button = $('#settings-preferences-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Saving…');
  try {
    const result = await postJSON('/api/account/preferences', {
      security: $('#notify-security').checked,
      email: $('#notify-email').checked,
      tips: $('#notify-tips').checked,
    });
    updateProfileUI(result.user);
    setSettingsMessage('Notification preferences saved.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-refresh-history').onclick = loadLoginHistory;
$('#settings-download-data').onclick = () => {
  window.location.href = '/api/account/export';
};

$('#settings-clear-data-form').onsubmit = async (event) => {
  event.preventDefault();
  if (!window.confirm('Clear your saved Help Guide questions and submitted reports?')) return;
  const button = $('#settings-clear-data-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Clearing…');
  try {
    await postJSON('/api/account/clear-data', {
      current_password: $('#settings-clear-data-password').value,
      confirmation: 'CLEAR',
    });
    localStorage.removeItem('pg-recent');
    $('#settings-clear-data-form').reset();
    renderRecent();
    setSettingsMessage('Personal activity data cleared successfully.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-delete-form').onsubmit = async (event) => {
  event.preventDefault();
  if (!window.confirm('Delete this account permanently? This cannot be undone.')) return;
  const button = $('#settings-delete-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Deleting…');
  try {
    await postJSON('/api/account/delete', {
      current_password: $('#settings-delete-password').value,
      confirmation: 'DELETE',
    });
    const deletedUsername = activeUser?.username;
    if (deletedUsername) forgetSavedAccount(deletedUsername);
    activeUser = null;
    closeSettings();
    showLogin('login');
    setAuthMessage('Your account and personal data were deleted.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-email-form').onsubmit = async (event) => {
  event.preventDefault();
  const button = $('#settings-email-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Saving…');
  try {
    const result = await postJSON('/api/auth/change-email', {
      email: $('#settings-email-input').value.trim(),
      current_password: $('#settings-email-password').value,
    });
    updateProfileUI(result.user);
    $('#settings-email-password').value = '';
    setSettingsMessage('Gmail address updated successfully.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-email-send-code').onclick = async (event) => {
  const button = event.currentTarget;
  setSettingsMessage('');
  setAuthBusy(button, true, 'Sending…');
  try {
    const result = await postJSON('/api/auth/email/request-verification', {});
    setSettingsMessage(result.message || 'A verification code has been sent.', 'success');
    $('#settings-email-code').focus();
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-email-verify-form').onsubmit = async (event) => {
  event.preventDefault();
  const button = $('#settings-email-verify-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Verifying…');
  try {
    const result = await postJSON('/api/auth/email/verify', {
      code: $('#settings-email-code').value.trim(),
    });
    updateProfileUI(result.user);
    $('#settings-email-code').value = '';
    setSettingsMessage('Email address verified. Email-based recovery and enabled notices are ready.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-recovery-form').onsubmit = async (event) => {
  event.preventDefault();
  const button = $('#settings-recovery-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Saving…');
  try {
    const result = await postJSON('/api/auth/recovery-question', {
      recovery_question: $('#settings-recovery-question').value,
      recovery_answer: $('#settings-recovery-answer').value,
      current_password: $('#settings-recovery-password').value,
    });
    updateProfileUI(result.user);
    $('#settings-recovery-form').reset();
    setSettingsMessage('Password recovery question updated.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-mobile-form').onsubmit = async (event) => {
  event.preventDefault();
  const button = $('#settings-mobile-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Saving…');
  try {
    const result = await postJSON('/api/auth/change-mobile', {
      mobile: $('#settings-mobile-input').value.trim(),
      current_password: $('#settings-mobile-password').value,
    });
    updateProfileUI(result.user);
    $('#settings-mobile-form').reset();
    setSettingsMessage('Mobile number updated successfully.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#settings-password-form').onsubmit = async (event) => {
  event.preventDefault();
  if ($('#settings-new-password').value !== $('#settings-confirm-password').value) {
    setSettingsMessage('The new passwords do not match.', 'error');
    return;
  }
  const button = $('#settings-password-submit');
  setSettingsMessage('');
  setAuthBusy(button, true, 'Changing…');
  try {
    const result = await postJSON('/api/auth/change-password', {
      current_password: $('#settings-current-password').value,
      new_password: $('#settings-new-password').value,
    });
    updateProfileUI(result.user);
    $('#settings-password-form').reset();
    setSettingsMessage('Password changed. Other sessions were signed out.', 'success');
  } catch (error) {
    setSettingsMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#btn-add-account').onclick = () => leaveDashboard('register');
$('#settings-add-account').onclick = () => leaveDashboard('register');

$('#tab-login').onclick = () => { setAuthMessage(''); showLogin('login'); };
$('#tab-register').onclick = () => { setAuthMessage(''); showLogin('register'); };
$$('.register-next').forEach((button) => {
  button.onclick = () => {
    if (validateRegisterStep(registerStep)) setRegisterStep(registerStep + 1);
  };
});
$$('.register-back').forEach((button) => {
  button.onclick = () => {
    setAuthMessage('');
    setRegisterStep(registerStep - 1);
  };
});
$('#btn-forgot-password').onclick = () => showForgotPassword($('#login-username').value.trim());
$('#btn-back-login').onclick = () => showLogin('login', $('#forgot-username').value.trim());
$('#btn-forgot-start-over').onclick = () => showForgotPassword($('#forgot-username').value.trim());

$('#forgot-lookup-form').onsubmit = async (event) => {
  event.preventDefault();
  const button = $('#btn-forgot-lookup');
  setAuthMessage('');
  setAuthBusy(button, true, 'Checking…');
  try {
    const result = await postJSON('/api/auth/forgot-password/question', {
      username: $('#forgot-username').value.trim(),
    });
    $('#forgot-question').textContent = result.question;
    $('#forgot-lookup-form').hidden = true;
    $('#forgot-reset-form').hidden = false;
    $('#forgot-answer').focus();
    setAuthMessage('Answer the question and choose a new password.', 'success');
  } catch (error) {
    setAuthMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#btn-request-reset-code').onclick = async (event) => {
  const button = event.currentTarget;
  setAuthMessage('');
  setAuthBusy(button, true, 'Sending…');
  try {
    const result = await postJSON('/api/auth/forgot-password/email/request', {
      username: $('#forgot-username').value.trim(),
    });
    $('#forgot-lookup-form').hidden = true;
    $('#forgot-reset-form').hidden = true;
    $('#forgot-email-reset-form').hidden = false;
    $('#forgot-email-code').focus();
    setAuthMessage(result.message || 'If this account has a verified Gmail address, a code has been sent.', 'success');
  } catch (error) {
    setAuthMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
};

$('#forgot-email-reset-form').onsubmit = (event) => {
  event.preventDefault();
  const newPassword = $('#forgot-email-new-password').value;
  if (newPassword !== $('#forgot-email-confirm-password').value) {
    setAuthMessage('Passwords do not match.', 'error');
    return;
  }
  submitAuth(
    event.currentTarget,
    $('#btn-forgot-email-reset'),
    '/api/auth/forgot-password/email/reset',
    {
      username: $('#forgot-username').value.trim(),
      code: $('#forgot-email-code').value.trim(),
      new_password: newPassword,
    },
  );
};
$('#btn-forgot-email-start-over').onclick = () => showForgotPassword($('#forgot-username').value.trim());

$('#forgot-reset-form').onsubmit = (event) => {
  event.preventDefault();
  const newPassword = $('#forgot-new-password').value;
  if (newPassword !== $('#forgot-confirm-password').value) {
    setAuthMessage('Passwords do not match.', 'error');
    return;
  }
  submitAuth(
    event.currentTarget,
    $('#btn-forgot-reset'),
    '/api/auth/forgot-password/reset',
    {
      username: $('#forgot-username').value.trim(),
      recovery_answer: $('#forgot-answer').value,
      new_password: newPassword,
    },
  );
};

async function submitAuth(form, button, path, payload) {
  setAuthMessage('');
  setAuthBusy(button, true, 'Please wait…');
  try {
    const result = await postJSON(path, payload);
    setAuthMessage('Account verified. Opening your secure workspace…', 'success');
    enterDashboard(result.user);
  } catch (error) {
    setAuthMessage(error.message, 'error');
  } finally {
    setAuthBusy(button, false);
  }
}

$('#login-form').onsubmit = (event) => {
  event.preventDefault();
  submitAuth(
    event.currentTarget,
    $('#btn-login'),
    '/api/auth/login',
    {
      username: $('#login-username').value.trim(),
      password: $('#login-password').value,
    },
  );
};

$('#register-form').onsubmit = (event) => {
  event.preventDefault();
  const password = $('#register-password').value;
  if (password !== $('#register-password-confirm').value) {
    setAuthMessage('Passwords do not match.', 'error');
    return;
  }
  submitAuth(
    event.currentTarget,
    $('#btn-register'),
    '/api/auth/register',
    {
      username: $('#register-username').value.trim(),
      password,
      mobile: $('#register-mobile').value.trim(),
      email: $('#register-email').value.trim(),
      recovery_question: $('#register-recovery-question').value,
      recovery_answer: $('#register-recovery-answer').value,
      monthly_summary: $('#register-monthly-summary').checked,
    },
  );
};

$('#btn-logout').onclick = async () => {
  $('#login-password').value = '';
  $('#register-password').value = '';
  $('#register-password-confirm').value = '';
  $('#register-email').value = '';
  $('#register-monthly-summary').checked = false;
  $('#register-recovery-question').value = '';
  $('#register-recovery-answer').value = '';
  setAuthMessage('You have been logged out.', 'success');
  await leaveDashboard('login');
};

async function checkSession() {
  const isLoginRoute = location.pathname === '/login' || location.pathname === '/ui-trial';
  const query = new URLSearchParams(location.search);
  const requestedMode = query.get('mode') === 'register' ? 'register' : 'login';
  const googleError = query.get('google_error');
  const googleErrorMessages = {
    setup: 'Google sign-in is not configured for this deployment yet.',
    cancelled: 'Google sign-in was cancelled.',
    state: 'The sign-in session expired. Please try again.',
    account: 'Google could not securely link this account. Check that your Google email is verified, then try again.',
    failed: 'Google sign-in could not be completed. Please try again.',
  };
  try {
    const result = await api('/api/auth/session');
    if (result.authenticated) enterDashboard(result.user);
    else if (isLoginRoute) {
      showLogin(requestedMode);
      if (googleErrorMessages[googleError]) setAuthMessage(googleErrorMessages[googleError], googleError === 'cancelled' ? '' : 'error');
    } else showLanding();
  } catch (error) {
    if (isLoginRoute) {
      showLogin(requestedMode);
      setAuthMessage('Unable to reach the authentication service. Please try again.', 'error');
    } else {
      showLanding();
    }
  }
}

/* -------------------------------------------------------------- Help AI ---- */
function scrollAssistant() {
  const box = $('#assistant-messages');
  box.scrollTop = box.scrollHeight;
}

function appendAssistantBubble(text, kind = 'ai', sources = [], suggestions = []) {
  const bubble = document.createElement('div');
  bubble.className = `assistant-bubble assistant-bubble-${kind}`;
  bubble.innerHTML = esc(text).replace(/\n/g, '<br>');
  if (sources.length) {
    const sourceBox = document.createElement('div');
    sourceBox.className = 'assistant-sources';
    sourceBox.innerHTML = `<div class="assistant-sources-title">Web sources</div>${sources.map((source) =>
      `<a class="assistant-source" href="${esc(source.url)}" target="_blank" rel="noopener noreferrer">${esc(source.title || source.url)}</a>`
    ).join('')}`;
    bubble.appendChild(sourceBox);
  }
  if (Array.isArray(suggestions) && suggestions.length) {
    const followups = document.createElement('div');
    followups.className = 'assistant-followups';
    suggestions.slice(0, 6).forEach((question) => {
      if (typeof question !== 'string' || !question.trim()) return;
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'assistant-followup';
      button.textContent = question;
      button.onclick = () => askAssistant(question);
      followups.appendChild(button);
    });
    if (followups.childElementCount) bubble.appendChild(followups);
  }
  $('#assistant-messages').appendChild(bubble);
  scrollAssistant();
  return bubble;
}

function openAssistant() {
  $('#assistant-panel').hidden = false;
  $('#assistant-input').focus();
  scrollAssistant();
}

function closeAssistant() {
  $('#assistant-panel').hidden = true;
}

async function askAssistant(question) {
  const value = (question || '').trim();
  if (!value || $('#assistant-send').disabled) return;
  $('#assistant-input').value = '';
  appendAssistantBubble(value, 'user');
  const loading = appendAssistantBubble('Checking the built-in app guide…', 'ai assistant-bubble-loading');
  $('#assistant-send').disabled = true;
  try {
    const result = await postJSON('/api/assistant', { question: value });
    loading.remove();
    appendAssistantBubble(result.answer, 'ai', result.sources || [], result.suggestions || []);
  } catch (error) {
    loading.remove();
    appendAssistantBubble(error.message, 'ai');
  } finally {
    $('#assistant-send').disabled = false;
    $('#assistant-input').focus();
  }
}

$('#help-ai-fab').onclick = openAssistant;
$('#sidebar-open-help').onclick = openAssistant;
$('#sidebar-open-notifications').onclick = () => {
  openSettings();
  openSettingsCategory('notifications');
};
$('#assistant-close').onclick = closeAssistant;
$('#assistant-form').onsubmit = (event) => {
  event.preventDefault();
  askAssistant($('#assistant-input').value);
};
$$('[data-assistant-question]').forEach((button) => {
  button.onclick = () => askAssistant(button.dataset.assistantQuestion);
});

let toastId = 0;
function toast(msg, kind = 'ok', ms = 5200) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<span>${esc(msg)}</span><button class="x" aria-label="Dismiss">×</button>`;
  $('#toasts').appendChild(el);
  const close = () => el.remove();
  el.querySelector('.x').onclick = close;
  setTimeout(close, ms);
}

/* ------------------------------------------------------------ tier vocabulary */
const TIERS = {
  malicious:   { label: 'Malicious',        icon: '⛔', color: 'var(--danger)' },
  suspicious:  { label: 'Suspicious',       icon: '⚠',  color: 'var(--warn)' },
  unknown:     { label: 'Unknown — verify', icon: '?',  color: 'var(--unknown)' },
  likely_safe: { label: 'Likely safe',      icon: '✓',  color: 'var(--ok)' },
  safe:        { label: 'Likely safe',      icon: '✓',  color: 'var(--ok)' },
  low:         { label: 'Low risk',         icon: '✓',  color: 'var(--ok)' },
};
const tierOf = (label) => TIERS[label] || TIERS.unknown;
const sevClass = (sev) => ({ critical: 'b-critical', high: 'b-high', medium: 'b-medium',
  low: 'b-low', info: 'b-info' }[sev] || 'b-info');

/* ------------------------------------------------------------------- theme */
const THEME_IDS = new Set(['signature', 'violet', 'blue', 'soft']);
function normalizeThemeId(value) {
  if (THEME_IDS.has(value)) return value;
  // Keep users' previous contrast preference when upgrading from the old toggle.
  if (value === 'light') return 'soft';
  return 'signature';
}
function applyTheme(themeId) {
  const selected = normalizeThemeId(themeId);
  const softContrast = selected === 'soft';
  document.documentElement.dataset.theme = softContrast ? 'light' : 'dark';
  document.documentElement.dataset.palette = selected;
  try { localStorage.setItem('pg-theme', selected); } catch { /* theme still applies for this session */ }
  $$('input[name="appearance-theme"]').forEach((input) => {
    input.checked = input.value === selected;
    input.closest('.theme-choice')?.classList.toggle('selected', input.checked);
  });
}
let initialTheme = 'signature';
try { initialTheme = normalizeThemeId(localStorage.getItem('pg-theme')); } catch { /* use the default */ }
$$('input[name="appearance-theme"]').forEach((input) => {
  input.addEventListener('change', () => {
    if (input.checked) applyTheme(input.value);
  });
});
applyTheme(initialTheme);

const sidebarToggle = $('#sidebar-toggle');
const sidebarProfileMore = $('.sidebar-profile-more');
if (sidebarProfileMore && window.matchMedia) {
  const compactSidebar = window.matchMedia('(max-width: 560px)');
  const syncSidebarProfileDisclosure = () => { sidebarProfileMore.open = !compactSidebar.matches; };
  syncSidebarProfileDisclosure();
  if (compactSidebar.addEventListener) compactSidebar.addEventListener('change', syncSidebarProfileDisclosure);
  else compactSidebar.addListener(syncSidebarProfileDisclosure);
}
function setSidebarHidden(hidden, persist = true) {
  const sidebar = $('#app-sidebar');
  $('#dashboard').classList.toggle('sidebar-hidden', hidden);
  sidebar.hidden = hidden;
  sidebar.setAttribute('aria-hidden', String(hidden));
  sidebarToggle.setAttribute('aria-expanded', String(!hidden));
  sidebarToggle.setAttribute('aria-label', hidden ? 'Show navigation panel' : 'Hide navigation panel');
  $('#sidebar-toggle-label').textContent = hidden ? 'Show panel' : 'Hide panel';
  syncAssistantVisibility();
  if (persist) {
    try { localStorage.setItem('pg-sidebar-hidden', hidden ? '1' : '0'); } catch { /* optional preference */ }
  }
}
let sidebarStartsHidden = false;
try { sidebarStartsHidden = localStorage.getItem('pg-sidebar-hidden') === '1'; } catch { /* storage may be unavailable */ }
setSidebarHidden(sidebarStartsHidden, false);
sidebarToggle.onclick = () => setSidebarHidden(!$('#dashboard').classList.contains('sidebar-hidden'));

/* ----------------------------------------------------------------- routing */
const ROUTES = {
  overview: { title: 'Overview', crumb: 'Your recent checks, saved evidence and next steps' },
  saved: { title: 'Saved scans', crumb: 'Organise important link and email checks into folders' },
  link: { title: 'Check a link', crumb: 'Review domain, infrastructure, reputation and redirect signals' },
  email: { title: 'Check an email', crumb: 'Review sender authentication, headers, links and attachments' },
  sweep: { title: 'Campaigns', crumb: 'Related reports, shared signals and campaign activity' },
};
function go(route) {
  if (!ROUTES[route]) route = 'overview';
  $$('.view').forEach((v) => { v.hidden = v.id !== `view-${route}`; });
  $$('.nav-item[data-route]').forEach((b) =>
    b.setAttribute('aria-current', b.dataset.route === route ? 'page' : 'false'));
  $('#page-title').textContent = ROUTES[route].title;
  $('#page-crumb').textContent = ROUTES[route].crumb;
  if (route === 'overview') renderPersonalDashboard();
  if (route === 'saved') renderSavedScans();
  if (route === 'sweep') loadSweep();
  history.replaceState(null, '', `#${route}`);
  window.scrollTo({ top: 0, behavior: 'instant' });
  if (route === 'link') $('#url-input').focus({ preventScroll: true });
}
$$('[data-route]').forEach((b) => { b.onclick = () => go(b.dataset.route); });
$$('[data-dashboard-route]').forEach((b) => { b.onclick = () => go(b.dataset.dashboardRoute); });
window.addEventListener('hashchange', () => {
  if (!$('#dashboard').hidden) go(location.hash.slice(1));
});

/* ------------------------------------------------------- recent checks ---- */
function getRecent() {
  try { return JSON.parse(localStorage.getItem('pg-recent') || '[]'); } catch { return []; }
}
function pushRecent(item) {
  const list = getRecent().filter((r) => r.label !== item.label);
  list.unshift({ ...item, ts: Date.now() });
  localStorage.setItem('pg-recent', JSON.stringify(list.slice(0, 7)));
  renderRecent();
}
function renderRecent() {
  const list = getRecent();
  const box = $('#recent');
  if (!list.length) {
    box.innerHTML = '<div class="recent-empty">Nothing checked yet</div>';
    return;
  }
  box.innerHTML = list.map((r, i) => {
    const t = tierOf(r.tier);
    return `<button class="recent-item" data-recent="${i}" title="${esc(r.label)}">
      <span class="dot" style="background:${t.color}"></span>
      <span>${esc(r.short || r.label)}</span></button>`;
  }).join('');
  $$('.recent-item', box).forEach((b) => {
    b.onclick = () => {
      const r = getRecent()[Number(b.dataset.recent)];
      go(r.kind === 'email' ? 'email' : 'link');
      if (r.kind === 'email') { $('#eml-raw').value = r.payload; setEmailMode('paste'); analyseEmail(r.payload, false); }
      else { $('#url-input').value = r.payload; analyseUrl(r.payload); }
    };
  });
}
renderRecent();

/* -------------------------------------------------------- saved scans ---- */
let savedFolderFilter = 'all';

function savedScansKey() {
  return `pg-saved-scans:${activeUser?.username || 'guest'}`;
}

function getSavedScans() {
  try {
    const value = JSON.parse(localStorage.getItem(savedScansKey()) || '[]');
    return Array.isArray(value) ? value.filter((item) => item && item.id && item.payload) : [];
  } catch { return []; }
}

function saveScan(item) {
  if (!activeUser) { toast('Log in before saving a scan', 'err'); return; }
  const chosen = window.prompt('Folder name for this scan:', item.folder || 'Unsorted');
  if (chosen === null) return;
  const folder = (chosen.trim().slice(0, 32) || 'Unsorted');
  const scans = getSavedScans();
  const existing = scans.find((saved) => saved.kind === item.kind && saved.payload === item.payload);
  const saved = {
    ...item,
    id: existing?.id || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    folder,
    ts: Date.now(),
  };
  const next = [saved, ...scans.filter((entry) => entry.id !== saved.id)].slice(0, 100);
  try {
    localStorage.setItem(savedScansKey(), JSON.stringify(next));
  } catch {
    toast('Browser storage is full. Remove an old saved scan first.', 'err');
    return;
  }
  renderSavedScans();
  renderPersonalDashboard();
  toast(`Saved in “${folder}”`);
}

function savedScanMarkup(item, compact = false) {
  const tier = tierOf(item.tier);
  return `<div class="saved-scan-row${compact ? ' compact' : ''}">
    <span class="dot" style="background:${tier.color}"></span>
    <div class="saved-scan-copy">
      <b>${esc(item.short || item.label || 'Saved scan')}</b>
      <span>${esc(item.kind === 'email' ? 'Email' : 'Link')} · ${esc(item.folder || 'Unsorted')} · ${esc(formatAccountDate(new Date(item.ts).toISOString()))}</span>
    </div>
    <span class="badge ${item.tier === 'malicious' ? 'b-critical' : item.tier === 'suspicious' ? 'b-high' : 'b-ok'}">${esc(tier.label)}</span>
    <button class="btn btn-ghost btn-sm" data-open-saved="${esc(item.id)}" type="button">Open</button>
    ${compact ? '' : `<button class="btn btn-icon btn-ghost btn-sm" data-delete-saved="${esc(item.id)}" type="button" aria-label="Delete saved scan">×</button>`}
  </div>`;
}

function openSavedScan(item) {
  if (!item) return;
  if (item.kind === 'email') {
    go('email');
    $('#eml-raw').value = item.payload;
    setEmailMode('paste');
    analyseEmail(item.payload, false);
  } else {
    go('link');
    $('#url-input').value = item.payload;
    analyseUrl(item.payload);
  }
}

function bindSavedScanButtons(root = document) {
  $$('[data-open-saved]', root).forEach((button) => {
    button.onclick = () => openSavedScan(getSavedScans().find((item) => item.id === button.dataset.openSaved));
  });
  $$('[data-delete-saved]', root).forEach((button) => {
    button.onclick = () => {
      if (!window.confirm('Remove this saved scan?')) return;
      const next = getSavedScans().filter((item) => item.id !== button.dataset.deleteSaved);
      localStorage.setItem(savedScansKey(), JSON.stringify(next));
      renderSavedScans();
      renderPersonalDashboard();
      toast('Saved scan removed');
    };
  });
}

function renderSavedScans() {
  const folderBox = $('#saved-folder-list');
  const listBox = $('#saved-scans-list');
  if (!folderBox || !listBox) return;
  const scans = getSavedScans();
  const folders = ['all', ...new Set(scans.map((item) => item.folder || 'Unsorted'))];
  folderBox.innerHTML = folders.map((folder) => `
    <button class="saved-folder${savedFolderFilter === folder ? ' active' : ''}" type="button" data-saved-folder="${esc(folder)}">
      ${folder === 'all' ? 'All scans' : esc(folder)}${folder === 'all' ? ` <span>${scans.length}</span>` : ` <span>${scans.filter((item) => (item.folder || 'Unsorted') === folder).length}</span>`}
    </button>`).join('');
  $$('[data-saved-folder]', folderBox).forEach((button) => {
    button.onclick = () => { savedFolderFilter = button.dataset.savedFolder; renderSavedScans(); };
  });
  const filtered = savedFolderFilter === 'all'
    ? scans
    : scans.filter((item) => (item.folder || 'Unsorted') === savedFolderFilter);
  $('#saved-scans-title').textContent = savedFolderFilter === 'all' ? 'All saved scans' : savedFolderFilter;
  $('#saved-scans-count').textContent = `${filtered.length} scan${filtered.length === 1 ? '' : 's'}`;
  listBox.innerHTML = filtered.length
    ? filtered.map((item) => savedScanMarkup(item)).join('')
    : '<div class="saved-empty"><b>No saved scans here.</b><span>Analyse a link or email and choose “Save scan” to create your library.</span></div>';
  bindSavedScanButtons(listBox);
}

function renderPersonalDashboard() {
  if (!activeUser) return;
  const displayName = activeUser.display_name || activeUser.username || 'there';
  $('#dashboard-user-name').textContent = displayName;
  const saved = getSavedScans();
  const recent = getRecent();
  const needsReview = saved.filter((item) => ['malicious', 'suspicious'].includes(item.tier)).length;

  $('#personal-kpis').innerHTML = `
    <div class="kpi"><div class="label">Recent checks</div><div class="value mono">${num(recent.length)}</div><div class="foot">on this device</div></div>
    <div class="kpi"><div class="label">Saved scans</div><div class="value mono">${num(saved.length)}</div><div class="foot">in your library</div></div>
    <div class="kpi"><div class="label">Flagged to review</div><div class="value mono">${num(needsReview)}</div><div class="foot">from saved results</div></div>`;

  const recentBox = $('#dashboard-recent-list');
  recentBox.innerHTML = recent.length
    ? recent.slice(0, 5).map((item, index) => {
        const tier = tierOf(item.tier);
        const name = item.short || item.label || (item.kind === 'email' ? 'Email scan' : 'Link scan');
        const kindLabel = item.kind === 'email' ? 'Email check' : 'Link check';
        return `<button class="overview-recent-item" type="button" data-overview-recent="${index}" data-tier="${esc(item.tier)}">
          <span class="overview-recent-dot" style="--activity-color:${tier.color}"></span>
          <span class="overview-recent-copy"><b>${esc(kindLabel)}</b><small>${esc(name)}</small></span>
          <span class="overview-recent-tier">${esc(tier.label)}</span><span class="overview-guide-arrow" aria-hidden="true">→</span>
        </button>`;
      }).join('')
    : '<div class="overview-empty"><span class="overview-empty-mark">✳</span><b>Your activity starts with a check.</b><span>Try a link or email to see its signals and evidence here.</span><button class="btn btn-primary btn-sm" type="button" data-dashboard-route="link">Check your first link →</button></div>';

  $$('[data-overview-recent]', recentBox).forEach((button) => {
    button.onclick = () => {
      const item = recent[Number(button.dataset.overviewRecent)];
      if (!item) return;
      if (item.kind === 'email') {
        go('email');
        $('#eml-raw').value = item.payload || '';
        setEmailMode('paste');
        if (item.payload) analyseEmail(item.payload, false);
      } else {
        go('link');
        $('#url-input').value = item.payload || '';
        if (item.payload) analyseUrl(item.payload);
      }
    };
  });
  $$('[data-dashboard-route]', recentBox).forEach((button) => {
    button.onclick = () => go(button.dataset.dashboardRoute);
  });

  const box = $('#dashboard-saved-list');
  box.innerHTML = saved.length
    ? saved.slice(0, 4).map((item) => savedScanMarkup(item, true)).join('')
    : '<div class="saved-empty"><b>Your saved library is empty.</b><span>Save important results into folders so you can review them later.</span></div>';
  bindSavedScanButtons(box);
}

/* ---------------------------------------------------------------- header ---- */
async function loadHeader() {
  try {
    const h = await api('/api/health');
    const keys = Object.entries(h.intel || {}).filter(([, v]) => v).map(([k]) => k);
    const reputationStatus = keys.length ? keys.join(', ') : 'No reputation keys configured';
    $('#engine-ver').textContent = '0.9.0';
    $('#engine-intel').textContent = reputationStatus;
    $('#engine-domains').textContent = num(h.stats.domains_seen);
    $('#engine-reports').textContent = num(h.stats.reports);
    $('#chip-intel').innerHTML = `<span class="dot" style="background:${keys.length ? 'var(--ok)' : 'var(--warn)'}"></span> reputation <b>${esc(keys.length ? keys.join(' + ') : 'BYO key needed')}</b>`;
    $('#chip-clusters').innerHTML = `<span class="dot" style="background:var(--accent)"></span> clusters <b>${num(h.stats.clusters)}</b>`;
    return h;
  } catch { return null; }
}

/* ============================================================================
   Shared renderers
   ========================================================================== */

function gauge(score, tierLabel) {
  const r = 44, c = 2 * Math.PI * r;
  const off = c * (1 - Math.max(0, Math.min(100, score)) / 100);
  return `<div class="gauge" role="img" aria-label="Risk score ${score} out of 100">
    <svg viewBox="0 0 104 104" width="104" height="104">
      <circle class="track" cx="52" cy="52" r="${r}" fill="none" stroke-width="9"/>
      <circle class="fill" cx="52" cy="52" r="${r}" fill="none" stroke-width="9"
              stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}"
              stroke-dashoffset="${off.toFixed(1)}"/>
    </svg>
    <div class="num">${esc(score)}<small>/ 100</small></div>
  </div>`;
}

function verdictHero(v, opts = {}) {
  const t = tierOf(v.label);
  const facts = opts.facts || '';
  const sigs = v.signals || [];
  const contentN = sigs.filter((s) => ['content', 'auth', 'attachment', 'reputation'].includes(s.category)).length;
  const trust = (v.label === 'malicious' || v.label === 'suspicious') && contentN === 0
    ? `<span class="chip" title="Every signal came from naming, infrastructure or language — we never observed the payload itself.">
         <span class="dot" style="background:var(--warn)"></span> naming evidence only — payload not observed</span>`
    : (contentN > 0 ? `<span class="chip"><span class="dot" style="background:var(--ok)"></span> ${contentN} content-level signal${contentN === 1 ? '' : 's'}</span>` : '');
  return `<div class="verdict" data-tier="${esc(v.label)}">
    <div class="verdict-inner">
      ${gauge(v.score, v.label)}
      <div class="verdict-copy">
        <span class="verdict-tier">${t.icon} ${esc(t.label)}</span>
        <h2>${esc(v.headline)}</h2>
        <div class="lede">${esc(v.explain)}</div>
        <div class="verdict-meta">
          <span class="chip"><span class="dot" style="background:${v.intel_ok ? 'var(--ok)' : 'var(--warn)'}"></span>
            ${v.intel_ok ? 'corroborated'
              : (v.provisional ? 'instant pass · verifying' : 'degraded — lexical only')}</span>
          <span class="chip">evidence strength <b>${esc(v.confidence)}</b></span>
          <span class="chip" title="${esc(v.confidence_text)}">${esc(v.confidence_text)}</span>
          ${trust}
          ${v.receipt_id ? `<span class="chip mono">${esc(v.receipt_id)}</span>` : ''}
        </div>
      </div>
      <div class="verdict-actions">
        ${opts.saveScan ? `<button class="btn btn-primary btn-sm" data-act="save">☆ Save scan</button>` : ''}
        <button class="btn btn-ghost btn-sm" data-act="receipt">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="14" height="14"><path d="M4 2v20l3-2 3 2 3-2 3 2 3-2V2l-3 2-3-2-3 2-3-2-3 2Z"/><path d="M8 8h8M8 12h6"/></svg>
          View receipt</button>
        <button class="btn btn-ghost btn-sm" data-act="copy">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" width="14" height="14"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          Copy defanged</button>
      </div>
    </div>
    ${facts ? `<div class="factstrip">${facts}</div>` : ''}
  </div>`;
}

const fact = (k, v, cls = '') => `<div class="f"><div class="k">${esc(k)}</div><div class="v ${cls}">${v}</div></div>`;

function signalsCard(v) {
  const counts = v.counts || {};
  const total = (v.signals || []).length;
  if (!total) {
    return `<div class="card"><div class="card-head"><h3 class="card-title">Evidence</h3></div>
      <div class="card-body"><div class="callout good"><b>No signals fired.</b>
      <div class="sub">Absence of evidence is not evidence of safety — it means we found nothing to argue with.</div></div></div></div>`;
  }
  const chips = [
    ['all', total], ['critical', counts.critical || 0], ['high', counts.high || 0],
    ['medium', counts.medium || 0], ['low', (counts.low || 0) + (counts.info || 0)],
  ].filter(([, n]) => n > 0 || true);

  const rows = v.signals.map((s) => `
    <div class="sig" data-sev="${esc(s.severity)}">
      <div class="sig-rail"></div>
      <div class="sig-main">
        <div class="sig-title">${esc(s.title)}
          <span class="badge ${sevClass(s.severity)}">${esc(s.severity)}</span>
          <span class="sig-meta">${esc(s.category)} · w${esc(s.weight)}</span></div>
        <div class="sig-ev">${esc(s.evidence)}</div>
        ${s.tip ? `<div class="sig-tip"><b>Remember:</b> ${esc(s.tip)}</div>` : ''}
      </div>
    </div>`).join('');

  return `<div class="card">
    <div class="card-head">
      <h3 class="card-title">Evidence chain</h3>
      <span class="faint tiny">${total} signal${total === 1 ? '' : 's'}</span>
      <div class="spacer"></div>
      <div class="filters">
        ${chips.map(([k, n], i) => `<button class="filter" data-filter="${k}" aria-pressed="${i === 0}">${k} · ${n}</button>`).join('')}
      </div>
    </div>
    <div class="card-body" id="sig-list">${rows}</div>
  </div>`;
}

function bindFilters(root) {
  $$('.filter', root).forEach((b) => {
    b.onclick = () => {
      $$('.filter', root).forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      const k = b.dataset.filter;
      $$('.sig', root).forEach((s) => {
        const sev = s.dataset.sev;
        const show = k === 'all' || (k === 'low' ? (sev === 'low' || sev === 'info') : sev === k);
        s.hidden = !show;
      });
    };
  });
}

function blastCard(b, preview) {
  if (!b) return '';
  const bad = ['credential_theft', 'malware', 'payment_fraud'].includes(b.risk);
  // If nothing fired at content level AND we could not load the page, saying
  // "no active content detected" would be a false clearance. Say what's true.
  const unobserved = b.risk === 'low' && preview && preview.ok === false;
  const body = unobserved
    ? `<div class="callout warn"><b>Not verified — the page never loaded.</b>
        <div class="sub">We could not observe the destination, so we cannot rule out a credential
        form or a redirect. Treat the blast radius as unknown, not empty.</div>
        <div class="sub faint" style="margin-top:6px">${esc(preview.error || '')}</div></div>`
    : `<div class="callout ${bad ? 'bad' : ''}">
        <b>${esc(b.summary)}</b><div class="sub">${esc(b.consequence)}</div></div>`;
  return `<div class="card"><div class="card-head"><h3 class="card-title">What happens if you click</h3></div>
    <div class="card-body">${body}</div></div>`;
}

function nextStepsCard(v) {
  return `<div class="card"><div class="card-head"><h3 class="card-title">Do this now</h3></div>
    <div class="card-body">
      <ol class="steps">${(v.next_steps || []).map((s) => `<li><span>${esc(s)}</span></li>`).join('')}</ol>
      <hr class="sep">
      <div class="callout"><b>Out-of-band challenge</b>
        <div class="sub">${esc(v.out_of_band.question)}</div>
        <div class="sub faint" style="margin-top:7px">${esc(v.out_of_band.principle)}</div>
      </div>
    </div></div>`;
}

function tipsCard(v) {
  if (!v.tips || !v.tips.length) return '';
  return `<div class="card"><div class="card-head"><h3 class="card-title">What to look for next time</h3>
      <div class="spacer"></div><span class="faint tiny">teach-in-the-moment</span></div>
    <div class="card-body"><div class="tile-grid">
      ${v.tips.map((t, i) => `<div class="tile"><div class="n">0${i + 1}</div><p>${esc(t)}</p></div>`).join('')}
    </div></div></div>`;
}

function infraCard(f) {
  if (!f) return '';
  const reg = f.registration || {}, dns = f.dns || {}, tls = f.tls || {};
  const rows = [
    ['registrable domain', esc(f.registrable_domain || '—')],
    ['displayed host', esc(f.display_host || '—')],
    ['brand impersonated', f.brand_impersonated ? `<span style="color:var(--danger)">${esc(f.brand_impersonated)}</span>` : '—'],
    ['registered', reg.registered ? esc(reg.registered) : esc(reg.error || 'unknown')],
    ['domain age', reg.age_days != null ? `${num(reg.age_days)} days` : 'unknown'],
    ['registrar', esc(reg.registrar || 'unknown')],
    ['resolves', dns.resolves ? 'yes' : 'no'],
    ['MX', (dns.mx || []).length ? esc(dns.mx.slice(0, 2).join(', ')) : 'none'],
    ['SPF', dns.spf ? esc(dns.spf.slice(0, 64)) : 'none published'],
    ['DMARC', dns.dmarc ? esc(dns.dmarc.slice(0, 64)) : 'none published'],
    ['TLS', tls.ok ? `ok · ${esc(tls.issuer || '?')} · ${esc(tls.not_before_days)}d old`
      : esc(tls.error || 'not checked')],
  ];
  if (f.baseline) {
    rows.push(['org baseline', f.baseline.first_contact
      ? '<span style="color:var(--warn)">first time seen here</span>'
      : `seen ${esc(f.baseline.hits)}× since ${esc((f.baseline.first_seen || '').slice(0, 10))}`]);
  }
  if (f.time_of_click && f.time_of_click.seen_before) {
    rows.push(['time-of-click', f.time_of_click.previously_clean_now_bad
      ? '<span style="color:var(--danger)">was clean when first seen, now hostile</span>'
      : (f.time_of_click.content_changed ? 'content changed since first seen' : 'unchanged since first seen')]);
  }
  return `<div class="card"><div class="card-head"><h3 class="card-title">Infrastructure</h3></div>
    <div class="card-body"><dl class="kv">
      ${rows.map(([k, val]) => `<dt>${esc(k)}</dt><dd>${val}</dd>`).join('')}
    </dl></div></div>`;
}

function previewCard(p) {
  if (!p) return '';
  const head = `<div class="card-head"><h3 class="card-title">What you'd land on</h3>
      <div class="spacer"></div>
      <span class="faint tiny">read-only HTML fetch · JS disabled</span></div>`;
  if (!p.ok) {
    return `<div class="card">${head}<div class="card-body">
      <div class="callout warn"><b>Could not fetch a preview</b>
        <div class="sub">${esc(p.error || 'unreachable')}</div>
        <div class="sub faint" style="margin-top:6px">A page that fails to load today can be armed tomorrow.
        This is a time-of-click risk, not a clearance.</div></div></div></div>`;
  }
  const forms = (p.forms || []).length ? `<table class="table" style="margin-top:12px">
      <thead><tr><th>form target</th><th>method</th><th>captures</th><th>fields</th></tr></thead>
      <tbody>${p.forms.map((f) => `<tr>
        <td class="mono">${esc(f.action_host || 'same site')}${f.is_external ? ' <span class="badge b-critical">external</span>' : ''}</td>
        <td>${esc(f.method)}</td>
        <td>${f.has_password ? '<span class="badge b-critical">password</span>' : '—'}</td>
        <td class="mono tiny">${esc((f.fields || []).join(', ') || '—')}</td></tr>`).join('')}</tbody></table>` : '';
  const ext = (p.external_form_actions || []).map((e) => `<div class="callout bad" style="margin-top:10px">
      Password field POSTs to <span class="mono">${esc(e.host)}</span> — a different domain from the page you'd be looking at.
      That is credential harvesting.</div>`).join('');
  return `<div class="card">${head}<div class="card-body">
    <dl class="kv">
      <dt>final URL</dt><dd class="defang">${esc(p.final_url_defanged)}</dd>
      <dt>redirect hops</dt><dd>${esc(p.redirect_hops)}</dd>
      <dt>page title</dt><dd>${esc(p.title || '—')}</dd>
      <dt>http status</dt><dd>${esc(p.status)}</dd>
    </dl>
    ${ext}${forms}
    ${p.text_snippet ? `<div class="callout" style="margin-top:12px"><b>Visible text</b>
      <div class="sub">“${esc(p.text_snippet.slice(0, 260))}…”</div></div>` : ''}
    ${(p.js_redirects || []).length ? `<div class="callout warn" style="margin-top:10px">
      JS / meta redirect to <span class="mono defang">${esc(p.js_redirects[0])}</span></div>` : ''}
    <div class="faint tiny" style="margin-top:12px">${esc(p.disclaimer)}</div>
  </div></div>`;
}

function receiptButton(v, root, saveItem = null) {
  $$('[data-act="receipt"]', root).forEach((b) => {
    b.onclick = () => openReceipt(v.receipt_id);
  });
  $$('[data-act="copy"]', root).forEach((b) => {
    b.onclick = async () => {
      const text = (v.facts && v.facts.defanged) || v.subject || '';
      if (!text) { toast('Nothing to copy', 'err'); return; }
      try {
        await navigator.clipboard.writeText(text);
        toast('Copied — safe to paste into a ticket or chat');
      } catch { toast('Clipboard blocked by the browser', 'err'); }
    };
  });
  $$('[data-act="save"]', root).forEach((b) => {
    b.onclick = () => saveScan(saveItem);
  });
}

/* ------------------------------------------------------------------ drawer */
async function openReceipt(rid) {
  if (!rid) { toast('No receipt for this verdict', 'err'); return; }
  $('#drawer-code').textContent = 'Loading…';
  $('#scrim').classList.add('open');
  $('#drawer').classList.add('open');
  $('#drawer').setAttribute('aria-hidden', 'false');
  try {
    const data = await api(`/api/receipt/${encodeURIComponent(rid)}`);
    $('#drawer-code').textContent = JSON.stringify(data, null, 2);
    $('#drawer-title').textContent = `Audit receipt · ${rid}`;
  } catch (e) {
    $('#drawer-code').textContent = `Could not load receipt: ${e.message}`;
  }
}
function closeDrawer() {
  $('#scrim').classList.remove('open');
  $('#drawer').classList.remove('open');
  $('#drawer').setAttribute('aria-hidden', 'true');
}
$('#scrim').onclick = closeDrawer;
$('#drawer-close').onclick = closeDrawer;
$('#drawer-copy').onclick = async () => {
  try {
    await navigator.clipboard.writeText($('#drawer-code').textContent);
    toast('Receipt copied to clipboard');
  } catch { toast('Clipboard blocked by the browser', 'err'); }
};
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeDrawer();
  if (e.key === '/' || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k')) {
    const el = document.activeElement;
    if (el && /INPUT|TEXTAREA/.test(el.tagName)) return;
    e.preventDefault();
    go('link'); $('#url-input').focus();
  }
  if (!(e.metaKey || e.ctrlKey) && /INPUT|TEXTAREA/.test(document.activeElement?.tagName || '')) return;
  if (e.key === '1') go('link');
  if (e.key === '2') go('email');
  if (e.key === '3') go('sweep');
});

/* ============================================================================
   LINK flow
   ========================================================================== */
let lastUrl = '';

function setStage(name, state) {
  const el = $(`.stage[data-stage="${name}"]`);
  if (el) el.dataset.state = state;
}
function resetStages() {
  $$('#url-pipeline .stage').forEach((s) => { s.dataset.state = ''; });
}

function scanMeterState(state = 'idle', includeReputation = false) {
  const loading = state === 'loading';
  const description = loading
    ? `Checking the URL structure, domain registration, DNS and TLS${includeReputation ? ', plus the reputation providers you selected' : ''}. Your result card will appear when the analysis is complete.`
    : 'Paste a link above and select Analyse. PhishGuard checks its structure and available infrastructure signals without opening the page.';
  return `<section class="scan-meter-state ${loading ? 'is-loading' : 'is-idle'}"
      ${loading ? 'role="status" aria-live="polite" aria-busy="true"' : 'aria-label="Link scan meter"'}>
    <div class="scan-meter-visual" aria-hidden="true">
      <svg class="scan-meter-ring" viewBox="0 0 120 120">
        <circle class="scan-meter-track" cx="60" cy="60" r="47" />
        <circle class="scan-meter-active" cx="60" cy="60" r="47" />
      </svg>
      <span class="scan-meter-needle"></span>
      <span class="scan-meter-hub"></span>
      <div class="scan-meter-readout"><b>${loading ? '···' : '—'}</b><small>${loading ? 'ANALYZING' : 'READY'}</small></div>
    </div>
    <div class="scan-meter-copy">
      <span class="scan-meter-eyebrow">${loading ? 'LINK ANALYSIS IN PROGRESS' : 'YOUR LINK RISK METER'}</span>
      <h3>${loading ? 'Reading the signals…' : 'Ready for your first link'}</h3>
      <p>${description}</p>
      <div class="scan-meter-foot"><span class="scan-meter-status-dot"></span>${loading ? 'Checking signals now' : 'No scan has started yet'}</div>
    </div>
  </section>`;
}

async function analyseUrl(url) {
  const out = $('#url-out');
  const includeReputation = $('#url-reputation-consent').checked;
  lastUrl = url;
  $('#url-pipeline').hidden = false;
  resetStages();
  $('#btn-url').disabled = true;
  out.innerHTML = scanMeterState('loading', includeReputation);
  setStage('lexical', 'run');

  let quick;
  try {
    quick = await postJSON('/api/check/url?mode=quick', { url });
  } catch (e) {
    $('#btn-url').disabled = false;
    setStage('lexical', '');
    $('#url-pipeline').hidden = true;
    out.innerHTML = `<div class="card card-pad"><div class="callout bad"><b>Could not analyse that.</b>
      <div class="sub">${esc(e.message)}</div></div></div>`;
    toast(e.message, 'err');
    return;
  }
  setStage('lexical', 'done');
  setStage('infra', 'run');
  setStage('rep', includeReputation ? 'run' : 'skip');
  setStage('preview', 'run');

  const f = quick.facts || {};
  const quickSaveItem = { kind: 'url', label: f.defanged || url, short: url.replace(/^https?:\/\//, '').slice(0, 32), tier: quick.label, score: quick.score, payload: url };

  let full;
  try {
    full = await postJSON('/api/check/url', {
      url,
      include_reputation: includeReputation,
    });
  } catch (e) {
    ['infra', 'rep', 'preview', 'baseline'].forEach((s) => setStage(s, ''));
    $('#btn-url').disabled = false;
    const degradedQuick = { ...quick, provisional: false, intel_ok: false };
    const quickFacts = fact('registrable domain', esc(f.registrable_domain || '—'))
      + fact('in this workspace', (f.baseline && f.baseline.first_contact)
        ? '<span style="color:var(--warn)">first contact</span>'
        : `seen ${esc(f.baseline ? f.baseline.hits : 0)}×`)
      + fact('pass', 'lexical only')
      + fact('latency', '~5 ms');
    out.innerHTML = verdictHero(degradedQuick, { saveScan: true, facts: quickFacts })
      + `<div class="callout warn" style="margin-bottom:0">
        <b>Full analysis could not finish.</b> <span class="muted">${esc(e.message)} The result below uses the instant lexical check only; infrastructure signals are unknown.</span></div>`
      + signalsCard(quick);
    bindFilters(out);
    receiptButton(degradedQuick, out, quickSaveItem);
    toast('Degraded mode: infrastructure lookups unavailable', 'err');
    pushRecent({ kind: 'url', label: quick.facts.defanged, short: url.slice(0, 34), tier: quick.label, payload: url });
    notifyScanComplete('link', quick, url.replace(/^https?:\/\//, '').slice(0, 42));
    return;
  }
  ['infra', 'preview', 'baseline'].forEach((s) => setStage(s, 'done'));
  setStage('rep', includeReputation ? 'done' : 'skip');
  $('#btn-url').disabled = false;

  const reg = (full.facts && full.facts.registration) || {};
  const dns = (full.facts && full.facts.dns) || {};
  const tls = (full.facts && full.facts.tls) || {};
  const facts = fact('registrable domain', esc((full.facts || {}).registrable_domain || '—'))
    + fact('domain age', reg.age_days != null
      ? `<span style="color:${reg.age_days <= 30 ? 'var(--danger)' : 'inherit'}">${num(reg.age_days)} days</span>`
      : 'unknown')
    + fact('DNS', dns.resolves ? `resolves · ${(dns.a || []).length} A` : '<span style="color:var(--warn)">no A record</span>')
    + fact('TLS', tls.ok ? `valid · ${esc(tls.not_before_days)}d` : (tls.error ? 'invalid' : 'n/a'))
    + fact('independent data', full.intel_ok ? 'available' : 'degraded')
    + fact('third-party URL check', includeReputation ? 'enabled for configured providers' : 'not shared');

  const fullSaveItem = { kind: 'url', label: full.facts.defanged || url, short: url.replace(/^https?:\/\//, '').slice(0, 32), tier: full.label, score: full.score, payload: url };
  out.innerHTML = verdictHero(full, { saveScan: true, facts })
    + `<div class="grid grid-2">${blastCard(full.blast_radius, full.preview)}${nextStepsCard(full)}</div>`
    + signalsCard(full)
    + `<div class="grid grid-2">${infraCard(full.facts)}${previewCard(full.preview)}</div>`
    + tipsCard(full);
  bindFilters(out);
  receiptButton(full, out, fullSaveItem);

  pushRecent({ kind: 'url', label: full.facts.defanged || url, short: url.replace(/^https?:\/\//, '').slice(0, 32), tier: full.label, payload: url });
  notifyScanComplete('link', full, url.replace(/^https?:\/\//, '').slice(0, 42));
  loadHeader();
}

$('#url-out').innerHTML = scanMeterState('idle');

$('#btn-url').onclick = () => {
  const u = $('#url-input').value.trim();
  if (!u) { toast('Paste a link first', 'err'); $('#url-input').focus(); return; }
  analyseUrl(u);
};
$('#url-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#btn-url').click(); });
$('#url-input').addEventListener('input', (e) => { $('#url-clear').hidden = !e.target.value; });
$('#url-clear').onclick = () => {
  $('#url-input').value = '';
  $('#url-clear').hidden = true;
  $('#url-out').innerHTML = scanMeterState('idle');
  $('#url-pipeline').hidden = true;
  $('#url-input').focus();
};
$$('[data-demo]').forEach((b) => { b.onclick = () => { $('#url-input').value = b.dataset.demo; analyseUrl(b.dataset.demo); }; });

/* ============================================================================
   EMAIL flow
   ========================================================================== */
let emailMode = 'file';
let selectedFile = null;

function setEmailMode(mode) {
  emailMode = mode;
  $$('[data-emode]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.emode === mode)));
  $('#eml-raw').hidden = mode !== 'paste';
  $('#eml-drop').hidden = mode !== 'file';
}

$$('[data-emode]').forEach((b) => { b.onclick = () => setEmailMode(b.dataset.emode); });

const drop = $('#eml-drop');
const fileInput = $('#eml-file');
drop.onclick = () => fileInput.click();
drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } };
fileInput.onchange = () => {
  selectedFile = fileInput.files[0] || null;
  if (selectedFile) {
    drop.classList.add('hasfile');
    $('#drop-title').textContent = selectedFile.name;
    $('#drop-sub').textContent = `${(selectedFile.size / 1024).toFixed(1)} KB · ready to analyse`;
  }
};
['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => {
  e.preventDefault(); drop.classList.add('over');
}));
['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => {
  e.preventDefault(); drop.classList.remove('over');
}));
drop.addEventListener('drop', (e) => {
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  if (!f) return;
  selectedFile = f;
  const dt = new DataTransfer();
  dt.items.add(f);
  fileInput.files = dt.files;
  drop.classList.add('hasfile');
  $('#drop-title').textContent = f.name;
  $('#drop-sub').textContent = `${(f.size / 1024).toFixed(1)} KB · ready to analyse`;
});

function authStrip(a, dkimVerified) {
  const order = [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC'], ['arc', 'ARC']];
  return order.map(([k, label]) => {
    const val = a && a[k];
    const cls = val === 'pass' ? 'pass' : (val === 'fail' ? 'fail' : (val ? 'mid' : ''));
    const shown = val === 'none' ? 'none' : (val || 'absent');
    const note = k === 'dkim'
      ? (dkimVerified === true ? 'signature verified' : dkimVerified === false ? 'verification failed' : 'header only')
      : '';
    return `<div class="authpill ${cls}">
      <div class="name">${esc(label)}</div>
      <div class="val">${esc(shown)}</div>
      ${note ? `<div class="note">${esc(note)}</div>` : ''}
    </div>`;
  }).join('');
}

function identityCard(e) {
  const dom = (s) => (String(s || '').split('@')[1] || '').toLowerCase();
  const flagged = (x, y) => x && y && dom(x) !== dom(y);
  const rows = [
    ['from', esc(e.from_display || '—') + ' &lt;' + esc(e.from_addr || '—') + '&gt;', false],
    ['reply-to', e.reply_to ? `<span class="defang">${esc(e.reply_to)}</span>` : '—',
      flagged(e.reply_to, e.from_addr)],
    ['return-path', e.return_path ? `<span class="defang">${esc(e.return_path)}</span>` : '—',
      flagged(e.return_path, e.from_addr)],
    ['subject', esc(e.subject), false],
    ['date', esc(e.date || '—'), false],
    ['message-id', esc(e.message_id || '—'), false],
    ['received', `${esc(e.received?.hops ?? '—')} hops${e.received?.anomaly ? ' · <span class="hl">injected hop</span>' : ''}`, !!e.received?.anomaly],
  ];
  return `<div class="card"><div class="card-head"><h3 class="card-title">Sender identity</h3>
      <div class="spacer"></div>
      <span class="faint tiny">only the address after @ identifies the sender</span></div>
    <div class="card-body">
      <div class="authstrip" style="margin-bottom:16px">${authStrip(e.auth, e.dkim_verified)}</div>
      <div class="ident">
        ${rows.map(([k, v, flag]) => `<div class="ident-row ${flag ? 'flag' : ''}">
          <div class="k">${esc(k)}</div><div class="v">${v}</div></div>`).join('')}
      </div>
    </div></div>`;
}

function linksCard(links) {
  if (!links || !links.length) {
    return `<div class="card"><div class="card-head"><h3 class="card-title">Links in the body</h3></div>
      <div class="card-body"><div class="faint small">No links found in this message.</div></div></div>`;
  }
  const rows = links.map((l, i) => `<tr>
    <td class="mono defang" style="max-width:280px">${esc(l.href_defanged)}</td>
    <td class="small">${l.display_text ? esc(l.display_text) : '<span class="faint">—</span>'}
      ${l.display_mismatch ? '<div><span class="badge b-critical">text lies</span></div>' : ''}</td>
    <td><span class="badge ${l.score >= 65 ? 'b-critical' : l.score >= 30 ? 'b-high' : 'b-ok'}">${esc(l.score)}</span></td>
    <td class="small muted">${esc((l.signals || []).slice(0, 2).map((s) => s.title).join('; ') || '—')}</td>
    <td><button class="btn btn-ghost btn-sm" data-deep="${i}">Deep scan</button></td>
  </tr>`).join('');
  return `<div class="card"><div class="card-head"><h3 class="card-title">Links in the body</h3>
      <span class="faint tiny">${links.length}</span>
      <div class="spacer"></div>
      <span class="faint tiny">scores are lexical — deep scan adds infrastructure + preview</span></div>
    <div class="card-body" style="padding:0">
      <table class="table"><thead><tr><th>href (defanged)</th><th>display text</th><th>score</th><th>why</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>
    <div id="deep-out" style="padding:0 20px 20px"></div>
  </div>`;
}

function attachmentsCard(atts) {
  if (!atts || !atts.length) {
    return `<div class="card"><div class="card-head"><h3 class="card-title">Attachments</h3></div>
      <div class="card-body"><div class="faint small">None.</div></div></div>`;
  }
  const rows = atts.map((a) => `<tr>
    <td class="mono">${esc(a.filename)}</td>
    <td class="num">${a.size < 1024 ? `${a.size} B` : `${(a.size / 1024).toFixed(1)} KB`}</td>
    <td>${a.macro_enabled ? '<span class="badge b-high">macro</span> ' : ''}${a.encrypted_archive ? '<span class="badge b-critical">encrypted zip</span> ' : ''}${a.double_extension ? '<span class="badge b-critical">double extension</span>' : ''}${(!a.macro_enabled && !a.encrypted_archive && !a.double_extension) ? '<span class="faint">—</span>' : ''}</td>
    <td class="mono tiny faint">${esc(a.sha256.slice(0, 24))}…</td></tr>`).join('');
  return `<div class="card"><div class="card-head"><h3 class="card-title">Attachments</h3>
      <span class="faint tiny">${atts.length}</span></div>
    <div class="card-body" style="padding:0">
      <table class="table"><thead><tr><th>filename</th><th>size</th><th>flags</th><th>sha256</th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>
    <div class="card-body" style="padding-top:12px"><div class="faint tiny">
      Files are hashed locally and never opened or executed. Add a VirusTotal key to auto-check these hashes.</div></div>
  </div>`;
}

function paymentCard(v) {
  const accts = v.accounts_found || [];
  const vendor = accts.length ? accts[0].vendor : '';
  return `<div class="card"><div class="card-head"><h3 class="card-title">Payment identifiers</h3></div>
    <div class="card-body">
      ${accts.length ? `<dl class="kv">${accts.map((a) =>
        `<dt>${esc(a.vendor || 'account')}</dt><dd class="defang">${esc(a.value)}</dd>`).join('')}</dl>` :
        '<div class="faint small">No account numbers, IBANs or IFSC codes found.</div>'}
      <div class="faint tiny" style="margin-top:12px">
        Diffed against the vendor's <b>trusted</b> baseline. A value taken from an unverified message never
        becomes the baseline — otherwise one fraudulent invoice would poison the reference and the second
        attempt would look clean.
      </div>
      ${vendor ? `<div class="row" style="margin-top:12px">
        <button class="btn btn-ghost btn-sm" data-confirm="${esc(vendor)}">I verified this by phone → update baseline</button>
      </div><div id="confirm-out" style="margin-top:9px"></div>` : ''}
    </div></div>`;
}

function reportCard(v, e) {
  const c = v.cluster || { reports: 0, clicked: 0 };
  const multi = (c.reports || 0) > 1;
  return `<div class="card"><div class="card-head"><h3 class="card-title">Report to sweep</h3>
      <div class="spacer"></div>
      ${multi ? `<span class="badge b-critical">${esc(c.reports)} reports · ${esc(c.clicked)} clicked</span>` : ''}</div>
    <div class="card-body">
      <div class="callout ${multi ? 'bad' : ''}">
        ${multi
          ? `<b>${esc(c.reports)} people have reported this campaign.</b> ${esc(c.clicked)} clicked.
             Reporting now warns everyone else who received it.`
          : 'First report of this campaign here. Reporting clusters any future copy automatically.'}
      </div>
      <div class="input-row" style="margin-top:14px;flex-wrap:wrap;align-items:center">
        <label class="field" style="flex:0 0 220px">
          <input id="reporter" type="text" placeholder="your name / desk (optional)" style="font-family:var(--sans)">
        </label>
        <label class="small muted" style="display:flex;align-items:center;gap:7px;white-space:nowrap">
          <input type="checkbox" id="clicked-cb"> I already clicked it</label>
        <button class="btn btn-primary btn-sm" id="btn-report">Report → sweep org</button>
      </div>
      <div id="report-out" style="margin-top:12px"></div>
    </div></div>`;
}

function postClickCard() {
  return `<div class="card" id="post-click"><div class="card-head">
      <h3 class="card-title">Post-click response</h3>
      <div class="spacer"></div><span class="badge b-critical">you already clicked</span></div>
    <div class="card-body">
      <div class="callout bad"><b>Order matters.</b>
        <div class="sub">Do these in sequence, fastest blast radius first.</div></div>
      <ol class="steps" style="margin-top:14px">
        <li><span><b>Revoke sessions now</b> — “sign out everywhere” for that account. Changing the password alone leaves the attacker's token alive.</span></li>
        <li><span><b>Change the password</b> from a known-clean device, then re-register MFA.</span></li>
        <li><span><b>Check mailbox rules</b> for auto-forward, hidden folders or delegate access — the standard way attackers keep reading mail after a reset.</span></li>
        <li><span><b>Check sent items and OAuth consents</b> for anything you did not authorise.</span></li>
        <li><span><b>Tell your security team with the receipt ID</b> so they can sweep the cluster and warn the other recipients.</span></li>
        <li><span>If card or payment details were entered: <b>call the bank now</b> — recall odds drop sharply after 24 hours.</span></li>
      </ol>
    </div></div>`;
}

async function analyseEmail(payload, isFile) {
  const out = $('#email-out');
  $('#btn-eml').disabled = true;
  out.innerHTML = `<div class="card card-pad"><div style="display:flex;align-items:center;gap:12px">
      <span class="spinner"></span><div><b>Parsing message…</b>
      <div class="faint small">verifying DKIM, walking the Received chain, scoring links</div></div></div></div>`;

  let v;
  try {
    v = isFile
      ? await api('/api/check/email', { method: 'POST', body: payload })
      : await postJSON('/api/check/email', { raw: payload });
  } catch (e) {
    $('#btn-eml').disabled = false;
    out.innerHTML = `<div class="card card-pad"><div class="callout bad">
      <b>Could not parse that message.</b><div class="sub">${esc(e.message)}</div></div></div>`;
    toast(e.message, 'err');
    return;
  }
  $('#btn-eml').disabled = false;
  const e = v.email || {};
  const links = v.links || [];

  const emailSaveItem = { kind: 'email', label: e.subject || 'email', short: (e.subject || 'email').slice(0, 30), tier: v.label, score: v.score, payload };
  out.innerHTML = verdictHero(v, {
    saveScan: true,
    facts: fact('from', esc(e.from_addr || '—'))
      + fact('authentication', esc((e.auth && (e.auth.dmarc || e.auth.spf)) || 'absent'))
      + fact('links', num(links.length))
      + fact('attachments', num((v.attachments || []).length))
      + fact('received', `${esc(e.received?.hops ?? '—')} hops`),
  })
  + `<div class="grid grid-2">${blastCard(v.blast_radius)}${nextStepsCard(v)}</div>`
  + identityCard(e)
  + signalsCard(v)
  + linksCard(links)
  + `<div class="grid grid-2">${attachmentsCard(v.attachments)}${paymentCard(v)}</div>`
  + tipsCard(v)
  + reportCard(v, e);

  bindFilters(out);
  receiptButton(v, out, emailSaveItem);

  // deep scan for a single link
  $$('[data-deep]', out).forEach((b) => {
    b.onclick = async () => {
      const l = links[Number(b.dataset.deep)];
      const box = $('#deep-out');
      box.innerHTML = `<div style="display:flex;gap:10px;align-items:center;padding:12px 0">
        <span class="spinner"></span><span class="muted small">Deep-scanning <span class="mono">${esc(l.href_defanged)}</span>…</span></div>`;
      try {
        const d = await postJSON('/api/check/url', { url: l.href });
        const deepSaveItem = { kind: 'url', label: d.facts?.defanged || l.href, short: l.href.replace(/^https?:\/\//, '').slice(0, 32), tier: d.label, score: d.score, payload: l.href };
        box.innerHTML = `<div class="stack" style="margin-top:8px">
          ${verdictHero(d, { saveScan: true, facts: fact('domain', esc((d.facts || {}).registrable_domain || '—'))
            + fact('age', ((d.facts || {}).registration || {}).age_days != null
              ? `${num(d.facts.registration.age_days)} days` : 'unknown') })}
          ${signalsCard(d)}${previewCard(d.preview)}</div>`;
        bindFilters(box);
        receiptButton(d, box, deepSaveItem);
      } catch (err) {
        box.innerHTML = `<div class="callout warn">Deep scan failed: ${esc(err.message)}</div>`;
      }
    };
  });

  // vendor baseline confirmation
  const confBtn = $('[data-confirm]', out);
  if (confBtn) {
    confBtn.onclick = async () => {
      if (!confirm('Only do this after calling the vendor on a number from your own records. Continue?')) return;
      try {
        const d = await postJSON('/api/vendor/confirm', { vendor_key: confBtn.dataset.confirm, by: ($('#reporter') || {}).value || 'analyst' });
        $('#confirm-out').innerHTML = `<div class="callout good">Baseline updated for
          <span class="mono">${esc(d.vendor)}</span> at ${esc(d.confirmed_at)}. Future messages with
          different details will flag again.</div>`;
        toast('Vendor baseline updated');
      } catch (err) {
        $('#confirm-out').innerHTML = `<div class="callout warn">${esc(err.message)}</div>`;
      }
    };
  }

  // report → sweep
  const reportBtn = $('#btn-report', out);
  if (reportBtn) {
    reportBtn.onclick = async () => {
      const clicked = $('#clicked-cb').checked;
      try {
        const d = await postJSON('/api/report', {
          cluster_key: (v.cluster || {}).cluster_key,
          subject: e.subject, sender: e.from_addr,
          links: links.map((l) => l.href),
          reporter: $('#reporter').value,
          clicked, verdict: v.label, score: v.score,
        });
        $('#report-out').innerHTML = `<div class="callout warn"><b>Reported.</b>
          ${esc(d.cluster.reports)} report(s) in this cluster · ${esc(d.cluster.clicked)} clicked.
          Everyone else who receives it now sees this immediately.</div>`;
        if (clicked && !$('#post-click')) {
          out.insertAdjacentHTML('beforeend', postClickCard());
          $('#post-click').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        toast('Reported — campaign swept');
        loadHeader();
      } catch (err) { toast(err.message, 'err'); }
    };
  }

  pushRecent({
    kind: 'email', label: e.subject || 'email', short: (e.subject || 'email').slice(0, 30),
    tier: v.label, payload,
  });
  notifyScanComplete('email', v, e.subject || 'Email scan');
  loadHeader();
}

$('#btn-eml').onclick = () => {
  if (emailMode === 'paste') {
    const raw = $('#eml-raw').value;
    if (!raw.trim()) { toast('Paste the raw message source first', 'err'); return; }
    analyseEmail(raw, false);
  } else {
    if (!selectedFile && !fileInput.files[0]) { toast('Choose an .eml file first', 'err'); return; }
    const fd = new FormData();
    fd.append('file', selectedFile || fileInput.files[0]);
    analyseEmail(fd, true);
  }
};
$$('[data-sample]').forEach((b) => {
  b.onclick = async () => {
    try {
      const res = await fetch(`/api/sample/${b.dataset.sample}`);
      if (!res.ok) throw new Error('sample unavailable');
      const txt = await res.text();
      setEmailMode('paste');
      $('#eml-raw').value = txt;
      analyseEmail(txt, false);
    } catch (e) { toast(e.message, 'err'); }
  };
});

/* ============================================================================
   SWEEP view
   ========================================================================== */
async function loadSweep() {
  const kpis = $('#sweep-kpis');
  const list = $('#sweep-list');
  kpis.innerHTML = `<div class="kpi"><div class="label">Loading</div><div class="value">…</div></div>`;
  list.innerHTML = '<div style="padding:18px"><div class="skel skel-line" style="width:60%"></div><div class="skel skel-line" style="width:40%"></div></div>';
  try {
    const [d, money] = await Promise.all([api('/api/clusters'), api('/api/money-deterred')]);
    kpis.innerHTML = `
      <div class="kpi accent">
        <div class="label">Est. loss prevented</div>
        <div class="value mono">₹${num(money.est_value_protected_inr)}</div>
        <div class="foot">${esc(money.method)}</div>
      </div>
      <div class="kpi"><div class="label">Clusters neutralised</div>
        <div class="value mono">${num(money.clusters_neutralised)}</div>
        <div class="foot">campaigns confirmed malicious</div></div>
      <div class="kpi"><div class="label">People protected</div>
        <div class="value mono">${num(money.people_protected)}</div>
        <div class="foot">warned by someone else's report</div></div>
      <div class="kpi"><div class="label">Reports handled</div>
        <div class="value mono">${num(money.reports_handled)}</div>
        <div class="foot">${esc(money.note)}</div></div>`;

    if (!d.clusters.length) {
      list.innerHTML = `<div style="padding:22px"><div class="callout">
        <b>No clusters yet.</b><div class="sub">Analyse an email, then hit “Report → sweep org”.
        Two reports of the same campaign create a cluster and warn the other recipients.</div></div></div>`;
      return;
    }
    list.innerHTML = d.clusters.map((c) => {
      const t = tierOf(c.verdict);
      return `<div class="campaign">
        <div>
          <div class="subj">${esc(c.subject || '(no subject)')}</div>
          <div class="who">${esc(c.sender || '—')}</div>
          <div class="pillrow" style="margin-top:8px">
            <span class="badge ${c.verdict === 'malicious' ? 'b-critical' : c.verdict === 'suspicious' ? 'b-high' : 'b-ok'}">${esc(c.verdict || 'unknown')}</span>
            <span class="chip tiny">${esc(t.icon)} score ${esc(c.score)}</span>
            <span class="chip tiny">last seen ${esc((c.last || '').slice(0, 16).replace('T', ' '))}</span>
          </div>
        </div>
        <div class="stats">
          <div class="stat"><div class="n">${esc(c.reports)}</div><div class="l">reports</div></div>
          <div class="stat"><div class="n ${c.clicked ? 'bad' : ''}">${esc(c.clicked)}</div><div class="l">clicked</div></div>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    kpis.innerHTML = '';
    list.innerHTML = `<div style="padding:20px"><div class="callout warn">Could not load clusters: ${esc(e.message)}</div></div>`;
  }
}
$('#btn-refresh-clusters').onclick = loadSweep;

/* ------------------------------------------------------------------- start */
loadPublicCheckCount();
checkSession();
