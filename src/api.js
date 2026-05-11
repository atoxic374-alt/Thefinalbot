// ── Build-stamp watcher: detects server restarts and shows a reload banner ──
(function watchBuildStamp() {
  const boot = window.__BUILD_STAMP__ || null;
  if (!boot) return;
  let banner = null;
  function showBanner() {
    if (banner) return;
    banner = document.createElement('div');
    banner.style.cssText =
      'position:fixed;top:0;left:0;right:0;z-index:99999;background:#7c3aed;color:#fff;' +
      'padding:10px 14px;text-align:center;font:600 14px/1.4 system-ui,sans-serif;' +
      'box-shadow:0 2px 8px rgba(0,0,0,.3);cursor:pointer;';
    banner.textContent = '⚠️ تم تحديث التطبيق — اضغط هنا لإعادة التحميل';
    banner.addEventListener('click', () => window.location.reload(true));
    if (document.body) document.body.appendChild(banner);
    else document.addEventListener('DOMContentLoaded', () => document.body.appendChild(banner));
  }
  async function check() {
    try {
      const r = await fetch('/api/build-stamp', { cache: 'no-store' });
      if (!r.ok) return;
      const j = await r.json();
      if (j && j.stamp && String(j.stamp) !== String(boot)) showBanner();
    } catch (_) {}
  }
  setTimeout(check, 4000);
  setInterval(check, 30_000);
})();

async function apiCall(method, url, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  let res;
  try {
    res = await fetch(url, opts);
  } catch (e) {
    return { success: false, error: 'Network error: ' + (e?.message || 'fetch failed') };
  }
  let data;
  try { data = await res.json(); } catch { data = {}; }
  if (!res.ok && data.success === undefined) data.success = false;
  return data;
}

window.electronAPI = {
  minimize: () => {},
  maximize: () => {},
  close: () => {},

  // ── True-Studio / Bot-Studio API ──────────────────────────────────────
  tsAccounts:            () => apiCall('GET',    '/api/ts/accounts'),
  tsSaveAccount:         (p) => apiCall('POST',  '/api/ts/accounts', p),
  tsDeleteAccount:       (email) => apiCall('DELETE', `/api/ts/accounts/${encodeURIComponent(email)}`),
  tsState:               () => apiCall('GET',    '/api/ts/state'),
  tsStart:               (cfg) => apiCall('POST', '/api/ts/start', cfg),
  tsStop:                () => apiCall('POST',   '/api/ts/stop'),
  tsTestAccount:         (email) => apiCall('POST', '/api/ts/test-account', { email }),
  tsLibrary:             (email) => apiCall('GET', `/api/ts/library?email=${encodeURIComponent(email)}`),
  tsResetBot:            (appId, email, name, icon) =>
    apiCall('POST', `/api/ts/applications/${encodeURIComponent(appId)}/reset-bot-token`, { email, name: name || appId, icon: icon || null }),
  tsExportUrl:           (format = 'text') => `/api/ts/export?format=${encodeURIComponent(format)}`,
  tsCaptchaSettings:     () => apiCall('GET', '/api/ts/captcha-settings'),
  tsSaveCaptchaSettings: (p) => apiCall('POST', '/api/ts/captcha-settings', p),
  tsCaptchaVerify:       () => apiCall('GET', '/api/ts/captcha-verify'),
  tsResolveCaptcha:      (id, token) => apiCall('POST', `/api/ts/captcha-resolve/${encodeURIComponent(id)}`, { token }),
  tsCancelCaptcha:       (id) => apiCall('POST', `/api/ts/captcha-cancel/${encodeURIComponent(id)}`),
  tsBotTokens:           () => apiCall('GET', '/api/ts/bot-tokens'),
  tsSaveBotToken:        (data) => apiCall('POST', '/api/ts/bot-tokens', data),
  tsDeleteBotToken:      (appId) => apiCall('DELETE', `/api/ts/bot-tokens/${encodeURIComponent(appId)}`),
  tsVerifyProxy:         (proxyUrl) => apiCall('POST', '/api/ts/proxy-verify', { proxyUrl }),
  tsListTeams:           (email) => apiCall('GET', `/api/ts/teams?email=${encodeURIComponent(email)}`),
  tsCreateTeam:          (email, name) => apiCall('POST', '/api/ts/teams/create', { email, name }),
  tsAddAppToTeam:        (email, appId, teamId) => apiCall('POST', `/api/ts/teams/${encodeURIComponent(teamId)}/add-app`, { email, appId }),
  tsResetAllStart:       (email, bots) => apiCall('POST', '/api/ts/reset-all/start', { email, bots }),
  tsResetAllState:       () => apiCall('GET', '/api/ts/reset-all/state'),
  tsResetAllStop:        () => apiCall('POST', '/api/ts/reset-all/stop'),
};
