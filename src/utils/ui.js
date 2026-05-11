import { sfx } from './sounds.js';
import { t } from './i18n.js';

export const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
    showNotification('Copied to clipboard!');
  } catch (error) {
    console.error('Failed to copy:', error);
  }
};

// Now routes through the prominent top toast so users actually see things.
// Accepts an optional 2nd arg: 'success' | 'error' | 'info' (default info).
export const showNotification = (message, type = 'info') => {
  try { showToast(message, type); }
  catch (_) {
    const n = document.createElement('div');
    n.className = 'copy-notification';
    n.textContent = message;
    document.body.appendChild(n);
    setTimeout(() => n.remove(), 2000);
  }
};

// Toast (bottom-right). type: 'success' | 'error' | 'info'
// Includes a 1.2s dedupe window — if the same (type+message) toast fires again,
// we just bump a counter on the existing card instead of stacking 20 copies.
let _toastHost = null;
function getToastHost() {
  if (_toastHost && document.body.contains(_toastHost)) return _toastHost;
  _toastHost = document.createElement('div');
  _toastHost.id = 'toast-host';
  _toastHost.className = 'toast-host';
  document.body.appendChild(_toastHost);
  return _toastHost;
}
const ICON_OK   = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
const ICON_BAD  = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9"  x2="9"  y2="15"/><line x1="9"  y1="9"  x2="15" y2="15"/></svg>';
const ICON_INFO = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8"  x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
const _recentToasts = new Map(); // key -> { card, count, ts, timer }
const _MAX_TOASTS = 6;
const _DEDUPE_MS = 1500;
export const showToast = (message, type = 'info', dur = 3000) => {
  const host = getToastHost();
  const msg = String(message ?? '');
  const key = `${type}:${msg}`;
  const now = Date.now();

  // Dedupe window — bump the existing card.
  const prev = _recentToasts.get(key);
  if (prev && (now - prev.ts) < _DEDUPE_MS && prev.card.isConnected) {
    prev.count += 1;
    prev.ts = now;
    let badge = prev.card.querySelector('.toast-count');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'toast-count';
      badge.style.cssText = 'margin-left:8px;padding:2px 7px;border-radius:10px;background:rgba(255,255,255,.15);font-size:11px;font-weight:600';
      prev.card.appendChild(badge);
    }
    badge.textContent = `×${prev.count}`;
    clearTimeout(prev.timer);
    prev.timer = setTimeout(() => {
      prev.card.classList.remove('in'); prev.card.classList.add('out');
      setTimeout(() => prev.card.remove(), 280);
      _recentToasts.delete(key);
    }, dur);
    return;
  }

  const card = document.createElement('div');
  card.className = `toast toast-${type}`;
  const ic = type === 'success' ? ICON_OK : type === 'error' ? ICON_BAD : ICON_INFO;
  card.innerHTML = `<span class="toast-ic">${ic}</span><span class="toast-msg"></span>`;
  card.querySelector('.toast-msg').textContent = msg;
  host.appendChild(card);

  // Cap simultaneous toasts.
  while (host.children.length > _MAX_TOASTS) host.removeChild(host.firstChild);

  if (type === 'success') sfx.success?.();
  else if (type === 'error') sfx.fail?.();
  requestAnimationFrame(() => card.classList.add('in'));
  const close = () => {
    card.classList.remove('in'); card.classList.add('out');
    setTimeout(() => card.remove(), 280);
    _recentToasts.delete(key);
  };
  card.addEventListener('click', close);
  const timer = setTimeout(close, dur);
  _recentToasts.set(key, { card, count: 1, ts: now, timer });
};

// Button feedback: disables, shows "saving…" then "saved!"/"failed" then restores label.
export const pulseButton = async (btn, fn) => {
  if (!btn) return fn();
  const orig = btn.innerHTML;
  const wasDisabled = btn.disabled;
  btn.disabled = true;
  btn.classList.add('btn-busy');
  btn.dataset._origText = orig;
  btn.innerHTML = `<span class="btn-spin"></span><span>${t('common.saving')}</span>`;
  try {
    const r = await fn();
    btn.classList.remove('btn-busy');
    btn.classList.add('btn-ok');
    btn.innerHTML = `<span>✓</span><span>${t('common.saved')}</span>`;
    setTimeout(() => {
      btn.classList.remove('btn-ok');
      btn.innerHTML = orig;
      btn.disabled = wasDisabled;
    }, 1500);
    return r;
  } catch (e) {
    btn.classList.remove('btn-busy');
    btn.classList.add('btn-err');
    btn.innerHTML = `<span>✕</span><span>${t('common.save_fail')}</span>`;
    setTimeout(() => {
      btn.classList.remove('btn-err');
      btn.innerHTML = orig;
      btn.disabled = wasDisabled;
    }, 1800);
    throw e;
  }
};

// Simple confirm dialog with i18n. Returns Promise<boolean>.
export const showConfirm = (message, { confirmText, cancelText, icon: iconSvg, title } = {}) => {
  return new Promise((resolve) => {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.animation = 'fadeIn 0.18s ease-out';
    const content = document.createElement('div');
    content.className = 'modal-content confirm-modal';
    const WARN_ICON = `<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    const iconHtml = iconSvg || WARN_ICON;
    content.innerHTML = `
      <div class="confirm-icon">${iconHtml}</div>
      ${title ? `<p class="confirm-title"></p>` : ''}
      <p class="confirm-msg"></p>
      <div class="button-group">
        <button class="confirm-yes"></button>
        <button class="secondary confirm-no"></button>
      </div>
    `;
    if (title) content.querySelector('.confirm-title').textContent = title;
    content.querySelector('.confirm-msg').textContent = message;
    content.querySelector('.confirm-yes').textContent = confirmText || t('common.ok') || 'OK';
    content.querySelector('.confirm-no').textContent  = cancelText  || t('common.cancel') || 'Cancel';
    modal.appendChild(content);
    document.body.appendChild(modal);
    const close = (val) => {
      content.style.animation = 'slideOut 0.15s ease-in forwards';
      modal.style.animation   = 'fadeOut 0.15s ease-in forwards';
      setTimeout(() => { modal.remove(); resolve(val); }, 140);
    };
    modal.addEventListener('click', (e) => { if (e.target === modal) close(false); });
    content.querySelector('.confirm-yes').addEventListener('click', () => { sfx.click?.(); close(true); });
    content.querySelector('.confirm-no').addEventListener('click',  () => { sfx.click?.(); close(false); });
  });
};

// Brief shake animation on an element (used for invalid clicks).
export const shakeFail = (el) => {
  if (!el) return;
  el.classList.remove('shake-fail');
  void el.offsetWidth;
  el.classList.add('shake-fail');
  sfx.fail?.();
  setTimeout(() => el.classList.remove('shake-fail'), 500);
};

// Discord-style preview toast for test mode — shows what would have been sent.
export const showTestPreview = (action, text, where, idx, total) => {
  const tag = ({ send: 'SEND', repeat: 'REPEAT', schedule: 'SCHEDULE', react: 'REACT' }[action] || 'TEST');
  const card = document.createElement('div');
  card.className = 'test-preview-card';
  const safe = String(text || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  card.innerHTML = `
    <div class="tp-head">
      <div class="tp-av">
        <svg viewBox="0 0 64 64" width="36" height="36">
          <rect width="64" height="64" rx="32" fill="#5865F2"/>
          <path fill="#fff" d="M44.6 19.5c-2.3-1-4.7-1.8-7.3-2.2-.3.6-.7 1.4-1 2-2.7-.4-5.4-.4-8 0-.3-.6-.7-1.4-1-2-2.5.5-5 1.3-7.3 2.3-4.6 6.9-5.8 13.6-5.2 20.2 3.1 2.3 6 3.7 8.9 4.6.7-1 1.4-2 1.9-3.1-1.1-.4-2.1-.9-3.1-1.5.3-.2.5-.4.8-.6 5.9 2.7 12.4 2.7 18.3 0 .3.2.5.4.8.6-1 .6-2 1.1-3.1 1.5.6 1.1 1.2 2.1 1.9 3.1 2.9-.9 5.8-2.3 8.9-4.6.7-7.7-1.2-14.3-5.2-20.2zM25.4 36.1c-1.8 0-3.2-1.6-3.2-3.6s1.4-3.6 3.2-3.6 3.3 1.6 3.2 3.6c0 2-1.4 3.6-3.2 3.6zm13.1 0c-1.8 0-3.2-1.6-3.2-3.6s1.4-3.6 3.2-3.6 3.3 1.6 3.2 3.6c0 2-1.4 3.6-3.2 3.6z"/>
        </svg>
      </div>
      <div class="tp-meta">
        <div class="tp-name">Ahmed (Test) <span class="tp-tag">${tag}</span></div>
        <div class="tp-where">→ ${where} ${total > 1 ? `· #${idx}/${total}` : ''}</div>
      </div>
      <button class="tp-x" aria-label="close">×</button>
    </div>
    <div class="tp-body">${safe || '<em>(empty message)</em>'}</div>
    <div class="tp-foot">AHMED · @4_3a</div>
  `;
  card.querySelector('.tp-x').addEventListener('click', () => card.remove());
  let host = document.getElementById('test-preview-host');
  if (!host) {
    host = document.createElement('div');
    host.id = 'test-preview-host';
    document.body.appendChild(host);
  }
  host.appendChild(card);
  setTimeout(() => card.classList.add('in'), 10);
  setTimeout(() => { card.classList.remove('in'); card.classList.add('out'); }, 6500);
  setTimeout(() => card.remove(), 7200);
};

export const showProgressModal = (title, total) => {
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';

  const content = document.createElement('div');
  content.className = 'modal-content';

  const titleEl = document.createElement('h2');
  titleEl.textContent = title;

  const progressContainer = document.createElement('div');
  progressContainer.className = 'progress-container';

  const progressBar = document.createElement('div');
  progressBar.className = 'progress-bar';

  const progress = document.createElement('div');
  progress.className = 'progress';
  progress.style.width = '0%';

  const progressText = document.createElement('div');
  progressText.className = 'progress-text';
  progressText.textContent = `0/${total}`;

  progressBar.appendChild(progress);
  progressContainer.appendChild(progressBar);
  progressContainer.appendChild(progressText);

  content.appendChild(titleEl);
  content.appendChild(progressContainer);
  modal.appendChild(content);

  document.body.appendChild(modal);

  return {
    updateProgress: (completed) => {
      const percent = (completed / total) * 100;
      progress.style.width = `${percent}%`;
      progressText.textContent = `${completed}/${total}`;
    },
    closeModal: () => modal.remove()
  };
};

export const showInfoModal = () => {
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });

  const content = document.createElement('div');
  content.className = 'modal-content info-modal';

  content.innerHTML = `
    <div class="info-badge">
      <svg viewBox="0 0 24 24" width="42" height="42" fill="none">
        <circle cx="12" cy="12" r="11" stroke="#5865f2" stroke-width="1.5"/>
        <path d="M9 12l2 2 4-4" stroke="#5865f2" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <h2 class="info-app-name">Discord Account Manager</h2>
    <p class="info-version">Version 1.5.6</p>
    <div class="info-divider"></div>
    <div class="info-owner-card">
      <div class="info-owner-icon">A</div>
      <div class="info-owner-details">
        <span class="info-owner-label">Developed by</span>
        <span class="info-owner-name">Ahmed</span>
        <span class="info-owner-handle">@4_3a</span>
      </div>
    </div>
    <div class="info-rights">
      <span>© 2025 Ahmed — All Rights Reserved</span>
    </div>
    <button class="info-close-btn" id="infoCloseBtn">Close</button>
  `;

  modal.appendChild(content);
  document.body.appendChild(modal);
  modal.querySelector('#infoCloseBtn').addEventListener('click', () => modal.remove());
};

export const showInputModal = (title, message) => {
  return new Promise((resolve) => {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';

    const content = document.createElement('div');
    content.className = 'modal-content';

    const titleEl = document.createElement('h2');
    titleEl.textContent = title;

    const messageEl = document.createElement('p');
    messageEl.textContent = message;

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'modal-input';

    const buttonGroup = document.createElement('div');
    buttonGroup.className = 'button-group';

    const saveBtn = document.createElement('button');
    saveBtn.textContent = 'Save';
    saveBtn.addEventListener('click', () => {
      const value = input.value.trim();
      if (value) {
        resolve(value);
        modal.remove();
      }
    });

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'secondary-btn';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', () => {
      resolve(null);
      modal.remove();
    });

    buttonGroup.appendChild(saveBtn);
    buttonGroup.appendChild(cancelBtn);

    content.appendChild(titleEl);
    content.appendChild(messageEl);
    content.appendChild(input);
    content.appendChild(buttonGroup);
    modal.appendChild(content);

    document.body.appendChild(modal);
    input.focus();
  });
};
