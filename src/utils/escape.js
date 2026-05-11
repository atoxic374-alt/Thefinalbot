// Centralized HTML/attribute/JS escape helpers — prevents XSS from
// user-controlled strings (server names, channel names, message bodies, etc).
//
// Use:
//   esc(text)        → safe inside element body
//   escAttr(text)    → safe inside an attribute value
//   escJs(text)      → safe inside a JS string literal in inline handlers
//   safeId(id)       → strips anything that isn't a Discord snowflake-safe char

const _div = typeof document !== 'undefined' ? document.createElement('div') : null;

export function esc(s) {
  if (s == null) return '';
  if (_div) { _div.textContent = String(s); return _div.innerHTML; }
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function escAttr(s) {
  return esc(s).replace(/`/g, '&#96;');
}

export function escJs(s) {
  return String(s ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/</g, '\\u003c');
}

// Snowflake-safe id (digits only). Returns '' if input is unsafe.
export function safeId(s) {
  const v = String(s ?? '');
  return /^[0-9]{1,32}$/.test(v) ? v : '';
}
