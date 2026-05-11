// WebAudio sound effects with localStorage toggle. Zero file dependencies.
// Refined: chic, soft, sine-only tones at low volume — never harsh.

let _ctx = null;
function ctx() {
  if (!_ctx) {
    try { _ctx = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) {}
  }
  if (_ctx && _ctx.state === 'suspended') { try { _ctx.resume(); } catch (e) {} }
  return _ctx;
}

export function isSoundOn() {
  return localStorage.getItem('sound_fx') !== 'off';
}

export function setSoundOn(on) {
  localStorage.setItem('sound_fx', on ? 'on' : 'off');
  window.dispatchEvent(new CustomEvent('sound-fx-changed', { detail: on }));
}

function tone(freq, dur = 0.10, type = 'sine', vol = 0.025) {
  if (!isSoundOn()) return;
  const c = ctx();
  if (!c) return;
  try {
    const o = c.createOscillator();
    const g = c.createGain();
    const lp = c.createBiquadFilter();
    lp.type = 'lowpass';
    lp.frequency.value = 4200;
    lp.Q.value = 0.7;
    o.type = type;
    o.frequency.value = freq;
    g.gain.value = 0;
    o.connect(lp).connect(g).connect(c.destination);
    const t = c.currentTime;
    g.gain.linearRampToValueAtTime(vol, t + 0.018);
    g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    o.start(t);
    o.stop(t + dur + 0.02);
  } catch (e) {}
}

export const sfx = {
  click:   () => tone(1100, 0.035, 'sine', 0.018),
  pop:     () => tone(1320, 0.045, 'sine', 0.022),
  ding:    () => { tone(880, 0.07, 'sine', 0.022); setTimeout(() => tone(1320, 0.10, 'sine', 0.018), 70); },
  notify:  () => { tone(880, 0.06, 'sine', 0.020); setTimeout(() => tone(1175, 0.10, 'sine', 0.018), 70); },
  success: () => { tone(784, 0.06, 'sine', 0.022); setTimeout(() => tone(988, 0.07, 'sine', 0.020), 70); setTimeout(() => tone(1318, 0.12, 'sine', 0.018), 150); },
  fail:    () => { tone(440, 0.08, 'sine', 0.022); setTimeout(() => tone(330, 0.14, 'sine', 0.020), 90); },
  toggle:  () => tone(960, 0.04, 'sine', 0.018),
};

if (typeof window !== 'undefined') window.sfx = sfx;
