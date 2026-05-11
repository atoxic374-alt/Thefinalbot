import { TrueStudioManager } from './components/TrueStudioManager.js';
import { applyLang, t } from './utils/i18n.js';

window.t = t;
applyLang();

const root = document.getElementById('bs-root');
window.trueStudioManager = new TrueStudioManager(root);
window.trueStudioManager.init();
