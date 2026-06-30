// Internationalization helper
// Loads locale JSON and provides t() translation function

const i18n = (() => {
  let _strings = {};
  let _lang = 'en';

  async function load(lang) {
    try {
      const res = await fetch(`/locales/${lang}.json`);
      if (!res.ok) throw new Error('locale not found');
      _strings = await res.json();
      _lang = lang;
      localStorage.setItem(LS_LANG, lang);
    } catch {
      if (lang !== 'en') {
        // Fallback to English
        const res = await fetch('/locales/en.json');
        _strings = await res.json();
        _lang = 'en';
      }
    }
    applyToDOM();
  }

  // Translate key → string, with optional {{placeholder}} substitution
  function t(key, vars = {}) {
    let str = _strings[key] || key;
    for (const [k, v] of Object.entries(vars)) {
      str = str.replace(new RegExp(`{{${k}}}`, 'g'), v);
    }
    return str;
  }

  // Apply data-i18n attributes to the whole DOM
  function applyToDOM() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      el.textContent = t(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      el.title = t(el.getAttribute('data-i18n-title'));
    });
  }

  function getLang() { return _lang; }

  function getSupportedLangs() {
    return [
      { code: 'en', label: 'English' },
      { code: 'bn', label: 'বাংলা'   },
    ];
  }

  return { load, t, applyToDOM, getLang, getSupportedLangs };
})();
