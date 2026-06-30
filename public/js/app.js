// Main application — view routing + event handlers

(async () => {
  // ── Boot ───────────────────────────────────────────────────────
  const savedLang = localStorage.getItem(LS_LANG) || 'en';
  await i18n.load(savedLang);
  buildLangSwitcher();

  const session = Auth.getSession();
  if (session) {
    showView('app');
    hydrateApp(session);
  } else {
    showView('landing');
  }

  wireNavEvents();
  wireSignupFlow();
  wireLoginFlow();
  wireComposeFlow();
  wireDecodeFlow();
  wireAccountFlow();

  // ── View router ────────────────────────────────────────────────

  function showView(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const el = document.getElementById(`view-${name}`);
    if (el) el.classList.add('active');
    window.scrollTo(0, 0);
  }

  function showTab(name) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    const panel = document.getElementById(`tab-${name}`);
    if (panel) panel.classList.add('active');
    const btn = document.querySelector(`[data-tab="${name}"]`);
    if (btn) btn.classList.add('active');
  }

  // ── Navbar ─────────────────────────────────────────────────────

  function wireNavEvents() {
    document.getElementById('nav-logout')?.addEventListener('click', () => {
      Auth.logOut();
      showView('landing');
      updateNavbar(false);
    });

    document.querySelectorAll('[data-tab]').forEach(btn => {
      btn.addEventListener('click', () => showTab(btn.dataset.tab));
    });

    document.getElementById('btn-go-signup')?.addEventListener('click', () => showView('signup'));
    document.getElementById('btn-go-login')?.addEventListener('click',  () => showView('login'));
    document.getElementById('link-go-signup')?.addEventListener('click', e => { e.preventDefault(); showView('signup'); });
    document.getElementById('link-go-login')?.addEventListener('click',  e => { e.preventDefault(); showView('login');  });
    document.getElementById('link-from-login')?.addEventListener('click', e => { e.preventDefault(); showView('signup'); });
    document.getElementById('link-from-signup')?.addEventListener('click', e => { e.preventDefault(); showView('login'); });
  }

  function updateNavbar(loggedIn) {
    document.getElementById('nav-auth-in')?.classList.toggle('hidden',  !loggedIn);
    document.getElementById('nav-auth-out')?.classList.toggle('hidden',   loggedIn);
  }

  function hydrateApp(session) {
    updateNavbar(true);
    document.getElementById('account-user-id').textContent  = session.userId;
    document.getElementById('account-pub-key').textContent  = session.publicKey;
    showTab('compose');

    const pk = Auth.getPrivateKey(session.userId);
    if (pk) {
      document.getElementById('decode-no-key-banner')?.classList.add('hidden');
    } else {
      document.getElementById('decode-no-key-banner')?.classList.remove('hidden');
    }
  }

  // ── Sign-up flow ───────────────────────────────────────────────

  function wireSignupFlow() {
    let _generated = null;

    document.getElementById('btn-start-signup')?.addEventListener('click', async () => {
      setStatus('signup-status', '', '');
      setLoading('signup-section-generate', true);
      document.getElementById('signup-step1').classList.add('hidden');

      try {
        const result = await Auth.signUp();
        _generated = result;

        document.getElementById('signup-display-id').textContent    = result.userId;
        document.getElementById('signup-display-token').textContent = result.tokenWords;
        document.getElementById('signup-step2').classList.remove('hidden');
      } catch (err) {
        document.getElementById('signup-step1').classList.remove('hidden');
        setStatus('signup-status', 'error', err.message || i18n.t('error_generic'));
      } finally {
        setLoading('signup-section-generate', false);
      }
    });

    document.getElementById('btn-copy-token')?.addEventListener('click', () => {
      if (!_generated) return;
      navigator.clipboard.writeText(_generated.tokenWords).then(() => {
        const btn = document.getElementById('btn-copy-token');
        btn.textContent = i18n.t('signup_copy_done');
        setTimeout(() => { btn.textContent = i18n.t('signup_copy_token'); }, 2000);
      });
    });

    document.getElementById('btn-download-key')?.addEventListener('click', () => {
      if (!_generated) return;
      Crypto.downloadKeyFile(_generated.userId, _generated.publicKey, _generated.privateKey);
    });

    document.getElementById('btn-goto-app')?.addEventListener('click', () => {
      const session = Auth.getSession();
      if (session) {
        showView('app');
        hydrateApp(session);
      }
    });
  }

  // ── Login flow ─────────────────────────────────────────────────

  function wireLoginFlow() {
    document.getElementById('form-login')?.addEventListener('submit', async e => {
      e.preventDefault();
      const userId = document.getElementById('login-userid').value.trim();
      const token  = document.getElementById('login-token').value.trim();
      const keyFile = document.getElementById('login-keyfile')?.files[0];

      if (!userId || !token) {
        setStatus('login-status', 'error', i18n.t('error_required'));
        return;
      }

      setLoading('form-login', true);
      setStatus('login-status', '', '');

      try {
        const result = await Auth.logIn(userId, token);
        const session = Auth.getSession();

        // If key file uploaded, parse and save private key
        if (keyFile) {
          try {
            const parsed = await Crypto.parseKeyFile(keyFile);
            Auth.savePrivateKey(session.userId, parsed.privateKey);
          } catch {
            // Non-fatal — user can upload later in decode tab
          }
        }

        showView('app');
        hydrateApp(session);
      } catch (err) {
        setStatus('login-status', 'error', err.message || i18n.t('error_generic'));
      } finally {
        setLoading('form-login', false);
      }
    });
  }

  // ── Compose flow ───────────────────────────────────────────────

  function wireComposeFlow() {
    const charCount = document.getElementById('compose-char-count');
    const msgInput  = document.getElementById('compose-message');

    msgInput?.addEventListener('input', () => {
      const len = msgInput.value.length;
      charCount.textContent = `${len} ${i18n.t('compose_chars')}`;
    });

    document.getElementById('form-compose')?.addEventListener('submit', async e => {
      e.preventDefault();
      const recipientId = document.getElementById('compose-recipient').value.trim();
      const message     = document.getElementById('compose-message').value.trim();

      if (!recipientId || !message) {
        setStatus('compose-status', 'error', i18n.t('error_required'));
        return;
      }

      setLoading('form-compose', true);
      setStatus('compose-status', '', '');

      try {
        const recipientPubKey = await Auth.getPublicKey(recipientId);
        const wordString      = await Crypto.encryptMessage(recipientPubKey, recipientId, message);

        document.getElementById('compose-output').value = wordString;
        document.getElementById('compose-result-section').classList.remove('hidden');
        document.getElementById('form-compose').classList.add('hidden');
      } catch (err) {
        const msg = err.message === 'User not found.'
          ? i18n.t('compose_user_not_found')
          : (err.message || i18n.t('error_generic'));
        setStatus('compose-status', 'error', msg);
      } finally {
        setLoading('form-compose', false);
      }
    });

    document.getElementById('btn-copy-cipher')?.addEventListener('click', () => {
      const output = document.getElementById('compose-output').value;
      navigator.clipboard.writeText(output).then(() => {
        const btn = document.getElementById('btn-copy-cipher');
        btn.textContent = i18n.t('compose_copy_done');
        setTimeout(() => { btn.textContent = i18n.t('compose_copy_btn'); }, 2000);
      });
    });

    document.getElementById('btn-compose-new')?.addEventListener('click', () => {
      document.getElementById('compose-result-section').classList.add('hidden');
      document.getElementById('form-compose').classList.remove('hidden');
      document.getElementById('form-compose').reset();
      setStatus('compose-status', '', '');
      if (charCount) charCount.textContent = `0 ${i18n.t('compose_chars')}`;
    });
  }

  // ── Decode flow ────────────────────────────────────────────────

  function wireDecodeFlow() {
    // Key file upload inside decode tab
    document.getElementById('decode-keyfile-input')?.addEventListener('change', async e => {
      const file = e.target.files[0];
      if (!file) return;
      const session = Auth.getSession();
      if (!session) return;
      try {
        const parsed = await Crypto.parseKeyFile(file);
        if (parsed.userId !== session.userId) {
          setStatus('decode-status', 'error', 'Key file does not match your User ID.');
          return;
        }
        Auth.savePrivateKey(session.userId, parsed.privateKey);
        document.getElementById('decode-no-key-banner')?.classList.add('hidden');
        setStatus('decode-status', 'success', 'Private key loaded successfully.');
      } catch (err) {
        setStatus('decode-status', 'error', err.message);
      }
    });

    document.getElementById('form-decode')?.addEventListener('submit', async e => {
      e.preventDefault();
      const wordString = document.getElementById('decode-input').value.trim();

      if (!wordString) {
        setStatus('decode-status', 'error', i18n.t('error_required'));
        return;
      }

      const session = Auth.getSession();
      if (!session) { showView('login'); return; }

      const privateKey = Auth.getPrivateKey(session.userId);
      if (!privateKey) {
        setStatus('decode-status', 'error', i18n.t('decode_no_key'));
        return;
      }

      setLoading('form-decode', true);
      setStatus('decode-status', '', '');

      try {
        const plaintext = await Crypto.decryptMessage(
          wordString, session.publicKey, privateKey, session.userId
        );
        document.getElementById('decode-output').textContent = plaintext;
        document.getElementById('decode-result-section').classList.remove('hidden');
        document.getElementById('form-decode').classList.add('hidden');
      } catch (err) {
        let msg;
        if (err.message === 'not_for_you')    msg = i18n.t('decode_not_for_you');
        else if (err.message === 'invalid_words') msg = i18n.t('decode_invalid');
        else msg = i18n.t('decode_invalid');
        setStatus('decode-status', 'error', msg);
      } finally {
        setLoading('form-decode', false);
      }
    });

    document.getElementById('btn-decode-new')?.addEventListener('click', () => {
      document.getElementById('decode-result-section').classList.add('hidden');
      document.getElementById('form-decode').classList.remove('hidden');
      document.getElementById('form-decode').reset();
      setStatus('decode-status', '', '');
    });
  }

  // ── Account flow ───────────────────────────────────────────────

  function wireAccountFlow() {
    document.getElementById('btn-download-key-account')?.addEventListener('click', () => {
      const session    = Auth.getSession();
      if (!session) return;
      const privateKey = Auth.getPrivateKey(session.userId);
      if (!privateKey) {
        setStatus('account-status', 'error', 'No private key in browser storage. Upload your key file first.');
        return;
      }
      Crypto.downloadKeyFile(session.userId, session.publicKey, privateKey);
    });

    document.getElementById('btn-show-delete-confirm')?.addEventListener('click', () => {
      document.getElementById('delete-confirm-section').classList.remove('hidden');
    });

    document.getElementById('btn-cancel-delete')?.addEventListener('click', () => {
      document.getElementById('delete-confirm-section').classList.add('hidden');
      document.getElementById('delete-token-input').value = '';
    });

    document.getElementById('btn-confirm-delete')?.addEventListener('click', async () => {
      const session = Auth.getSession();
      if (!session) return;
      const token = document.getElementById('delete-token-input').value.trim();
      if (!token) {
        setStatus('account-status', 'error', i18n.t('error_required'));
        return;
      }

      setLoading('btn-confirm-delete', true, i18n.t('account_deleting'));
      setStatus('account-status', '', '');

      try {
        await Auth.deleteAccount(session.userId, token);
        showView('landing');
        updateNavbar(false);
      } catch (err) {
        setStatus('account-status', 'error', err.message || i18n.t('error_generic'));
        setLoading('btn-confirm-delete', false);
      }
    });
  }

  // ── Language switcher ──────────────────────────────────────────

  function buildLangSwitcher() {
    const container = document.getElementById('lang-switcher');
    if (!container) return;
    i18n.getSupportedLangs().forEach(({ code, label }) => {
      const btn = document.createElement('button');
      btn.textContent = label;
      btn.className   = 'lang-btn';
      btn.dataset.lang = code;
      btn.addEventListener('click', async () => {
        await i18n.load(code);
        document.querySelectorAll('.lang-btn').forEach(b =>
          b.classList.toggle('active', b.dataset.lang === code)
        );
      });
      if (code === savedLang) btn.classList.add('active');
      container.appendChild(btn);
    });
  }

  // ── Helpers ────────────────────────────────────────────────────

  function setStatus(id, type, message) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = message;
    el.className   = `status-msg ${type}`;
  }

  function setLoading(targetId, loading, label) {
    const el = document.getElementById(targetId);
    if (!el) return;
    const btns = el.tagName === 'BUTTON'
      ? [el]
      : el.querySelectorAll('button[type="submit"], .btn-primary');
    btns.forEach(btn => {
      btn.disabled = loading;
      if (loading && label) btn.dataset._orig = btn.textContent, btn.textContent = label;
      else if (!loading && btn.dataset._orig) btn.textContent = btn.dataset._orig;
    });
  }

})();
