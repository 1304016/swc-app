// Auth module — Supabase RPC wrappers + session management

const Auth = (() => {
  // Initialise Supabase client (loaded via CDN in HTML)
  const _sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

  // ── Session ─────────────────────────────────────────────────

  function saveSession(userId, publicKey) {
    const session = {
      userId,
      publicKey,
      expiry: Date.now() + SESSION_TTL_MS,
    };
    localStorage.setItem(LS_SESSION, JSON.stringify(session));
  }

  function getSession() {
    try {
      const raw = localStorage.getItem(LS_SESSION);
      if (!raw) return null;
      const s = JSON.parse(raw);
      if (Date.now() > s.expiry) {
        localStorage.removeItem(LS_SESSION);
        return null;
      }
      return s;
    } catch {
      return null;
    }
  }

  function clearSession() {
    const s = getSession();
    if (s) localStorage.removeItem(LS_PRIV_KEY(s.userId));
    localStorage.removeItem(LS_SESSION);
  }

  // ── Private key helpers ──────────────────────────────────────

  function savePrivateKey(userId, privateKeyB64) {
    localStorage.setItem(LS_PRIV_KEY(userId), privateKeyB64);
  }

  function getPrivateKey(userId) {
    return localStorage.getItem(LS_PRIV_KEY(userId)) || null;
  }

  function setRuntimePrivateKey(userId, privateKeyB64) {
    // Stores in memory for this page load if user uploaded a key file
    // also persists to localStorage for convenience
    savePrivateKey(userId, privateKeyB64);
  }

  // ── Generate a random numeric user ID (10 digits) ────────────

  function generateUserId() {
    // 10-digit number: first digit 1-9, rest 0-9
    const digits = [Math.floor(Math.random() * 9) + 1];
    for (let i = 0; i < 9; i++) digits.push(Math.floor(Math.random() * 10));
    return digits.join('');
  }

  // ── Sign up ──────────────────────────────────────────────────

  async function signUp() {
    // 1. Generate key pair in browser
    const { publicKey, privateKey } = await Crypto.generateKeyPair();

    // 2. Generate secret token (12 BIP39 words)
    const { words: tokenWords } = await Crypto.generateSecretToken();

    // 3. Try to register; retry with new ID if collision
    let userId, result;
    let attempts = 0;
    do {
      userId = generateUserId();
      const { data, error } = await _sb.rpc('swc_register', {
        p_user_id:      userId,
        p_public_key:   publicKey,
        p_secret_token: tokenWords,
      });
      if (error) throw new Error(error.message || 'Network error');
      result = data;
      attempts++;
      if (attempts > 5) throw new Error('Could not generate a unique User ID. Try again.');
    } while (result?.error === 'user_id_taken');

    if (result?.error) throw new Error(result.message || result.error);

    // 4. Persist session + private key in localStorage
    saveSession(userId, publicKey);
    savePrivateKey(userId, privateKey);

    return { userId, publicKey, privateKey, tokenWords };
  }

  // ── Log in ───────────────────────────────────────────────────

  async function logIn(userId, secretToken) {
    const { data, error } = await _sb.rpc('swc_login', {
      p_user_id:      String(userId).trim(),
      p_secret_token: secretToken.trim(),
    });

    if (error) throw new Error(error.message || 'Network error');
    if (data?.error) throw new Error(data.message || data.error);

    saveSession(data.user_id, data.public_key);
    return data; // { user_id, public_key }
  }

  // ── Log out ──────────────────────────────────────────────────

  function logOut() {
    clearSession();
  }

  // ── Get recipient public key ─────────────────────────────────

  async function getPublicKey(recipientUserId) {
    const { data, error } = await _sb.rpc('swc_get_public_key', {
      p_user_id: String(recipientUserId).trim(),
    });
    if (error) throw new Error(error.message || 'Network error');
    if (data?.error) throw new Error(data.message || data.error);
    return data.public_key;
  }

  // ── Delete account ───────────────────────────────────────────

  async function deleteAccount(userId, secretToken) {
    const { data, error } = await _sb.rpc('swc_delete_account', {
      p_user_id:      String(userId).trim(),
      p_secret_token: secretToken.trim(),
    });
    if (error) throw new Error(error.message || 'Network error');
    if (data?.error) throw new Error(data.message || data.error);
    clearSession();
    return true;
  }

  return {
    signUp,
    logIn,
    logOut,
    getPublicKey,
    deleteAccount,
    getSession,
    getPrivateKey,
    savePrivateKey,
    setRuntimePrivateKey,
  };
})();
