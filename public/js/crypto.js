// Crypto module — native WebCrypto (SubtleCrypto) + BIP39 word encoding
// Zero external dependencies: uses built-in browser crypto.subtle
//
// Sealed-box scheme: ECDH (P-256) + AES-256-GCM (anonymous sender)
//   Ciphertext layout: [ephemeralPubKey(65)] [iv(12)] [aes-gcm-ciphertext+tag]

const Crypto = (() => {
  const subtle = crypto.subtle;
  const ECDH   = { name: 'ECDH', namedCurve: 'P-256' };
  const AES    = { name: 'AES-GCM', length: 256 };
  const ENC    = new TextEncoder();
  const DEC    = new TextDecoder();

  // ── BIP39 encoding ─────────────────────────────────────────────

  function bytesToWords(bytes) {
    const bits = [];
    for (const b of bytes)
      for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
    while (bits.length % 11 !== 0) bits.push(0);

    const words = [];
    for (let i = 0; i < bits.length; i += 11) {
      let idx = 0;
      for (let j = 0; j < 11; j++) idx = (idx << 1) | bits[i + j];
      words.push(BIP39_WORDLIST[idx]);
    }
    return words.join(' ');
  }

  function wordsToBytes(wordString) {
    const words = wordString.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const bits  = [];
    for (const w of words) {
      const idx = BIP39_WORDLIST.indexOf(w);
      if (idx === -1) throw new Error(`Unknown word: "${w}"`);
      for (let i = 10; i >= 0; i--) bits.push((idx >> i) & 1);
    }
    const byteCount = Math.floor(bits.length / 8);
    const out = new Uint8Array(byteCount);
    for (let i = 0; i < byteCount; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
      out[i] = b;
    }
    return out;
  }

  // ── Key helpers ────────────────────────────────────────────────

  async function generateKeyPair() {
    const kp  = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    const pub  = await subtle.exportKey('jwk', kp.publicKey);
    const priv = await subtle.exportKey('jwk', kp.privateKey);
    // Store as base64-encoded JSON strings
    return {
      publicKey:  btoa(JSON.stringify(pub)),
      privateKey: btoa(JSON.stringify(priv)),
    };
  }

  async function _importPub(b64) {
    return subtle.importKey('jwk', JSON.parse(atob(b64)), ECDH, false, []);
  }
  async function _importPriv(b64) {
    return subtle.importKey('jwk', JSON.parse(atob(b64)), ECDH, false, ['deriveKey']);
  }

  // ── Secret token (12 random BIP39 words = 128 bits of entropy) ─

  async function generateSecretToken() {
    const bytes = crypto.getRandomValues(new Uint8Array(16)); // 128 bits
    const words = bytesToWords(bytes);
    return { words, raw: btoa(String.fromCharCode(...bytes)) };
  }

  // ── Encryption ─────────────────────────────────────────────────
  // Sealed-box: generate ephemeral keypair, ECDH → AES-256-GCM encrypt

  async function encryptMessage(recipientPublicKeyB64, recipientUserId, messageText) {
    const recipientPK = await _importPub(recipientPublicKeyB64);

    const ephemeral = await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
    );

    const sharedKey = await subtle.deriveKey(
      { name: 'ECDH', public: recipientPK },
      ephemeral.privateKey,
      AES, false, ['encrypt']
    );

    const ephPubRaw = new Uint8Array(
      await subtle.exportKey('raw', ephemeral.publicKey)  // 65 bytes
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const payload   = `${recipientUserId}::${messageText}`;
    const encrypted = new Uint8Array(
      await subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, ENC.encode(payload))
    );

    // Pack: ephPubRaw(65) | iv(12) | ciphertext+tag
    const out = new Uint8Array(65 + 12 + encrypted.length);
    out.set(ephPubRaw,  0);
    out.set(iv,         65);
    out.set(encrypted,  77);

    return bytesToWords(out);
  }

  // ── Decryption ──────────────────────────────────────────────────

  async function decryptMessage(wordString, myPublicKeyB64, myPrivateKeyB64, myUserId) {
    let packed;
    try { packed = wordsToBytes(wordString); }
    catch { throw new Error('invalid_words'); }

    if (packed.length < 77 + 16) throw new Error('decrypt_failed');

    const ephPubRaw  = packed.slice(0, 65);
    const iv         = packed.slice(65, 77);
    const ciphertext = packed.slice(77);

    const ephPK  = await subtle.importKey('raw', ephPubRaw, ECDH, false, []);
    const myPriv = await _importPriv(myPrivateKeyB64);

    const sharedKey = await subtle.deriveKey(
      { name: 'ECDH', public: ephPK },
      myPriv,
      AES, false, ['decrypt']
    );

    let plainBytes;
    try {
      plainBytes = await subtle.decrypt({ name: 'AES-GCM', iv }, sharedKey, ciphertext);
    } catch {
      throw new Error('decrypt_failed');
    }

    const payload = DEC.decode(plainBytes);
    const sep     = payload.indexOf('::');
    if (sep === -1) throw new Error('decrypt_failed');

    const embeddedRecipient = payload.substring(0, sep);
    const messageText       = payload.substring(sep + 2);

    if (embeddedRecipient !== String(myUserId)) throw new Error('not_for_you');
    return messageText;
  }

  // ── Key file helpers ────────────────────────────────────────────

  function downloadKeyFile(userId, publicKeyB64, privateKeyB64) {
    const content = [
      '=== Secret Word Cipher — Private Key File ===',
      'Keep this file secret. Anyone with it can decrypt your messages.',
      '',
      `User ID:     ${userId}`,
      `Public Key:  ${publicKeyB64}`,
      `Private Key: ${privateKeyB64}`,
      '',
      `Exported: ${new Date().toISOString()}`,
      '==============================================',
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: `swc-key-${userId}.txt` });
    a.click();
    URL.revokeObjectURL(url);
  }

  async function parseKeyFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => {
        const text       = e.target.result;
        const userId     = (text.match(/^User ID:\s+(.+)$/m)     || [])[1]?.trim();
        const publicKey  = (text.match(/^Public Key:\s+(.+)$/m)  || [])[1]?.trim();
        const privateKey = (text.match(/^Private Key:\s+(.+)$/m) || [])[1]?.trim();
        if (!userId || !publicKey || !privateKey)
          reject(new Error('Invalid key file format.'));
        else
          resolve({ userId, publicKey, privateKey });
      };
      reader.onerror = () => reject(new Error('Could not read file.'));
      reader.readAsText(file);
    });
  }

  return {
    bytesToWords, wordsToBytes,
    generateKeyPair, generateSecretToken,
    encryptMessage, decryptMessage,
    downloadKeyFile, parseKeyFile,
  };
})();
