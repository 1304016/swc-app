// Crypto module — libsodium wrapper + BIP39 encoding
// All operations are async (sodium must be ready before use)

const Crypto = (() => {

  // ── BIP39 encoding ──────────────────────────────────────────

  function bytesToWords(bytes) {
    // Convert Uint8Array → array of 11-bit indices → BIP39 words
    const bits = [];
    for (const byte of bytes) {
      for (let i = 7; i >= 0; i--) {
        bits.push((byte >> i) & 1);
      }
    }
    // Pad to next multiple of 11
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
    const bits = [];
    for (const word of words) {
      const idx = BIP39_WORDLIST.indexOf(word);
      if (idx === -1) throw new Error(`Unknown BIP39 word: "${word}"`);
      for (let i = 10; i >= 0; i--) bits.push((idx >> i) & 1);
    }
    // Convert bits → bytes (truncate trailing padding bits)
    const byteCount = Math.floor(bits.length / 8);
    const result = new Uint8Array(byteCount);
    for (let i = 0; i < byteCount; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
      result[i] = b;
    }
    return result;
  }

  // ── Key generation ───────────────────────────────────────────

  async function generateKeyPair() {
    await sodium.ready;
    const kp = sodium.crypto_box_keypair();
    return {
      publicKey:  sodium.to_base64(kp.publicKey,  sodium.base64_variants.ORIGINAL),
      privateKey: sodium.to_base64(kp.privateKey, sodium.base64_variants.ORIGINAL),
    };
  }

  // Generate a secret token (12 BIP39 words from 16 random bytes)
  async function generateSecretToken() {
    await sodium.ready;
    const bytes = sodium.randombytes_buf(16); // 128 bits
    const words = bytesToWords(bytes);        // ~12 words
    return { words, raw: sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL) };
  }

  // ── Encryption (crypto_box_seal — anonymous sender) ──────────

  async function encryptMessage(recipientPublicKeyB64, recipientUserId, messageText) {
    await sodium.ready;

    const recipientPK = sodium.from_base64(
      recipientPublicKeyB64, sodium.base64_variants.ORIGINAL
    );

    // Embed recipient ID as a header so we can verify on decode
    const payload = `${recipientUserId}::${messageText}`;
    const msgBytes = sodium.from_string(payload);

    // crypto_box_seal: only recipient's private key can open this
    const ciphertext = sodium.crypto_box_seal(msgBytes, recipientPK);

    return bytesToWords(ciphertext);
  }

  // ── Decryption ───────────────────────────────────────────────

  async function decryptMessage(wordString, myPublicKeyB64, myPrivateKeyB64, myUserId) {
    await sodium.ready;

    let ciphertext;
    try {
      ciphertext = wordsToBytes(wordString);
    } catch (e) {
      throw new Error('invalid_words');
    }

    const myPK = sodium.from_base64(myPublicKeyB64,  sodium.base64_variants.ORIGINAL);
    const mySK = sodium.from_base64(myPrivateKeyB64, sodium.base64_variants.ORIGINAL);

    let decrypted;
    try {
      decrypted = sodium.crypto_box_seal_open(ciphertext, myPK, mySK);
    } catch {
      throw new Error('decrypt_failed');
    }

    if (!decrypted) throw new Error('decrypt_failed');

    const payload = sodium.to_string(decrypted);
    const sepIdx  = payload.indexOf('::');
    if (sepIdx === -1) throw new Error('decrypt_failed');

    const embeddedRecipient = payload.substring(0, sepIdx);
    const messageText       = payload.substring(sepIdx + 2);

    if (embeddedRecipient !== String(myUserId)) {
      throw new Error('not_for_you');
    }

    return messageText;
  }

  // ── Key file helpers ─────────────────────────────────────────

  function buildKeyFileContent(userId, publicKeyB64, privateKeyB64) {
    return [
      '=== Secret Word Cipher — Private Key File ===',
      'Keep this file secret and safe. Anyone with this file can decrypt your messages.',
      '',
      `User ID:     ${userId}`,
      `Public Key:  ${publicKeyB64}`,
      `Private Key: ${privateKeyB64}`,
      '',
      `Exported: ${new Date().toISOString()}`,
      '==============================================',
    ].join('\n');
  }

  function downloadKeyFile(userId, publicKeyB64, privateKeyB64) {
    const content = buildKeyFileContent(userId, publicKeyB64, privateKeyB64);
    const blob    = new Blob([content], { type: 'text/plain' });
    const url     = URL.createObjectURL(blob);
    const a       = document.createElement('a');
    a.href        = url;
    a.download    = `swc-key-${userId}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function parseKeyFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => {
        const text = e.target.result;
        const userId     = (text.match(/^User ID:\s+(.+)$/m)     || [])[1]?.trim();
        const publicKey  = (text.match(/^Public Key:\s+(.+)$/m)  || [])[1]?.trim();
        const privateKey = (text.match(/^Private Key:\s+(.+)$/m) || [])[1]?.trim();
        if (!userId || !publicKey || !privateKey) {
          reject(new Error('Invalid key file format.'));
        } else {
          resolve({ userId, publicKey, privateKey });
        }
      };
      reader.onerror = () => reject(new Error('Could not read file.'));
      reader.readAsText(file);
    });
  }

  return {
    bytesToWords,
    wordsToBytes,
    generateKeyPair,
    generateSecretToken,
    encryptMessage,
    decryptMessage,
    downloadKeyFile,
    parseKeyFile,
  };
})();
