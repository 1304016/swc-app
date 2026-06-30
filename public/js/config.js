// Supabase project configuration
// These values are safe to expose in frontend code (anon/publishable key only)
const SUPABASE_URL = 'https://gwcwdehsjfangrxjslhm.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_GYOkq-hjsm51yJnlJy6lPA_dxdCdjqB';

// Session TTL in milliseconds (24 hours)
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

// LocalStorage key names
const LS_SESSION    = 'swc_session';       // { userId, publicKey, expiry }
const LS_PRIV_KEY   = (uid) => `swc_pk_${uid}`; // private key per user
const LS_LANG       = 'swc_lang';          // preferred language
