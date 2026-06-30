# 🔐 Secret Word Cipher

End-to-end encrypted messaging disguised as ordinary words.  
Encrypt any message into a string of BIP39 words — share it anywhere.

---

## বাংলা (Bengali)

### প্রজেক্ট কী করে?
- ব্রাউজারেই libsodium দিয়ে key-pair তৈরি হয় — private key কখনো সার্ভারে যায় না।
- মেসেজ `crypto_box_seal` দিয়ে এনক্রিপ্ট হয়, তারপর BIP39 শব্দতালিকায় এনকোড হয়।
- আউটপুট: `apple river dragon mountain...` — যেকোনো জায়গায় পাঠানো যায়।

### লোকাল সেটআপ
```bash
# 1. রিপো ক্লোন করুন
git clone https://github.com/1304016/swc-app.git
cd swc-app

# 2. Supabase-এ schema চালান
#    Dashboard → SQL Editor → schema.sql-এর পুরো কন্টেন্ট পেস্ট করুন

# 3. যেকোনো static server দিয়ে রান করুন
npx serve public
# অথবা
python -m http.server 3000 --directory public
```

---

## English

### What it does
- Generates a NaCl key-pair in the browser — private key never leaves your device.
- Encrypts messages with `crypto_box_seal` (anonymous sender), then encodes ciphertext as BIP39 words.
- Output looks like: `apple river dragon mountain cloud…` — send it anywhere.

### Tech stack
| Layer | Technology |
|-------|-----------|
| Frontend | Plain HTML + CSS + Vanilla JS |
| Encryption | [libsodium.js](https://github.com/jedisct1/libsodium.js) (`crypto_box_seal`) |
| Encoding | BIP39 2048-word list |
| Backend / Auth / DB | [Supabase](https://supabase.com) (Postgres + RLS + RPC) |
| Hosting | [Vercel](https://vercel.com) (static) |

### Project structure
```
swc-app/
├── public/
│   ├── index.html          # Single-page app (all views)
│   ├── privacy.html
│   ├── terms.html
│   ├── css/style.css
│   ├── js/
│   │   ├── config.js       # Supabase URL + anon key
│   │   ├── bip39-wordlist.js
│   │   ├── i18n.js
│   │   ├── crypto.js       # Encryption / BIP39 encoding
│   │   ├── auth.js         # Supabase RPC wrappers
│   │   └── app.js          # View routing + event handlers
│   └── locales/
│       ├── en.json
│       └── bn.json
├── supabase/
│   └── schema.sql          # Run once in Supabase SQL Editor
├── vercel.json
├── .env.example
└── README.md
```

### Local setup
```bash
git clone https://github.com/1304016/swc-app.git
cd swc-app

# Serve the public/ folder with any static server:
npx serve public        # Node
python -m http.server 3000 --directory public   # Python
```

### Supabase setup
1. Create a new project at [supabase.com](https://supabase.com) (Singapore region recommended).
2. Go to **SQL Editor → New query**, paste the full contents of `supabase/schema.sql`, and run it.
3. Copy your **Project URL** and **anon (publishable) key** from **Project Settings → API**.
4. Update `public/js/config.js` with your URL and key.

### Vercel deployment
1. Push this repo to GitHub.
2. Go to [vercel.com](https://vercel.com) → **Add New Project** → import the GitHub repo.
3. No build step needed — Vercel serves `public/` as-is via `vercel.json` rewrites.
4. Click **Deploy**.

### Security design
| Concern | Mitigation |
|---------|-----------|
| Private key exposure | Never transmitted; stored only in browser localStorage + downloadable file |
| Password storage | bcrypt (cost 10) — only the hash stored in Postgres |
| Brute-force login | 5 failed attempts per 15 min per User ID (Postgres-side rate limit) |
| Direct DB access | RLS denies all direct table access; all operations via `SECURITY DEFINER` RPC |
| XSS | No `innerHTML` usage; strict CSP headers via `vercel.json` |
| Message content | Never sent to server — all encryption is client-side |

### i18n
Add a new language by creating `public/locales/<code>.json` mirroring `en.json`, then adding the entry to `getSupportedLangs()` in `i18n.js`.

### GDPR / CCPA
Users can permanently delete their account from the **Account** tab. Deletion scrubs public key and token hash, purges login attempt records, and soft-deletes the row.

---

## License
MIT
