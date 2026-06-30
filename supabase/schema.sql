-- ============================================================
-- Secret Word Cipher — Supabase Schema
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New query)
-- ============================================================

-- Enable pgcrypto for bcrypt hashing
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ────────────────────────────────────────────────────────────
-- Tables
-- ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.swc_users (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       TEXT        UNIQUE NOT NULL,   -- numeric string, shown to user
  public_key    TEXT        NOT NULL,           -- base64 NaCl box public key
  token_hash    TEXT        NOT NULL,           -- bcrypt hash of secret token
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login    TIMESTAMPTZ,
  is_deleted    BOOLEAN     NOT NULL DEFAULT FALSE,
  deleted_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS public.login_attempts (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier   TEXT        NOT NULL,           -- user_id that was attempted
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  success      BOOLEAN     NOT NULL DEFAULT FALSE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_swc_users_user_id
  ON public.swc_users(user_id) WHERE NOT is_deleted;

CREATE INDEX IF NOT EXISTS idx_login_attempts_rate
  ON public.login_attempts(identifier, attempted_at DESC);

-- ────────────────────────────────────────────────────────────
-- Row Level Security — deny all direct table access
-- All operations must go through SECURITY DEFINER functions
-- ────────────────────────────────────────────────────────────

ALTER TABLE public.swc_users        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.login_attempts   ENABLE ROW LEVEL SECURITY;

CREATE POLICY "deny_all_swc_users"
  ON public.swc_users FOR ALL USING (FALSE);

CREATE POLICY "deny_all_login_attempts"
  ON public.login_attempts FOR ALL USING (FALSE);

-- ────────────────────────────────────────────────────────────
-- RPC: Register new user
-- ────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.swc_register(
  p_user_id     TEXT,
  p_public_key  TEXT,
  p_secret_token TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_hash TEXT;
BEGIN
  -- Basic input validation
  IF p_user_id !~ '^\d{8,12}$' THEN
    RETURN jsonb_build_object('error', 'invalid_user_id',
      'message', 'User ID must be 8–12 digits.');
  END IF;

  IF length(p_public_key) < 40 THEN
    RETURN jsonb_build_object('error', 'invalid_public_key',
      'message', 'Invalid public key.');
  END IF;

  IF length(p_secret_token) < 20 THEN
    RETURN jsonb_build_object('error', 'invalid_token',
      'message', 'Secret token too short.');
  END IF;

  -- Check uniqueness
  IF EXISTS (SELECT 1 FROM public.swc_users WHERE user_id = p_user_id) THEN
    RETURN jsonb_build_object('error', 'user_id_taken',
      'message', 'This User ID is already taken. A new one will be generated.');
  END IF;

  -- Hash with bcrypt cost=10
  v_hash := crypt(p_secret_token, gen_salt('bf', 10));

  INSERT INTO public.swc_users (user_id, public_key, token_hash)
  VALUES (p_user_id, p_public_key, v_hash);

  RETURN jsonb_build_object('success', true, 'user_id', p_user_id);
END;
$$;

-- ────────────────────────────────────────────────────────────
-- RPC: Login
-- ────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.swc_login(
  p_user_id      TEXT,
  p_secret_token TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user       RECORD;
  v_fail_count INT;
  v_dummy_hash TEXT := '$2a$10$dummy.salt.to.prevent.timing.attack.12345678';
BEGIN
  -- Rate limit: 5 failures per 15 min per identifier
  SELECT COUNT(*) INTO v_fail_count
  FROM public.login_attempts
  WHERE identifier   = p_user_id
    AND attempted_at > NOW() - INTERVAL '15 minutes'
    AND success      = FALSE;

  IF v_fail_count >= 5 THEN
    RETURN jsonb_build_object('error', 'rate_limited',
      'message', 'Too many failed attempts. Please wait 15 minutes.');
  END IF;

  -- Fetch user
  SELECT * INTO v_user
  FROM public.swc_users
  WHERE user_id = p_user_id AND is_deleted = FALSE;

  IF NOT FOUND THEN
    -- Constant-time dummy compare to prevent user enumeration via timing
    PERFORM crypt(p_secret_token, v_dummy_hash);
    INSERT INTO public.login_attempts (identifier, success) VALUES (p_user_id, FALSE);
    RETURN jsonb_build_object('error', 'invalid_credentials',
      'message', 'Invalid User ID or Secret Token.');
  END IF;

  -- Verify token
  IF crypt(p_secret_token, v_user.token_hash) = v_user.token_hash THEN
    UPDATE public.swc_users SET last_login = NOW() WHERE user_id = p_user_id;
    INSERT INTO public.login_attempts (identifier, success) VALUES (p_user_id, TRUE);
    RETURN jsonb_build_object(
      'success',    true,
      'user_id',    v_user.user_id,
      'public_key', v_user.public_key
    );
  ELSE
    INSERT INTO public.login_attempts (identifier, success) VALUES (p_user_id, FALSE);
    RETURN jsonb_build_object('error', 'invalid_credentials',
      'message', 'Invalid User ID or Secret Token.');
  END IF;
END;
$$;

-- ────────────────────────────────────────────────────────────
-- RPC: Get public key (for encryption)
-- ────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.swc_get_public_key(p_user_id TEXT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user RECORD;
BEGIN
  SELECT user_id, public_key INTO v_user
  FROM public.swc_users
  WHERE user_id = p_user_id AND is_deleted = FALSE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found',
      'message', 'User not found.');
  END IF;

  RETURN jsonb_build_object('user_id', v_user.user_id, 'public_key', v_user.public_key);
END;
$$;

-- ────────────────────────────────────────────────────────────
-- RPC: Delete account (GDPR / CCPA right-to-delete)
-- ────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.swc_delete_account(
  p_user_id      TEXT,
  p_secret_token TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user RECORD;
BEGIN
  SELECT * INTO v_user
  FROM public.swc_users
  WHERE user_id = p_user_id AND is_deleted = FALSE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF crypt(p_secret_token, v_user.token_hash) = v_user.token_hash THEN
    -- Soft-delete + scrub PII
    UPDATE public.swc_users
    SET is_deleted = TRUE,
        deleted_at  = NOW(),
        public_key  = '[deleted]',
        token_hash  = '[deleted]'
    WHERE user_id = p_user_id;

    DELETE FROM public.login_attempts WHERE identifier = p_user_id;

    RETURN jsonb_build_object('success', true);
  ELSE
    RETURN jsonb_build_object('error', 'invalid_credentials',
      'message', 'Invalid Secret Token. Account not deleted.');
  END IF;
END;
$$;

-- ────────────────────────────────────────────────────────────
-- Grant execute to anonymous role (client-facing API)
-- ────────────────────────────────────────────────────────────

GRANT EXECUTE ON FUNCTION public.swc_register      TO anon;
GRANT EXECUTE ON FUNCTION public.swc_login         TO anon;
GRANT EXECUTE ON FUNCTION public.swc_get_public_key TO anon;
GRANT EXECUTE ON FUNCTION public.swc_delete_account TO anon;
