-- Migration: Add permissions to users table
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS permissions JSONB;
