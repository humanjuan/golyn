-- Migration: Add theme column to auth.users
-- Date: 2026-01-10

\connect golyn;

ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS theme JSONB;

-- Optional: Initial default theme for existing users can be set here if needed
-- UPDATE auth.users SET theme = '{"sidebar": {"--color-primary": "#3EBF33", "--sidebar-bg": "#3EBF33", "--sidebar-bg-item-active": "#F8F9FA", "--sidebar-item-hover": "#22c55e", "--sidebar-text": "#F8F9FA", "--sidebar-text-secondary": "#9CA3AF", "--sidebar-text-hover": "#FFFFFF", "--sidebar-text-active": "#3EBF33", "--sidebar-item-tooltip": "#1E1E1E"}, "logoVariant": "white"}' WHERE theme IS NULL;
