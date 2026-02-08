-- Migration: 06-add-ip-and-ua-to-sessions.sql
-- Description: Add ip_address and user_agent to refresh_tokens for session tracking

ALTER TABLE auth.refresh_tokens ADD COLUMN ip_address INET;
ALTER TABLE auth.refresh_tokens ADD COLUMN user_agent TEXT;
