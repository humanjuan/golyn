-- Create user dev with password
CREATE USER dev WITH PASSWORD 'IdontKnow';

-- Create database golyn owned by root
-- CREATE DATABASE golyn;
\c golyn;

-- Create schema golyn in database golyn
CREATE SCHEMA golyn;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA golyn;
CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA golyn;

-- Grant privileges to user dev
GRANT ALL PRIVILEGES ON DATABASE golyn TO dev;
GRANT ALL PRIVILEGES ON SCHEMA golyn TO dev;
ALTER DEFAULT PRIVILEGES IN SCHEMA golyn
GRANT ALL ON TABLES TO dev;
ALTER DEFAULT PRIVILEGES IN SCHEMA golyn
GRANT ALL ON FUNCTIONS TO dev;