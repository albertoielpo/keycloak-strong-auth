-- Create keycloak schema
CREATE SCHEMA IF NOT EXISTS keycloak;

-- Grant privileges to postgres user (or create a dedicated keycloak user)
GRANT ALL PRIVILEGES ON SCHEMA keycloak TO postgres;

-- Set search path to include keycloak schema
ALTER DATABASE postgres SET search_path TO public, keycloak;