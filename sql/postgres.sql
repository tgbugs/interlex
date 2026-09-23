-- postgres postgres
-- CONNECT TO postgres USER postgres;

DO
$body$
BEGIN
    IF NOT EXISTS ( SELECT * FROM pg_catalog.pg_user
        WHERE usename = 'interlex-user') THEN
        CREATE ROLE "interlex-user" LOGIN
        NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE;
    END IF;

    IF NOT EXISTS ( SELECT * FROM pg_catalog.pg_user
        WHERE usename = 'interlex-admin') THEN
        CREATE ROLE "interlex-admin" LOGIN
        NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE;
    END IF;
END;
$body$ language plpgsql;

-- postgres postgres

ALTER ROLE "interlex-admin" SET search_path = interlex, public;
ALTER ROLE "interlex-user" SET search_path = interlex, public;

-- postgres postgres

-- rds needs this https://stackoverflow.com/a/34898033
SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'rdsadmin') AS rds \gset

\if :rds
GRANT "interlex-admin" TO CURRENT_USER;
\endif

-- postgres postgres

DROP DATABASE IF EXISTS :database;

-- postgres postgres

\if :rds
CREATE DATABASE :database -- interlex
    WITH OWNER = 'interlex-admin'
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    CONNECTION LIMIT = -1;
\else
CREATE DATABASE :database -- interlex
    WITH OWNER = 'interlex-admin'
    ENCODING = 'UTF8'
    TABLESPACE = pg_default
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    CONNECTION LIMIT = -1;
\endif

-- postgres postgres

\if :rds
REVOKE "interlex-admin" FROM CURRENT_USER;
\endif
