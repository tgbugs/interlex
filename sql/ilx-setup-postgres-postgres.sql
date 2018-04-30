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

DROP DATABASE IF EXISTS :database;

-- postgres postgres

CREATE DATABASE :database -- interlex
    WITH OWNER = 'interlex-admin'
    ENCODING = 'UTF8'
    TABLESPACE = pg_default
    LC_COLLATE = 'en_US.utf8'  -- as opposed to 'en_US.UTF-8' for < 10.0 ??
    LC_CTYPE = 'en_US.utf8'
    CONNECTION LIMIT = -1;

