-- interlex-admin interlex_test

CREATE SCHEMA IF NOT EXISTS interlex;
CREATE FUNCTION reference_host() RETURNS varchar
       IMMUTABLE LANGUAGE SQL AS 'SELECT ''uri.interlex.org''';
