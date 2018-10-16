-- negative tests
-- block interlex uris from being existing_iris
INSERT INTO existing_iris VALUES ('0000001', 'http://uri.interlex.org/test', idFromGroupname('tgbugs'));
INSERT INTO existing_iris VALUES ('0000001', 'http://curies.interlex.org/test:', idFromGroupname('tgbugs'));

-- own role cannot be admin
UPDATE groups SET own_role = 'admin' WHERE id = idFromGroupname('tgbugs');

-- datatype or language, not both
INSERT INTO triples (s, p, o_lit, datatype, language) VALUES
       ('http://ex.org/a', 'http://ex.org/b', 'test', 'http://ex.org/type', 'klingon');

-- no dupes s, p, o_blank
INSERT INTO triples (s, p, o_blank, subgraph_identity) VALUES
       ('http://test.url/1',
       'http://test.url/predicate',
       0,
       E'\\x47bae44cd84731f1f1566b48bb7f6fe93532fd0466bd24371dd34f89d4e4420d');
INSERT INTO triples (s, p, o_blank, subgraph_identity) VALUES
       ('http://test.url/1',
       'http://test.url/predicate',
       0,
       E'\\x47bae44cd84731f1f1566b48bb7f6fe93532fd0466bd24371dd34f89d4e4420d');
DELETE FROM triples WHERE s = 'http://test.url/1';

-- no dupes s, p, o_lit
INSERT INTO triples (s, p, o_lit) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'your father was a hampster');
--DELETE FROM triples WHERE s = 'http://test.url/1';  -- FIXME for some reason this fails!?

-- emails must be unique (group emails don't exist)
INSERT INTO user_emails (user_id, email, email_primary) VALUES
       (idFromGroupname('base'), 'tgbugs@gmail.com', TRUE);

-- builtins may have emails, but generic groups do not
INSERT INTO user_emails (user_id, email, email_primary) VALUES
       (idFromGroupname('base'), 'base@interlex.org', TRUE);
