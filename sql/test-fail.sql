-- negative tests
-- block interlex uris from being existing_iris
INSERT INTO existing_iris VALUES ('ilx', '0000001', 'http://uri.interlex.org/test', idFromGroupname('tgbugs'));
INSERT INTO existing_iris VALUES ('ilx', '0000001', 'http://curies.interlex.org/test:', idFromGroupname('tgbugs'));

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
INSERT INTO triples (s, p, o_lit, triple_identity) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'your father was a hampster',
        tripleIdentity('http://test.url/1', 'http://test.url/annotationProperty', null, 'your father was a hampster', null, null));

INSERT INTO triples (s, p, o, triple_identity) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'http://test.url/object',
        tripleIdentity('http://test.url/1', 'http://test.url/annotationProperty', 'http://test.url/object', null, null, null));

INSERT INTO triples (s, p, o_lit, datatype, triple_identity) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'object',
        'http://test.url/datatype',
        tripleIdentity('http://test.url/1', 'http://test.url/annotationProperty', null, 'object', 'http://test.url/datatype', null));

INSERT INTO triples (s, p, o_lit, language, triple_identity) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'object',
        'ja',
        tripleIdentity('http://test.url/1', 'http://test.url/annotationProperty', null, 'object', null, 'ja'));

-- no ilx outside base
INSERT INTO triples (s, p, o, triple_identity) VALUES ('http://uri.interlex.org/tgbugs/ilx_1234567', 'http://uri.interlex.org/base/ilx_1234567', 'http://uri.interlex.org/base/ilx_1234567', '\xeb49899f5a01f12924a3c5a6937c6e1722803e7713830a82bc2bfce93e37fb3a'::bytea);

INSERT INTO triples (s, p, o, triple_identity) VALUES ('http://uri.interlex.org/base/ilx_1234567', 'http://uri.interlex.org/tgbugs/ilx_1234567', 'http://uri.interlex.org/base/ilx_1234567', '\x326cb669fcc30bcd8ff66763700296c728bcb7d953561a55e694bc759a074d4b'::bytea);

INSERT INTO triples (s, p, o, triple_identity) VALUES ('http://uri.interlex.org/base/ilx_1234567', 'http://uri.interlex.org/base/ilx_1234567', 'http://uri.interlex.org/tgbugs/ilx_1234567', '\xc257b22607590cf9a007f7bdb01da196c088aef0c6f1589f9d874efde9062ad2'::bytea);

-- checksum mismatch

INSERT INTO triples (s, p, o, triple_identity) VALUES ('http://uri.interlex.org/base/ilx_1234567', 'http://uri.interlex.org/base/ilx_1234567', 'http://uri.interlex.org/base/ilx_1234567', '\x896caba6372d15cfe6b211ffab08a0e65ad72ab62e15fc93d0f93b4cba2c4e79'::bytea);
-- 896caba6372d15cfe6b211ffab08a0e65ad72ab62e15fc93d0f93b4cba2c4e78

--DELETE FROM triples WHERE s = 'http://test.url/1';  -- FIXME for some reason this fails!? -> .ur/ != .url/

-- emails must be unique (group emails don't exist)
INSERT INTO user_emails (user_id, email, email_primary) VALUES
       (idFromGroupname('base'), 'tgbugs@gmail.com', TRUE);

-- builtins may have emails, but generic groups do not
INSERT INTO user_emails (user_id, email, email_primary) VALUES
       (idFromGroupname('base'), 'base@interlex.org', TRUE);
