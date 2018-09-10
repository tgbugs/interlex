-- failing tests
INSERT INTO existing_iris VALUES ('0000001', 'http://uri.interlex.org/test', idFromGroupname('tgbugs'));
INSERT INTO existing_iris VALUES ('0000001', 'http://curies.interlex.org/test:', idFromGroupname('tgbugs'));

UPDATE groups SET own_role = 'admin' WHERE id = idFromGroupname('tgbugs');

INSERT INTO triples (s, p, o_lit, datatype, language) VALUES ('http://ex.org/a', 'http://ex.org/b', 'test', 'http://ex.org/type', 'klingon');

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

INSERT INTO triples (s, p, o_lit) VALUES
       ('http://test.ur/1',
       'http://test.url/annotationProperty',
       'your father was a hampster');
INSERT INTO triples (s, p, o_lit) VALUES
       ('http://test.url/1',
       'http://test.url/annotationProperty',
       'your father was a hampster');
DELETE FROM triples WHERE s = 'http://test.url/1';
