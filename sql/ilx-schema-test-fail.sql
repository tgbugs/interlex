-- failing tests
INSERT INTO existing_iris VALUES ('0000001', 'http://uri.interlex.org/test', idFromGroupname('tgbugs'));
INSERT INTO existing_iris VALUES ('0000001', 'http://curies.interlex.org/test:', idFromGroupname('tgbugs'));

UPDATE groups SET own_role = 'admin' WHERE id = idFromGroupname('tgbugs');
