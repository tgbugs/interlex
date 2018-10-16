-- CONNECT TO interlex_test USER "interlex-admin";
-- interlex-user interlex_test
/* tests */

--DO
--$body$
--BEGIN
INSERT INTO interlex_ids DEFAULT VALUES RETURNING id;

/*
INSERT INTO existing_iris (ilx_id, iri, group_id) VALUES ('0000001', 'http://uri.neuinfo.org/nif/nifstd/birnlex_796', 1),
                                                         ('0000001', 'http://purl.obolibrary.org/obo/UBERON_0000955', 1);
INSERT INTO triples (s, p, o)
       -- seriously consider pre-truncating everything for performance issues
       -- even if it is using my compression version of ttlser... probabably better
       -- to use the standard curies though for human readability of the database
       -- on the other hand using the uri type sort of obviates the issue
       VALUES ('http://uri.neuinfo.org/nif/nifstd/birnlex_796',
               'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
               'http://www.w3.org/2002/07/owl#Class'),
              ('http://uri.interlex.org/base/ilx_0000001',
               'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
               'http://www.w3.org/2002/07/owl#Class'),
              ('http://purl.obolibrary.org/obo/UBERON_0000955',
               'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
               'http://www.w3.org/2002/07/owl#Class');


INSERT INTO triples (s, p, o)
       -- hopefully case sensitive :x (indeed, thankfully)
       VALUES ('http://URI.NEUINFO.ORG/nif/nifstd/birnlex_796',
               'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
               'http://www.w3.org/2002/07/owl#Class'),
              ('HTTP://uri.interlex.org/base/ilx_0000001',
               'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
               'http://www.w3.org/2002/07/owl#Class'),
              ('http://purl.obolibrary.org/OBO/UBERON_0000955',
               'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
               'http://www.w3.org/2002/07/owl#Class');

*/

SELECT * FROM user_emails JOIN groups ON groups.id = user_emails.user_id;
SELECT * FROM users;

INSERT INTO orgs VALUES (idFromGroupname('uberon'), idFromGroupname('tgbugs'));  -- if run before I am a user fails

DELETE FROM orgs WHERE id = idFromGroupname('uberon');

SELECT * FROM groups;
SELECT * FROM user_permissions;

 -- UPDATE new_users set email_validated = TRUE WHERE id = 9;
 -- UPDATE new_users set orcid_validated = TRUE WHERE id = 9;

 -- test insert plus seed for no dupes later

INSERT INTO triples (s, p, o_lit) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'your father was a hampster');

INSERT INTO triples (s, p, o) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'http://test.url/object');

INSERT INTO triples (s, p, o_lit, datatype) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'object',
        'http://test.url/datatype');

INSERT INTO triples (s, p, o_lit, language) VALUES
       ('http://test.url/1',
        'http://test.url/annotationProperty',
        'object',
        'ja');

 -- annotations
 -- FIXME this approach seriously risks data integrity issues :/
 -- we *could* try to use subgraph_identity in this case to be the hash of the row??
 -- for major dumps we wouldn't have to use that identity but for one off retireveal
 -- it might actually be faster if the annotation identitiers were indexed? _BUT_ then
 -- we can't use null to distingusih annotations from subgraphs

INSERT INTO triples (s, s_blank, p, o_lit) VALUES
('annotation', 1, 'https://this-is-an-annotation-on-a-triple-maybe.maybe/?', 'YAY COMMENTS USING THE DISTINGUSHING POWER OF NOTHINGNESS!');

--END;
--$body$ language plpgsql;
