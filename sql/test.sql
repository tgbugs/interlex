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


--END;
--$body$ language plpgsql;

