-- CONNECT TO interlex_test USER "interlex-admin";
-- interlex-user interlex_test
/* tests */

--DO
--$body$
--BEGIN
INSERT INTO interlex_ids DEFAULT VALUES RETURNING id;

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

-- DECLARE tgbugs_id integer;
-- SELECT id INTO STRICT tgbugs_id FROM idFromGroupname('tgbugs');
-- tgbugs_id := idFromGroupname('tgbugs');

INSERT INTO user_emails (user_id, email, email_primary) VALUES (idFromGroupname('tgbugs'), 'tgbugs@gmail.com', TRUE);
INSERT INTO users (id, orcid) VALUES (idFromGroupname('tgbugs'), 'https://orcid.org/0000-0002-7509-4801');

select * from user_emails join groups on groups.id = user_emails.user_id;
select * from users;

UPDATE user_emails SET email_validated = TRUE WHERE user_id = idFromGroupname('tgbugs'); -- shouldn't actually be able to do this directly?
-- correct, interlex-user only has insert and select access, so these need to be populated via trigger on insert
UPDATE users SET orcid_validated = TRUE WHERE id = idFromGroupname('tgbugs'); -- shouldn't actually be able to do this directly?

INSERT INTO user_permissions VALUES (0, idFromGroupname('tgbugs'), 'admin');

INSERT INTO orgs VALUES (idFromGroupname('uberon'), idFromGroupname('tgbugs'));  -- if run before I am a user fails

DELETE FROM orgs WHERE id = idFromGroupname('uberon');

select * from groups;
select * from user_permissions;

 -- UPDATE new_users set email_validated = TRUE WHERE id = 9;
 -- UPDATE new_users set orcid_validated = TRUE WHERE id = 9;


--END;
--$body$ language plpgsql;

