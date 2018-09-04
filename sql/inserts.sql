-- groups
-- NOTE: normalized to lower case

ALTER TABLE groups DISABLE TRIGGER groupname_length_check;
-- base

INSERT INTO groups (id, groupname, own_role) VALUES (0, 'base', 'builtin');  -- not an org, base for everything, root 0

INSERT INTO groups (groupname, own_role) VALUES
       -- builtins
       ('latest', 'builtin'),
       ('origin', 'builtin'),
       ('curated', 'builtin'),
       ('reasonable', 'builtin')
       -- ('types', 'builtin')
       -- ('history', 'builtin') -- TODO consdier the right way to pull this off
       ;

INSERT INTO groups (groupname) VALUES
       -- users
       ('tgbugs'),
       ('jgrethe'),
       ('bandrow'),
       ('memartone'),
       -- ('slarson'),

       -- orgs
       ('NIF'),
       ('SciCrunch'),
       ('scibot'),
       ('uberon'),
       ('obo'),
       ('NDA'),
       ('MESH'),
       ('FSL'),
       ('FreeSurfer');

-- blacklist
-- populate more with with len > 4
-- TODO populate also from group_role
-- make sure user roles are also black liasted here
-- blackhole
-- behavior when resolving is to 404
-- behavior if referenced internally by accident internally?

INSERT INTO groups (own_role, groupname)
       SELECT 'blacklist', unnest.unnest
       FROM unnest(enum_range(NULL::group_role)) ON CONFLICT (groupname) DO NOTHING;

-- API structure endpoints or other names with length > 4
INSERT INTO groups (own_role, groupname)
       SELECT 'blacklist', unnest
       FROM unnest(ARRAY['info',
                         'postgres',
                         'default'
                         'type',  -- TODO
                         'types',

                         'tom',
                         'tgillesp',
                         'tgillespie',
                         'jeff',
                         'anita',
                         'maryann',

                         'api',
                         'read',
                         'readonly',
                         'read-only',

                         'swagger',
                         'swaggerui',
                         'readable',
                         'contributions',
                         'ontology',
                         'ontologies',
                         'vocabulary',
                         'vocabularies',
                         'lexicon',
                         'version',
                         'versions',
                         'curie',
                         'curies',
                         'prefix',
                         'prefixes'
                         ]);


-- https://github.com/shouldbee/reserved-usernames/blob/master/reserved-usernames.txt
\cd :resources
\copy groups (groupname, own_role) FROM './reserved-usernames-len-gt-4.txt' ( FORMAT CSV, DELIMITER('|') );

ALTER TABLE groups ENABLE TRIGGER groupname_length_check;

-- sources
-- INSERT INTO source_triples VALUES (E'\\x00', 0, 0);
-- INSERT INTO source_serialization VALUES (E'\\x00', E'\\x00');
-- INSERT INTO sources (id, owner_group_id, interlex_source_path, external_source_iri) VALUES
       -- (0, 0, '/interlex.ttl', 'https://uri.interlex.org/base/interlex.ttl');  -- FIXME we really need an agnostic suffix :/ owl is too xml

-- prov
/*
INSERT INTO load_processes 
(id,
source_serialization_hash,
process_type,
-- source_iri,
-- vcs_commit_ident,
-- datetime
group_id,
user_id) VALUES
(0, E'\\x00', 'InterLex', 0, 0);
*/
-- qualifiers
/*
INSERT INTO qualifiers (id, source_id, source_triples_hash, group_id, -- datetime
       previous_qualifier_id, equivalent_qualifier_id, load_process_id, source_serialization_hash)
       VALUES (0, 0, E'\\x00', 0, 0, 0, 0, E'\\x00');
*/
