-- fragment prefixes

INSERT INTO fragment_prefix_sequences (prefix, suffix_max, current_pad) VALUES
 ('tmp', 0, 9),
 ('ilx', 0, 7),
 ('fde', 0, 7),
 ('cde', 0, 7),
 ('pde', 0, 8);

-- groups
-- NOTE: normalized to lower case

ALTER TABLE groups DISABLE TRIGGER groupname_length_check;
-- base

INSERT INTO groups (id, groupname, own_role) VALUES (0, 'empty', 'builtin');  -- we need the empty group to simplify handling the empty perspective
--(, 'base', 'builtin');  -- not an org, base for everything, root 0


INSERT INTO groups (groupname, own_role) VALUES
       -- builtins
       ('base', 'builtin'),  -- not an org, base for everything, can't be root 0 because we have uris that resolve
       ('latest', 'builtin'),
       ('origin', 'builtin'),
       ('curated', 'builtin'),
       ('reasonable', 'builtin')
       -- ('types', 'builtin')
       -- ('history', 'builtin') -- TODO consdier the right way to pull this off
       ;

-- perspectives

INSERT INTO perspectives (id, group_id, name, default_group_perspective) VALUES
-- the empty perspective, it is owned by the base group for
-- convenience XXX given that base currently has real semantics we may
-- want to have an empty group too
(0, 0, 'empty', FALSE),
(1, 1, 'base', FALSE); -- FIXME HACK this might not match as expected

--INSERT INTO perspective_parent (perspective, parent, datetime) VALUES ();

-- back to groups


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
       ('MetaCell'),
       ('scibot'),
       ('uberon'),
       ('obo'),
       ('NDA'),
       ('NINDSCDE'),
       ('TOPNT'),
       ('MESH'),
       ('FSL'),
       ('FreeSurfer'),
       ('fakeobo'),
       ('dicom'),
       ('biccn'),
       ('dknet'),
       ('sparc'),
       ('cocomac'),
       ('aibs'),
       ('HCP'),
       ('mindboggle'),
       ('paxinos'),
       ('waxholm'),
       ('berman'),
       ('npo'),
       ('neurons'),
       ('neuinfo'),
       ('swanson'),
       ('precise-tbi'), -- FIXME check name on this one
       ('NeuroLex'),
       ('InterLex');

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

                         -- compact
                         'h',  -- hashes XXX not sure if want
                         'l',  -- loads
                         'o',  -- ontologies
                         'q',  -- qualifiers
                         'r',  -- readable
                         't',  -- triples
                         'u',  -- uris
                         'hq',  -- hasQualifier
                         'ht',  -- hasTriple
                         'pq',  -- parentQualifier
                         'iq',  -- includeQualifier
                         'dq',  -- deleteQualifier
                         'eq',  -- excludeQualifier (aka dq)

                         'dns', -- used to simplify resolution to non-interlex iris with point in time support if we need to, simplifies curie redirect
                         'api',
                         'read',
                         'readonly',
                         'read-only',

                         'nil',
                         'null',
                         'zero',
                         'one',
                         'two',
                         'three',
                         'four',
                         'five',
                         'six',
                         'seven',
                         'eight',
                         'nine',
                         'ten',
                         'no-groupname',

                         'swagger',
                         'swaggerui',
                         'readable',
                         'contributions',
                         'ontology',
                         'ontologies',
                         'vocabulary',
                         'vocabularies',
                         'lexical',
                         'lexicon',
                         'version',
                         'versions',
                         'curie',
                         'curies',
                         'prefix',
                         'prefixes',
                         'load',
                         'loads',
                         'qualifier',
                         'qualifiers',
                         'triple',
                         'triples',
                         'hasTriple',
                         'hasQualifier',

                         'brain'
                         ]);


-- https://github.com/shouldbee/reserved-usernames/blob/master/reserved-usernames.txt
\cd :resources
\copy groups (groupname, own_role) FROM './reserved-usernames-len-gt-4.txt' ( FORMAT CSV, DELIMITER('|') );

ALTER TABLE groups ENABLE TRIGGER groupname_length_check;

-- user approval example and basic admin setup

-- DECLARE tgbugs_id integer;
-- SELECT id INTO STRICT tgbugs_id FROM idFromGroupname('tgbugs');
-- tgbugs_id := idFromGroupname('tgbugs');

INSERT INTO orcid_metadata (orcid, token_access) VALUES ('https://orcid.org/0000-0002-7509-4801', gen_random_uuid());

INSERT INTO users (id, orcid) VALUES
       (idFromGroupname('tgbugs'), 'https://orcid.org/0000-0002-7509-4801');

INSERT INTO user_emails (user_id, email, email_primary) VALUES
       (idFromGroupname('tgbugs'), 'tgbugs@gmail.com', TRUE);

UPDATE user_emails SET email_validated = CURRENT_TIMESTAMP WHERE user_id = idFromGroupname('tgbugs'); -- shouldn't actually be able to do this directly?
-- correct, interlex-user only has insert and select access, so these need to be populated via trigger on insert
--UPDATE users SET orcid_validated = CURRENT_TIMESTAMP WHERE id = idFromGroupname('tgbugs'); -- shouldn't actually be able to do this directly?

INSERT INTO user_permissions (group_id, user_id, user_role) VALUES (0, idFromGroupname('tgbugs'), 'admin');

-- development orgs
INSERT INTO orgs (id, creator_id) VALUES (idFromGroupname('MetaCell'), idFromGroupname('tgbugs'));
INSERT INTO user_permissions (group_id, user_id, user_role) VALUES (idFromGroupname('MetaCell'), idFromGroupname('tgbugs'), 'owner');

-- need the null identity in to avoid conficts
INSERT INTO identities (identity, type, record_count) VALUES (digest('', 'sha256'), 'empty', 0);

-- sources
-- INSERT INTO source_triples VALUES (E'\\x00', 0, 0);
-- INSERT INTO source_serialization VALUES (E'\\x00', E'\\x00');
-- INSERT INTO sources (id, owner_group_id, interlex_source_path, external_source_iri) VALUES
       -- (0, 0, '/interlex.ttl', 'https://uri.interlex.org/base/interlex.ttl');  -- FIXME we really need an agnostic suffix :/ owl is too xml
       -- the absolute madlads, they actually indended .owl as a semantic file extension O_O this explains so many things

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

-- pulls

INSERT INTO voting_systems (description, default_vote, quorum_ratio, pass_exact) VALUES
('pass if any reviewer approve',         'present',    1,            1); -- XXX this behavior is actually weird and bad because 4 deny 1 approve passes
INSERT INTO voting_systems (description, default_vote, quorum_ratio, pass_ratio) VALUES
('pass if all reviewer approve',         'absent',     1,            1); -- unanimity
INSERT INTO voting_systems (description, default_vote, quorum_ratio, fail_exact) VALUES
('pass if no reviewer deny',             'approve',    1,            1);
INSERT INTO voting_systems (description, default_vote, quorum_ratio, pass_ratio) VALUES
('pass if > 0.5 reviewer approve',       'absent',     1,            0.5);
INSERT INTO voting_systems (description, default_vote, quorum_ratio, pass_ratio) VALUES
('pass if > 0.66 reviewer approve',      'absent',     1,            0.66);

-- note the subtle difference between this and the variant where pass_ratio := 1, a present vote would block in that case
-- another way one might try to implement this would be as
-- default_vote pass_exact fail_exact, accept 1 1, except that
-- produces ambiguity that can lead to arguments if there is a 1:1 tie
-- in the exact criteria because then there is no specification for
-- what to do if the remaining accept outnumber the deny

-- we made them as a joke, for completeness
INSERT INTO voting_systems (description, default_vote, quorum_exact, pass_exact, fail_ratio) VALUES
('pass if any reviewer present',         'absent',     1,            0,          1);
-- does anybody object? yes! can I get a second? passed!
INSERT INTO voting_systems (description, default_vote, quorum_exact, pass_exact, fail_exact) VALUES
('pass if any reviewer deny',            'absent',     1,            0,          2);
INSERT INTO voting_systems (description, default_vote, quorum_exact, pass_exact) VALUES
('can i get a second',                   'absent',     1,            2); -- any 1 can bring motion but 2 required to pass, need some quorum_reached, duration or similar criteria, also works with default vote as present for committees of any size i think? quorum exact could be zero and pe 2? hrm.

INSERT INTO review_process_specs (description, voting_system, duration, duration_dow_after)
SELECT
-- 'public review, pass if no reviewer deny before the first friday after 1 week',
-- oh right, the reason this is confusing is because it is equivalent to one week from friday since addition is commutative and weeks is modular
-- 'public review, will pass if no objection 1 week from friday',
'public review, silent unanimous vote, until 1 week from friday', -- yep, silent votes must always have a duration
vs.id, '1 week', 'friday'
FROM voting_systems AS vs WHERE vs.description = 'pass if no reviewer deny';

/* -- probably don't use this because deny votes are meaningless
INSERT INTO review_process_specs (description, voting_system)
SELECT 'public review, pass if any reviewer approve', vs.id
FROM voting_systems AS vs WHERE vs.description = 'pass if any reviewer approve';
*/

INSERT INTO review_process_specs (description, voting_system) SELECT
-- 'public review, pass if all reviewer approve',
'public review, unanimous vote', vs.id
FROM voting_systems AS vs WHERE vs.description = 'pass if all reviewer approve';

INSERT INTO review_process_specs (description, voting_system) SELECT
'public review, majority vote', vs.id
FROM voting_systems AS vs WHERE vs.description = 'pass if > 0.5 reviewer approve';

INSERT INTO review_process_specs (description, voting_system) SELECT
'public review, super majority vote', vs.id
FROM voting_systems AS vs WHERE vs.description = 'pass if > 0.66 reviewer approve';

/* -- by default there is no formal review step so only role <= curator can merge
INSERT INTO perspective_pull_settings (perspective_id, default_spec)
SELECT 0, rps.id
FROM review_process_specs AS rps WHERE rps.description = 'public review, pass if all reviewer approve';
*/

