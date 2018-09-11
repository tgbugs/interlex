-- CONNECT TO interlex_test USER "interlex-admin";
-- see notes in new-schema.sql

CREATE sequence if NOT exists interlex_ids_seq;

CREATE TABLE interlex_ids(
       -- these when used in http://uri.interlex.org/base/ilx_{id} are the reference ids for terms
       -- they can however be mapped to more than one since they cannot (usually) be bound
       id char(7) PRIMARY key DEFAULT LPAD(NEXTVAL('interlex_ids_seq')::text, 7, '0'),
       CHECK (id ~ '[0-9]{7}')
);

CREATE OR REPLACE FUNCTION ilxIdFromIri(iri uri, OUT ilx_id char(7)) RETURNS char(7) AS $ilxIdFromIri$
       BEGIN
           SELECT substring((uri_path_array(iri))[array_upper(uri_path_array(iri), 1)], 5)::char(7) INTO ilx_id;
       END;
$ilxIdFromIri$ language plpgsql;

CREATE TABLE existing_iris(
       -- note that this table does NOT enumerate any uri.interlex.org identifiers
       -- the default/curated user will be the fail over
       -- do we need exclude rules? latest + original user will always be inserted
       -- but do we really even need latest to be explicit here?
       ilx_id char(7) NOT NULL,
       iri uri UNIQUE NOT NULL CHECK (uri_host(iri) NOT LIKE '%interlex.org'),
       group_id integer NOT NULL,
       CONSTRAINT fk__existing_iris__ilx_id__interlex_ids
                  FOREIGN key (ilx_id)
                  REFERENCES interlex_ids (id) match simple,
       CONSTRAINT fk__existing_iris__group_id__group
                  FOREIGN key (group_id)
                  REFERENCES groups (id) match simple,
       CONSTRAINT pk__existing_iris PRIMARY KEY (iri, group_id)
);

-- NOTE 'names' referred to here are 'graph names' or 'triple set names'
/* DOCS
   see v3 for some early thinking
   0. binding
      +
      when one identified piece of data is stuck to another one
      either explicitly or implicitly
      implicitly as in a file or as in 'i got this data using this name but the name is not in the data'
      invariant -> name
      bound invariant -> bound name
      co-named variable -> just some other data (metadata)
      bound co-named variable -> bound metadata
      1. strong binding relation
         in the same file
         trusted 3rd party source that provides identity of the bound pair with a method to reproduce
      2. pointing aka weak binding relations
         data resolved to using url
         filename for data
         data pointed to by name
   1. identity
      source -> data OR data + name OR data + metadata + name
      name
      metadata
      data
      name + data
      name + metadata
      (or metadata - name if you implicitly included the name in the metadata)
   2. name independent identity
   3. co-named data
      also co-bound-name data
   4. source subset rule
      name -> points to relation, or 'should be pointed to by'
      metadata -> about
      ---
      basically any way that you can split up the source
      metadata is just a name we give to a particular subset of a source
      you can split stuff up as much as you want, the question is
      whether there is a part of it that is or can be used for identity
      so ignore htis and focus on name independent identity
   5. metadata
      in some sense this ends up being data 'about' the name, not the 'named' data
      and it is the aboutness relationship that we subset on for the subset rule
      BUT the aboutness is context dependent and that is still data
      there are other subsetting rules that could be used as well

*/
CREATE TABLE names(
       -- any uri that has ever pointed to a bound name, the set of these is quite large
       -- even those that no longer resolve but are bound names
       -- NOTE that security/validity/trust is not managed at this level
       -- it is managed at the level of qualifiers, anyone can claim to be uberon
       -- the validity of the claim is orthogonal to the claim itself, these tables deal with the claims
       -- the best way to identify invalid claims is the enumerate them an mark them as such
       -- NOTE this table can be extended to track the current state of the resolution of a name
       name uri PRIMARY KEY
       -- should not be a reference name?
);

/*  -- going to do this as a table initially
CREATE FUNCTION name_to_identity() RETURNS trigger as $$
       BEGIN
       END;
$$ language plpgsql;

CREATE TRIGGER name_to_identity BEFORE INSERT
       ON names FOR EACH ROW EXECUTE PROCEDURE no_update_expected_bound_name();
*/

CREATE TABLE reference_names(
       -- the set of interlex uris that we use internally to track all bound names
       -- one or the other of these names SHALL be the bound name
       -- note that I'm implementing this with uris, but really it could be anything
       name uri PRIMARY KEY CHECK (uri_host(name) = reference_host()),  -- change this to match your system
       -- external_name uri UNIQUE, -- this doesn't go here
       expected_bound_name uri UNIQUE,  -- default name, but can be updated to a single external external name
       -- FIXME what happens in cases where an external source looses control of a uri and has to change the bound name?
       -- I think we can use ordering on bound name identities to resolve the issue without too much trouble
       CHECK (uri_host(expected_bound_name) = reference_host()
              AND
              expected_bound_name = name
              OR
              uri_host(expected_bound_name) <> reference_host()),
       group_id integer NOT NULL -- TODO where names are actually uris check that the group name matches
);

CREATE FUNCTION no_update_expected_bound_name() RETURNS trigger as $$
       BEGIN
           IF OLD.expected_bound_name IS NOT NULL AND OLD.expected_bound_name <> OLD.name THEN
              RAISE exception 'Cannot change the expected bound name for a reference name!';
              -- if you need to do this then use use the name ordering functionality
              -- can change away from case where name matches ebn
           END IF;
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TRIGGER no_update_expected_bound_name BEFORE UPDATE
       ON reference_names FOR EACH ROW EXECUTE PROCEDURE no_update_expected_bound_name();

CREATE FUNCTION user_reference_name() RETURNS trigger AS $$
       BEGIN
           INSERT INTO reference_names (name, group_id)
                  -- this tracks the source that is the user's interlex
                  -- contributions that have no additional artifact
                  -- uploads are tied to bound name of the file
                  -- and can be tracked and computed separately
                  SELECT 'https://' || reference_host() || '/' || groupname || '/contributions', id
                  FROM groups WHERE id = NEW.id;
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TRIGGER user_reference_name AFTER INSERT
       ON users FOR EACH ROW EXECUTE PROCEDURE user_reference_name();

-- graph_subsets, graphs, subgraphs... HRM content_sets, ie the actual ontology content

-- note to self: qualified and unqualified imports, all named based imports without identity are unqualified
-- we distinguish here because names 'point' to more than one type of thing that we want to be able to track the history of
CREATE TYPE named_type AS ENUM ('serialization',
                                'local_naming_conventions',  -- aka curies
                                -- bound to bound_name incidentally so they are ranked higher
                                -- FIXME hashing bound names for this is stupid
                                'bound_name',  -- just use the string itself? might be more space efficient to hash? we will want to be able to
                                         --   create name equivalences e.g. for mapping user iris to interlex iris?
                                         --   but probably not using the qualifier system... probably...
                                         --   nope, needed to track external renamings ?? we will find a use
                                         --   nope again, names don't have reference names, that would be redundant
                                         --   triple nope, names as defined in the names table sure do map to reference_names... but they might map to more than one, so quad nope
                                         --   quint nope says bound_name is in 1:1 with reference_name and need to be able to reconstruct the actual name
                                -- 'source',  -- (name, metadata_identity, data_identity) but could be any subset of those, and we can reconstruct using the load data
                                'metadata',  -- pairs, includes the type
                                'data',  -- triples s p o type + lang
                                'subgraph' -- FIXME how is this any different from data? unnamed subgraphs
                                -- singletion identified by hash on triple set  these are not named, that is the whole point, so they don't need to be here
                                -- 'name-metadata' -- (name, metadata_identity)
                                -- 'name-data' -- (name, data_identity)
                                -- 'source',  -- can be computed if we need it
                                );

CREATE TABLE identities(
       identity bytea PRIMARY KEY,
       triples_count integer NOT NULL, -- ok to be zero for bound_name
       reference_name uri,
       type named_type NOT NULL,
       CHECK (reference_name IS NULL AND type = 'subgraph' OR
              reference_name IS NOT NULL AND type = 'subgraph' OR
              type <> 'subgraph'),
       -- FIXME serialization from interlex needs to differ from triples?? name
       -- also n3 format might collide?
       CONSTRAINT fk__identities__reference_name__reference_names
                  FOREIGN key (reference_name)
                  REFERENCES reference_names (name) match simple
       -- this includes metadata identities because the keys will never collide unless they do, in which case we want to know
       -- anything that is co-named here can go in, the process of calculating the identity is effectively identical even though
       -- the code is different, it is just the data - the name
       -- we just have to create an additional qualifier off of the source which has a parallel history per user
       -- and then we link the two in another table?! no, the problem is determining the correct previous qualifier
       -- this could include any hashing identities including unparsed bytes?
);

CREATE INDEX identities_identity_index ON identities (identity);

CREATE TABLE name_to_identity(
       -- as opposed to hashing names
       name uri,
       identity bytea,  -- usually should point to a serialization
       CONSTRAINT pk__name_to_identity PRIMARY KEY (name, identity),
       CONSTRAINT fk__name_to_identity__name__names
                  FOREIGN key (name)
                  REFERENCES names (name) match simple,
       CONSTRAINT fk__name_to_identity__identity__identities
                  FOREIGN key (identity)
                  REFERENCES identities (identity) match simple
);

CREATE TABLE currently_loading_names(
       -- locking table
       -- need read uncommitted when checking?
       -- explicitly no fk here
       -- just ignore this if loading multiple versions of the same name
       name uri PRIMARY KEY NOT NULL
);

CREATE TABLE currently_loading_serializations(
       -- locking table
       -- need read uncommitted when checking?
       -- explicitly no fk here
       identity bytea PRIMARY KEY NOT NULL
);

CREATE TYPE source_process AS ENUM ('FileFromIRI',  -- transitive closure be implemented using these on each file
                                    'FileFromPOST', -- we do not allow untrackable uploads use /<user>/ontologies /user/upload worst case
                                    'FileFromVCS',  -- this requires InterLex to clone the repo... which is ok I guess requires admin
                                    'NonOntologyFileFromVCS',

                                    'InterLexFile', -- source process for the collection of rules used to create a file
                                    -- these are the static sets of rules that are used to generate a file from a set of qualifiers

                                    'ReasonerOnFile', -- always reason on a 'file' as the abstraction never on subset directly
                                    -- when reasoning on an interlex defined file have to be careful to exclude already reasoned
                                    -- reasoned on file entries should have the file qualifier 
                                    -- 'ReasonerOnSubset',
                                    'InterLex'
                                    );


CREATE TYPE identity_relation AS ENUM ('hasPart', 'dereferencedTo'); -- , 'named', 'pointedTo', 'resolvedTo');
-- dereferencedTo history can be reconstructed for names -> serialization without a bound name

CREATE TYPE qualifier_relations AS ENUM('includes',
                                        'excludes',
                                        'hasPrev', -- hasNext? there are multiple possible nexts
                                        'break');

CREATE TYPE qualifier_types AS ENUM('group',
                                    'reference_name',  -- aka source qualifier
                                    'computed',
                                    -- computed and static could be used for things like latest
                                    -- where there is a static rule that is used to generate
                                    -- the triple set and versions are generated on change
                                    -- for the old version...
                                    'static_create_new_on_version'
);

CREATE TABLE identity_relations(
       s bytea NOT NULL,
       p identity_relation,
       o bytea NOT NULL,
       CONSTRAINT pk__serialization_parts PRIMARY KEY (s, p, o),
       CONSTRAINT fk__identity_relations__s__identities
                  FOREIGN key (s)
                  REFERENCES identities (identity) match simple,
       CONSTRAINT fk__identity_relations__o__identities
                  FOREIGN key (o)
                  REFERENCES identities (identity) match simple
       -- amusingly when serializing this table back to RDF it will be ident:serialization hasPart: ident:constituent as owl:NamedIndividuals
);

CREATE TABLE qualifiers(
       -- qualifiers are source triple hashes with an ordering rule
       -- but those orderings are also 'qualified' per group
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       identity bytea NOT NULL,
       group_id integer NOT NULL,
       previous_qualifier_id integer,
       -- CONSTRAINT pk__qualifiers PRIMARY KEY (data_identity, group_id)
       CONSTRAINT fk__qualifiers_previous_qualifier_id
                  FOREIGN key (previous_qualifier_id)
                  REFERENCES qualifiers (id) match simple
);

-- TODO user explicitly included/excluded qualifiers (ie when they switch to closed world) needs to have datetime

CREATE TYPE transform_rule AS ENUM ('EquivClassIntersection', 'EquivClassUnion', 'RestrictionSome', 'RestrictionAll', 'List');

CREATE TABLE load_events(
       -- NOTE: this is also the user edit log...
       -- SELECT * FROM load_events AS e JOIN identity_relations AS rel JOIN identities AS i ON e.serialization_identity = rel.s AND rel.o = i.identity WHERE rel.p = 'hasPart';
       -- gives the reference_names for the parts of a serialization, usually we go the other way
       -- SELECT * FROM reference_names AS ref JOIN identity_relations AS rel JOIN load_events AS e ON ref.identity = rel.o AND rel.s = e.serialization_identity WHERE rel.p = 'hasPart' AND datetime < some_time;
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       serialization_identity bytea NOT NULL,
       -- identity bytea NOT NULL,  -- TODO trigger check on data and metadata
       group_id integer NOT NULL, -- from /<user>/path-to-reference-name
       user_id integer NOT NULL, -- from the api key mapping
       datetime timestamp DEFAULT CURRENT_TIMESTAMP,
       CONSTRAINT un__load_events__ident_group_id UNIQUE (serialization_identity, group_id), -- possibly redundent?
       CONSTRAINT fk__load_events__ident__identities
                  FOREIGN KEY (serialization_identity)
                  REFERENCES identities (identity)
);

CREATE FUNCTION load_event_to_qualifier() RETURNS trigger AS $$
       BEGIN
           INSERT INTO qualifiers (identity, group_id, previous_qualifier_id)
           SELECT i.identity, q.group_id, q.id
           FROM qualifiers as q, identity_relations as ir
           JOIN identities as i ON ir.o = i.identity
           WHERE q.group_id = NEW.group_id AND
                 i.type = 'data' AND
                 ir.p = 'hasPart' AND
                 ir.s = NEW.serialization_identity;
           RETURN NULL;
       END
$$ language plpgsql;

CREATE TRIGGER load_event_to_qualifier BEFORE INSERT ON load_events
       FOR EACH ROW EXECUTE PROCEDURE load_event_to_qualifier();

/*
CREATE TABLE load_processes(
       -- this is more for prov curiosity than real use right now
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       source_serialization_hash bytea NOT NULL,
       process_type source_process NOT NULL,
       source_iri uri,
       vcs_commit_ident text,
       datetime timestamp DEFAULT CURRENT_TIMESTAMP,
       group_id integer NOT NULL,
       user_id integer NOT NULL,
       CONSTRAINT fk__load_proc__source_ser__source_ser_hash__source_ser
                  FOREIGN key (source_serialization_hash)
                  REFERENCES source_serialization (source_serialization_hash) match simple
       -- TODO more forieng keys here
);
*/

CREATE TABLE qualifiers_current(
       identity bytea PRIMARY KEY,
       id integer NOT NULL,
       previous_ids integer[] NOT NULL,  -- no FK here, 'enforced' via population via trigger
       -- TODO CHECK qualifiers previous_qualifier_id = OLD.id aka previous_ids head? in trigger?
       CONSTRAINT fk__qualifiers__identity__identities
                  FOREIGN key (identity)
                  REFERENCES identities (identity) match simple,
       CONSTRAINT fk__qualifiers_current__id__qualifiers
                  FOREIGN key (id)
                  REFERENCES qualifiers (id) match simple
);

CREATE FUNCTION qualifiers_to_current() RETURNS trigger AS $$
       -- TODO align on types
       BEGIN
           IF NOT EXISTS (SELECT * FROM qualifiers_current AS qc WHERE qc.identity = NEW.identity) THEN
              -- FIXME actually retrieve previous_qualifier_id
              INSERT INTO qualifiers_current (identity, id, previous_ids) VALUES (NEW.identity, NEW.id, '{0}');
           ELSE
              UPDATE qualifiers_current AS qc SET qc.id = NEW.id WHERE qc.identity = NEW.identity;
           END IF;
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE FUNCTION qualifiers_current_array() RETURNS trigger AS $$
       BEGIN
           UPDATE qualifiers_current as qc
                  SET previous_ids = (NEW.identity || NEW.previous_ids)
                  WHERE qc.identity = NEW.identity;
           -- TODO does NEW work for this and restrict to row automatically?
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TRIGGER qualifiers_to_current AFTER INSERT OR UPDATE ON qualifiers
       FOR EACH ROW EXECUTE PROCEDURE qualifiers_to_current();
CREATE TRIGGER qualifiers_current_array AFTER INSERT ON qualifiers_current
       FOR EACH ROW EXECUTE PROCEDURE qualifiers_current_array();
CREATE TRIGGER qualifiers_current_array_id_only AFTER UPDATE ON qualifiers_current
       FOR EACH ROW WHEN (OLD.id IS DISTINCT FROM NEW.id) EXECUTE PROCEDURE qualifiers_current_array();

CREATE INDEX qualifiers_id_index ON qualifiers (id);

-- the root qualifier the root for all new source process qualifiers

/*  -- nooo? at least not for now?
CREATE FUNCTION create_source_qualifier() RETURNS trigger AS $$
       -- creates the root for all source process qualifiers, is equivalent to itself since there is no load id
       -- TODO create group interlex source process -> create source_process qualifier
       -- DECLARE
           -- prev_qual integer;
       BEGIN
           --IF NOT EXISTS (SELECT * FROM qualifiers AS q WHERE q.source_process_id = NEW.id)
           --THEN
                -- TODO figure out the proper group to derive previous from maybe latest? or is it curated?
                -- SELECT id INTO STRICT prev_qual FROM qualifiers_current as q WHERE q.group_id = 1 AND;
                -- load processes are where we will need to actually look up the previous qualifier id
           INSERT INTO qualifiers
                  (source_id,
                   group_id,
                   source_triples_hash,
                   equivalent_qualifier_id,
                   previous_qualifier_id)
           source_id, source_triples_hash, group_id, -- datetime
           previous_qualifier_id, equivalent_qualifier_id, load_process_id, source_serialization_hash
           VALUES (NEW.id, NEW.id, 0);
           --END IF;
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TRIGGER create_source_qualifier AFTER INSERT ON sources FOR EACH ROW EXECUTE PROCEDURE create_source_qualifier();
*/

CREATE FUNCTION create_load_process_qualifier() RETURNS trigger AS $$  -- TODO should be source_triples_hash if anything
       DECLARE
           prev_qual_id integer;
       BEGIN
           -- boy... this seems a lot slower than the array version
           SELECT id INTO STRICT prev_qual_id FROM qualifiers_current AS qc WHERE qc.source_process_id = NEW.source_process_id;
           INSERT INTO qualifiers (source_process_id, load_procedss_id, previous_qualifier_id)
                  VALUES (NEW.source_process_id, NEW.id, prev_qual_id);
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TABLE predicate_cardinality(
       p uri PRIMARY KEY,  -- only include predicates with actual limites
       cardinality integer NOT NULL
       -- rank integer NOT NULL DEFAULT -1 -- want or use the ranking in pyontutils??
);

CREATE TYPE rdf_type AS enum ('Class', 'Ontology', 'AnnotationProperty', 'ObjectProperty', 'DataPropery');  -- TODO

CREATE TABLE subject_types(
       s uri NOT NULL,
       o rdf_type NOT NULL,
       CONSTRAINT pk__types__s_o PRIMARY KEY (s, o)
);

CREATE TABLE triples(
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, -- preferred for 10+
       s uri,
       s_blank integer, -- internal bnode counter for isomorphism checks
       p uri NOT NULL,
       o uri,
       o_lit text,
       o_blank integer, -- this is internal for (s_blank p o_blank) and triples.id for (s, p, o_blank)
       datatype uri,
       language varchar(10), -- FIXME can we put these in the datatype column as just strings?
       subgraph_identity bytea,
       CHECK (uri_host(s) <> reference_host() OR
              uri_host(s) = reference_host() AND
              (uri_path_array(s))[2] !~* 'ilx_' OR
              uri_host(s) = reference_host() AND
              -- TODO we can't check that the id is actually in the database without a trigger
              -- TODO also prevent users from creating ilx_ fragments in /uris/
              -- only base may have ilx ids, all the rest are by construction from qualifiers
              -- FIXME un hardcode 'base' and 'ilx_'
              (uri_path_array(s))[1] = 'base' AND
              (uri_path_array(s))[2] ~* 'ilx_'),
       CHECK ((s IS NOT NULL AND s_blank IS NULL) OR
              (s IS NULL AND s_blank IS NOT NULL)),
       CHECK ((o IS NOT NULL AND o_lit IS NULL AND o_blank IS NULL) OR
              (o IS NULL AND o_lit IS NOT NULL AND o_blank IS NULL) OR
              (o IS NULL AND o_lit IS NULL AND o_blank IS NOT NULL)),
       CHECK (NOT (datatype IS NOT NULL AND language IS NOT NULL)),
       CHECK (s_blank IS NULL OR
              s_blank IS NOT NULL AND
              subgraph_identity IS NOT NULL),
       CHECK (o_blank IS NULL OR
              o_blank IS NOT NULL AND
              subgraph_identity IS NOT NULL),
       CHECK (o_blank <> s_blank)
       -- CONSTRAINT un__triples__s_p_o UNIQUE (s, p, o),
       -- CONSTRAINT un__triples__s_p_o_lit UNIQUE (s, p, o_lit, datatype, language),
       -- FIXME o_lib can be BIG, too big to
       -- CONSTRAINT un__triples__s_p_o_blank UNIQUE (s, p, o_blank, subgraph_identity)
       -- CONSTRAINT un__triples__s_blank_p_o_blank UNIQUE (s_blank, p, o_blank, subgraph_identity)
);
CREATE INDEX triples__s__index ON triples (s);

CREATE INDEX triples__subgraph_identity__index
       ON triples (subgraph_identity);

CREATE UNIQUE INDEX un__triples__s_p_o_uri_hash
       -- assume uri_hash is safe since it is based on
       -- access/hash.h hash_any directly from the postgres sources
       ON triples
       (uri_hash(s), uri_hash(p), uri_hash(o))
       WHERE s IS NOT NULL AND
             o IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_p_o_lit_md5
       ON triples (uri_hash(s), uri_hash(p), md5(o_lit))
       WHERE s IS NOT NULL AND
             o_lit IS NOT NULL AND
             datatype IS NULL AND
             language is NULL;

CREATE UNIQUE INDEX un__triples__s_p_o_lit_datatype_md5
       ON triples
       (uri_hash(s), uri_hash(p), md5(o_lit), uri_hash(datatype))
       WHERE s IS NOT NULL AND
             o_lit IS NOT NULL AND
             datatype IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_p_o_lit_lang_md5
       ON triples
       (uri_hash(s), uri_hash(p), md5(o_lit), md5(language))
       WHERE s IS NOT NULL AND
             o_lit IS NOT NULL AND
             language IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_lit_md5
       ON triples
       (s_blank, uri_hash(p), md5(o_lit))
       -- this should be a VERY rare condition
       WHERE s_blank IS NOT NULL AND
             o_lit IS NOT NULL AND
             datatype IS NULL AND
             language is NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_lit_datatype_md5
       ON triples
       (s_blank, uri_hash(p), md5(o_lit), uri_hash(datatype), subgraph_identity)
       -- this should be a VERY rare condition
       WHERE s_blank IS NOT NULL AND
             o_lit IS NOT NULL AND
             datatype IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_lit_lang_md5
       ON triples
       (s_blank, uri_hash(p), md5(o_lit), md5(language), subgraph_identity)
       -- this should be a VERY rare condition
       WHERE s_blank IS NOT NULL AND
             o_lit IS NOT NULL AND
             language IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_p_o_blank
       ON triples
       (uri_hash(s), uri_hash(p), o_blank, subgraph_identity)
       WHERE s IS NOT NULL AND
             o_blank IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_blank
       ON triples
       (s_blank, uri_hash(p), o_blank, subgraph_identity)
       WHERE s_blank IS NOT NULL AND
             o_blank IS NOT NULL;

CREATE INDEX search_index ON triples USING GIN (to_tsvector('english', o_lit)) WHERE o_lit IS NOT NULL;

-- ALTER TABLE triples DROP CONSTRAINT un__triples__s_p_o_lit;
-- CREATE UNIQUE INDEX un__triples_s_p_o_lit_md5 ON triples (s, p, md5(o_lit), datatype, language);
-- ALTER TABLE triples ADD CONSTRAINT un__triples_s_p_o_lit UNIQUE USING INDEX un__triples_s_p_o_lit_md5;
-- does not work, probably because md5(o_lit) but that is ok

-- note diff at load time from the previous qualifier for the source?
-- ON CONFLICT INSERT INTO temp table or something

/*
(9997 null 0 rdf:type           null null owl:Restriction null null ASDF87SDF7A6SD75A5)
(9998 null 0 owl:onProperty     null null BFO:0000050     null null ASDF87SDF7A6SD75A5)
(9999 null 0 owl:someValuesFrom null null UBERON:0000955  null null ASDF87SDF7A6SD75A5)

(?? null ?? owl:onProperty null null BFO:0000050 null null ASDF87SDF7A6SD75A5)
(?? null ?? owl:onProperty null null BFO:0000050 null null ASDF87SDF7A6SD75A5)
(?? null ?? owl:onProperty null null BFO:0000050 null null ASDF87SDF7A6SD75A5)
(?? null ?? owl:onProperty null null BFO:0000050 null null ASDF87SDF7A6SD75A5)
*/

-- what about (?? null ?? owl:onProperty null null BFO:0000050 null null ???)
-- we cannot reuse subgraph triples, we can reuse entire subgraphs starting from (s, p, o_blank)

CREATE TABLE qualifier_triples(
       triple_id integer NOT NULL,
       qualifier_id integer NOT NULL,
       CONSTRAINT pk__qualifier_triples PRIMARY KEY (triple_id, qualifier_id),
       CONSTRAINT fk__qualifier_triples__triple_id__triples
                  FOREIGN KEY (triple_id)
                  REFERENCES triples (id),
       CONSTRAINT fk__qualifier_triple__qualifier_id__qualifiers
                  FOREIGN key (qualifier_id)
                  REFERENCES qualifiers (id) match simple
);

/*
-- this implementation is also bad, we do not need the exclude table
-- because we can just create an exclude relationship between qualifiers
-- this keeps all sets of triples in the same table and semantically
-- equivalent, the only issue is resolving inclusion/exclusion when
-- a triple is added in both include and exclude and there is only a
-- temporal ordering on the include and exclude, no explicit sequence
-- relation, an includes relation where the object triple ids occur in
-- the subject triple ids + the object qualifier datetime > for subject
-- might be sufficient for modelling removal of triples between versions
-- removedFrom(A, B) :- includes(A, B), before(A, B), excludes(C, B), 
-- removedFrom(A,B) :- includes(A,B), before(A,B), excludes(C,B), nextVersionOf(C, A) .
CREATE TABLE include_triples(
       triple_id integer NOT NULL,
       qualifier_id integer NOT NULL,
       CONSTRAINT fk__include_triples__triple_id__triples
                  FOREIGN KEY (triple_id)
                  REFERENCES triples (id),
       CONSTRAINT fk__include_triple__qualifier_id__qualifiers
                  FOREIGN key (qualifier_id)
                  REFERENCES qualifiers (id) match simple

);

CREATE TABLE exclude_triples(
       -- A note on how to 'reset' a user or how to mass include
       -- When creating a new account, a user can choose by default
       -- to start with an empty world, that is to say that they start
       -- with a qualifier that includes only the null set qualifier (0)
       -- they could also choose the qualifier that always points to the
       -- latest as a starting point
       -- when a user decides to make a 'breaking' change to their
       -- environment then we simply have 2 relationships on the new
       -- qualifier 1. 
       triple_id integer NOT NULL,
       qualifier_id integer NOT NULL,
       CONSTRAINT fk__exclude_triples__triple_id__triples
                  FOREIGN KEY (triple_id)
                  REFERENCES triples (id),
       CONSTRAINT fk__exclude_triple__qualifier_id__qualifiers
                  FOREIGN key (qualifier_id)
                  REFERENCES qualifiers (id) match simple
);
*/

/*

-- old implementation

CREATE TABLE triple_qualifiers(
       triple_id integer NOT NULL,
       qualifier_id integer NOT NULL,
       CONSTRAINT fk__triple_qualifiers__triple_id__triples
                  FOREIGN KEY (triple_id)
                  REFERENCES triples (id),
       CONSTRAINT fk__triple_qualifiers__qualifier_id__qualifiers
                  FOREIGN key (qualifier_id)
                  REFERENCES qualifiers (id) match simple
);

CREATE TABLE deletions(
       triple_id integer NOT NULL,
       qualifier_id integer NOT NULL,  -- gone here
       previous_qualifier_id integer NOT NULL, -- present or unspecified here
       CHECK (qualifier_id > previous_qualifier_id),
       -- QUESTION: how to handle cases of open world where user never added triples themselves?
       -- zap at origin? have to zap based on the user's ranking at that point in time
       -- if you change the ranking then you can change the meaning of qualifiers
       -- ANSWER: we implicitly 'include' things in the triples table but it is also
       -- entirely valid for someone to explicitly _exclude_ triples from their world view (graph)
       -- by default even if they were never explicitly or implicitly included in the first place
       -- 'these are triples that could exist and I DO NOT WANT THEM thank you very much'

       -- one additional feature that could be implemented here is 'banning' triples
       -- permanently, saying 'never ask me to include this again' even if others do
       -- that could be computed in software or another table, or it could go here
       -- using one of the builting utility qualifiers... HRM would have to be negative ids
       -- essentially 'maximum delete qualifier'

       CONSTRAINT fk__deletions__triple_id__triples
                  FOREIGN KEY (triple_id)
                  REFERENCES triples (id),
       CONSTRAINT fk__triple_qualifiers__qualifier_id__qualifiers
                  FOREIGN key (qualifier_id)
                  REFERENCES qualifiers (id) match simple,
       CONSTRAINT fk__triple_qualifiers__previous_qualifier_id__qualifiers
                  FOREIGN key (previous_qualifier_id)
                  REFERENCES qualifiers (id) match simple
);
*/

CREATE TABLE annotations(
       triple_id integer NOT NULL,  -- ah, and now we see the problem with having 3 tables
       annotation_triple_id integer NOT NULL,
       CONSTRAINT fk__annotations__triple_id__triples
                  FOREIGN KEY (triple_id)
                  REFERENCES triples (id),
       CONSTRAINT fk__annotations__annotation_triple_id__triples
                  FOREIGN KEY (annotation_triple_id)
                  REFERENCES triples (id)
);
