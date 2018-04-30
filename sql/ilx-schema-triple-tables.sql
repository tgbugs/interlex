-- CONNECT TO interlex_test USER "interlex-admin";
-- see notes in new-schema.sql

CREATE sequence if NOT exists interlex_ids_seq;

CREATE TABLE interlex_ids(
       id char(7) PRIMARY key DEFAULT LPAD(NEXTVAL('interlex_ids_seq')::text, 7, '0')
);

CREATE TABLE existing_iris(
       -- note that this table does NOT enumerate any uri.interlex.org identifiers
       -- the default/curated user will be the fail over
       -- do we need exclude rules? latest + original user will always be inserted
       -- but do we really even need latest to be explicit here?
       ilx_id char(7) NOT NULL,
       iri uri NOT NULL CHECK (uri_host(iri) NOT LIKE '%interlex.org'),
       group_id integer NOT NULL,
       CONSTRAINT fk__existing_iris__ilx_id__interlex_ids
                  FOREIGN key (ilx_id)
                  REFERENCES interlex_ids (id) match simple,
       CONSTRAINT fk__existing_iris__group_id__group
                  FOREIGN key (group_id)
                  REFERENCES groups (id) match simple,
       CONSTRAINT pk__existing_iris PRIMARY KEY (iri, group_id)
);

CREATE TYPE source_process AS ENUM ('FileFromIRI',  -- transitive closure be implemented using these on each file
                                    'FileFromPOST', -- we do not allow untrackable uploads use /<user>/ontologies
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

-- NOTE 'names' referred to here are 'graph names' or 'triple set names'
/* -- EXPLAINIATION
   incompatible defs
   source = data + bound name + metadata
   source - data = metadata
   source - name = ??
   source - metadata = ??
   source = data
   source = metadata + data
   source = metadata + data + name

   THIS IS NOT CORRECT
   name and metadata are NOT subsets of data in more precise nomenclature
   The system developed here is based on invariance under an identity function
   to changes in defined/distinct subsets of data.

   Ident(name1) -> 0
   Ident(name2) -> 0
   =>
   name1 = name2
   
   Ident(data1) -> 1
   Ident(data2) -> 1
   =>
   data1 = data2

   =>
   data1 != name1
   
   Ident(data3) -> 0
   =>
   data3 = name1
   
   In this implementation the identity function is a hash function, currently SHA256.
   Names are any subset of data that are unique for a given identity function.
   In this context case sensitive string matching or bytestring equality also work.
   
   Invariants are then considered only over 2 levels, data and its complement.
   We call the invariant data a name and the part that can vary data.
   
   Names are always invariant to changes in data because by definition they are the thing that does not change.
   The function Data is completely unconstrained when applied to a name.
   Data(data1) -> data2
   data1 = data2
   data1 != data2

   Thus it is no surprise that
   Data(name1) -> data1
   Data(name2) -> data2
   data1 != data2
   happens routinely

   Pointing of names to data means that the identity of the data is invariant to changes in the name.
   Name(data) -> name1
   Name(data) -> name2
   =/> name1 = name2
   
   Name(data) -> name1
   Name(data) -> name2
   Name(data) -> name3
   name1 != name2 != name3

   Binding of names to data means that the name is embedded in the data
   so that the data is no longer invariant to changes in the name.

   BoundName(data) -> name1
   BoundName(data) -> name2
   name1 != name2
   =>
   data1 != data2
   
   BoundName(data1) -> name1
   BoundName(data2) -> name2
   name1 != name2

   Means that I can implement

   Data(name) -> data
   BoundName(data) = name
   Data(name2) -> data
   BoundName(data) != name2

   and solves the Name(data) issue


   However there is one additional criteria that is required.
   There must be a function that can distinguish between changes in
   the identity of the data where the name has not change and
   changes in the identity of the data where the name has changed.
   
   data1 != data2
   NameChanged(data1, data2) -> True
   =>
   BoundName(data1) != BoundName(data2)

   data1 != data2
   NameChanged(data1, data2) -> False
   =>
   BoundName(data1) = BoundName(data2)

   The NameChanged function actually gives us something more powerful.
   It gives us bound metadata* (hencforth referred to just as metadata).
   A bound name can be considered to be the minimal subset of the data
   that has a useful identity function. This could be as complex as
   urls that resolve differently or a simple as the first byte of a file.
   The number of things that can be named using the first byte of a file
   is quite small, so we usually pick identity functions that are a bit
   larger.
   
   data1 != data2
   BoundData(data1) = data3
   BoundData(data2) = data4
   data3 = data4
   data3 != data4

   SubsetChanged(data1, data2) -> True
   SubsetChanged(data1, data2) -> False

   The generalized SubsetChanged function implies that
   there is some subset of the data that we can treat as
   distinct from the data and that subset can have as many
   subsets as our identity function can support.
   
   The trick is to use a common subset as a name.
   We usually break this out into name, metadata, and data.
   Where the name is a subset of both, and the metadata is
   a subset of the data. We are then left with the 'real'
   data that can change identity independent of the name
   and the metadata without loosing its identity.

   A bound name is the minimal subset of the data that satisfies the
   desired Ident function and NameWithCorrectness(name) -> data

   * Unbound metadata is not really a useful idea because technically
   any other data bound to a name could be considered as metadata and
   thus open to interpretation and convention.
     
   # backwards definitions
   IdentName(name) -> 1
   IdentName(name) -> 2
   1 != 2
   =>
   {name | IdentName(name) -> 1} != {name | IdentName(name) -> 2}
   shorthand name1 name2

   DataIdent(data) -> 1
   DataIdent(data) -> 2
   1 != 2
   => 
   {data | IdentData(data) -> 1} != {data | IdentData(data) -> 2}
   shorthand data1 data2
   
   IdentName does not have to be the same as IdentData, though they can be
   
   BoundName(data) => name
   
   Note: data and name can have the same type if 

   NameChanged({data | IdentData(data) -> 1}, {data | IdentData(data) -> 2}) -> True
   =>
   BoundName({data | IdentData(data) -> 1}) != BoundName({data | IdentData(data) -> 2})
   => 
   name

   NameChanged({data | IdentData(data) -> 1}, {data | IdentData(data) -> 2}) -> False
   

*/
CREATE TABLE names(
       -- any uri that has ever pointed to a bound name, the set of these is quite large
       -- even those that no longer resolve but are bound names
       -- NOTE that security/validity/trust is not managed at this level
       -- it is managed at the level of qualifiers, anyone can claim to be uberon
       -- the validity of the claim is orthogonal to the claim itself, these tables deal with the claims
       -- the best way to identify invalid claims is the enumerate them an mark them as such
       -- NOTE this table can be extended to track the current state of the resolution of a name
       name uri PRIMARY KEY,
       bound_name uri NOT NULL
);

CREATE TABLE bound_names(
       name uri PRIMARY KEY,
       -- names explicitly occuring in conjuction with a set of triples
);

CREATE TABLE reference_names(
       -- the set of interlex uris that we use internally to track all bound names
       -- one or the other of these names SHALL be the bound name
       -- note that I'm implementing this with uris, but really it could be anything
       name uri PRIMARY KEY CHECK (uri_host(name) = reference_host()),  -- change this to match your system
       bound_name uri UNIQUE,  -- default name, but can be updated to a single external external name
       CHECK (uri_host(bound_name) = reference_host() AND bound_name = name OR uri_host(bound_name) <> reference_host()),
       group_id integer NOT NULL -- TODO where names are actually uris check that the group name matches
);

CREATE FUNCTION user_reference_name() RETURNS trigger AS $$
       BEGIN
           INSERT INTO reference_names (name, group_id) VALUES
                  -- this tracks the source that is the user's interlex
                  -- contributions that have no additional artifact
                  -- uploads are tied to bound name of the file
                  -- and can be tracked and computed separately
                  ('https://' || reference_host() || (SELECT groupname FROM groups WHERE id = NEW.id) || '/contributions'),
                  NEW.id)
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TRIGGER user_reference_name AFTER INSERT ON users FOR EACH ROW EXECUTE PROCEDURE user_reference_name();

CREATE TABLE metadata_identities(
       -- hashes of owl:Ontology sections aka metadata identity naming doesn't quite make sense atm
       identity bytea PRIMARY KEY,
       -- the minimal value here is the name or the hash of the name + a type to distinguish it from
       -- the data
       -- minimal metadata in this case is thus identical the bound_name + type
       bound_name uri NOT NULL
);

/*
CREATE TABLE sources(
       -- aka files NOT ontologies
       -- sources do not tell you whether they are loading to or from, they are independent of that
       -- they are the unresolved graph subset
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       owner_group_id integer NOT NULL,
       interlex_source_path text NOT NULL, -- this is user + ontpath
       external_source_iri uri UNIQUE, -- this is what should appear internally in source_metadata
       -- CONSTRAINT pk__sources PRIMARY KEY (owner_group_id, interlex_source_path),
       CONSTRAINT un__sources UNIQUE (owner_group_id, interlex_source_path),
       CONSTRAINT fk__sources__owner_group_id__groups
                  FOREIGN key (owner_group_id)
                  REFERENCES groups (id) match simple
);

-- TODO renaming?

CREATE FUNCTION create_user_source() RETURNS trigger AS $$
       BEGIN
           INSERT INTO sources (owner_group_id, interlex_source_path) VALUES
                  (NEW.id, '/interlex.ttl'); -- NOTE this is /<user>/interlex.ttl neet to be clear that this is not an ont path
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TRIGGER create_user_source AFTER INSERT ON users FOR EACH ROW EXECUTE PROCEDURE create_user_source();

CREATE TABLE source_metadata(
       source_id integer NOT NULL,
       metadata_triples_hash bytea NOT NULL,
       -- and suddenly self describing document structure makes sense
);
*/

-- graph_subsets, graphs, subgraphs... HRM content_sets, ie the actual ontology content
/*
CREATE TABLE source_triples(
       -- BIG NOTE: triples included for hash computation should be split into into
       -- those attached to an owl:Ontology typed subject and everything else
       -- because the owl:Ontology section 'names' the rest of the graph but
       -- the hash of the content should be invariant to changes in the name
       -- they are literally the same
       -- if there is not an owl:Ontology typed subject then the containing source
       -- certain other rdf:type predicates may also fall into the metadata naming section
       -- if changes to them do not affect the view...

       source_triples_hash bytea PRIMARY KEY,
       triples_count integer NOT NULL,
       source_id integer NOT NULL,
       CONSTRAINT fk__source_triples__source_id__sources
                  FOREIGN key (source_id)
                  REFERENCES sources (id) match simple
);
*/

CREATE TABLE data_identities(
       identity bytea PRIMARY KEY,
       triples_count integer NOT NULL CHECK (triples_count > 0),
       source_id integer NOT NULL,
       CONSTRAINT fk__source_triples__source_id__sources
                  FOREIGN key (source_id)
                  REFERENCES sources (id) match simple
);

CREATE TABLE bound_name_()

CREATE TABLE qualifiers(
             -- qualifiers are source triple hashes with an ordering rule
             -- but those orderings are also 'qualified' per group
             -- with the note that source triples hashes can only have 
             id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
             source_triples_hash,
             previous_qualifier_id integer
             -- CONSTRAINT pk__qualifiers PRIMARY KEY (source_triples_hash, group_id)
)

CREATE TABLE source_serialization(
       -- prov
       source_serialization_hash bytea PRIMARY KEY,
       source_triples_hash bytea NOT NULL,
       CONSTRAINT fk__source_ser__source_triples_hash__source_triples
                  FOREIGN key (source_triples_hash)
                  REFERENCES source_triples (source_triples_hash) match simple
       -- group_id integer NOT NULL,
);

CREATE TYPE transform_rule AS enum ('EquivClassIntersection', 'EquivClassUnion', 'RestrictionSome', 'RestrictionAll', 'List');

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

CREATE TABLE old_qualifiers(
       -- ordering of source_triples_hash for a given source id in time by group
       -- there are some use cases where dissociation from temporal order may be useful
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       source_id integer NOT NULL,  -- can get this from the load_process_id, but may be tricky to validate previous_q_id...
       load_process_id integer CHECK (load_process_id IS NOT NULL OR (load_process_id IS NULL AND equivalent_qualifier_id IS NOT NULL)),

       group_id integer NOT NULL, -- redundant
       datetime timestamp DEFAULT CURRENT_TIMESTAMP, -- this also here for speed to avoid dealing with joins? or we leave date out of lopr?
       source_serialization_hash bytea NOT NULL,
       source_triples_hash bytea, -- NOT NULL,
       previous_qualifier_id integer NOT NULL CHECK (previous_qualifier_id <= id),  -- do we even need this anymore? no?
       equivalent_qualifier_id integer,  -- useful for exact duplicate loads by different users and quick rollbacks

       -- basically load process id + time, load processes are not sequential, but are treated as time invariant
       -- this allows us to do REALLY fast rollbacks by simply adding an equivalent qulaifier id to the old version
       -- and then setting previous qualifier as usual
       -- source_triples_hash could go in for completeness
       -- useful for just completely ignoring a set of changes and starting back from the past in terms of content
       -- TODO need a check on previous qualifier_id to make sure its source_process_id matches
       -- but that is a super advanced feature

       CONSTRAINT fk__qualifiers__source_id__source_processes
                  FOREIGN key (source_id)
                  REFERENCES sources (id) match simple,
       CONSTRAINT fk__qualifiers__source_serialization_hash__source_serialization
                  FOREIGN key (source_serialization_hash)
                  REFERENCES source_serialization (source_serialization_hash) match simple,
       CONSTRAINT fk__qualifiers__load_process_id__load_processes
                  FOREIGN key (load_process_id)
                  REFERENCES load_processes (id) match simple,
       -- CONSTRAINT fk__qualifiers__source_qualifier__qualifiers
                  -- FOREIGN key (source_qualifier_id)
                  -- REFERENCES qualifiers (id) match simple,
       CONSTRAINT fk__qualifiers__previous_qualifier__qualifiers
                  FOREIGN key (previous_qualifier_id)
                  REFERENCES qualifiers (id) match simple
);

CREATE TABLE qualifiers_current(
       source_id integer PRIMARY KEY,
       id integer NOT NULL,
       previous_ids integer[] NOT NULL,  -- no FK here, 'enforced' via population via trigger
       -- TODO CHECK qualifiers previous_qualifier_id = OLD.id aka previous_ids head? in trigger?
       CONSTRAINT fk__qualifiers__source_id__source_processes
                  FOREIGN key (source_id)
                  REFERENCES sources (id) match simple,
       CONSTRAINT fk__qualifiers_current__id__qualifiers
                  FOREIGN key (id)
                  REFERENCES qualifiers (id) match simple
);

CREATE FUNCTION qualifiers_to_current() RETURNS trigger AS $$
       BEGIN
           IF NOT EXISTS (SELECT * FROM qualifiers_current AS qc WHERE qc.source_id = NEW.source_id) THEN
              -- FIXME actually retrieve previous_qualifier_id
              INSERT INTO qualifiers_current (source_id, id, previous_ids) VALUES (NEW.source_id, NEW.id, '{0}');
           ELSE
              UPDATE qualifiers_current AS qc SET qc.id = NEW.id WHERE qc.source_id = NEW.source_id;
           END IF;
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE FUNCTION qualifiers_current_array() RETURNS trigger AS $$
       BEGIN
           UPDATE qualifiers_current as qc
                  SET previous_ids = (NEW.source_id || NEW.previous_ids)
                  WHERE qc.source_id = NEW.source_id;
           -- TODO does NEW work for this and restrict to row automatically?
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TRIGGER qualifiers_to_current AFTER INSERT OR UPDATE ON qualifiers FOR EACH ROW EXECUTE PROCEDURE qualifiers_to_current();
CREATE TRIGGER qualifiers_current_array AFTER INSERT ON qualifiers_current
       FOR EACH ROW EXECUTE PROCEDURE qualifiers_current_array();
CREATE TRIGGER qualifiers_current_array_id_only AFTER UPDATE ON qualifiers_current
       FOR EACH ROW WHEN (OLD.id IS DISTINCT FROM NEW.id) EXECUTE PROCEDURE qualifiers_current_array();

CREATE INDEX qualifiers_id_index ON qualifiers (id);

-- the root qualifier the root for all new source process qualifiers

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
       datatype uri CHECK (o_lit IS NULL OR o_lit IS NOT NULL AND datatype IS NOT NULL),
       language varchar(10),
       subgraph_hash bytea CHECK (s_blank IS NULL OR s_blank IS NOT NULL AND subgraph_hash IS NOT NULL),
       CHECK ((s IS NOT NULL AND s_blank IS NULL) OR
              (s IS NULL AND s_blank IS NOT NULL)),
       CHECK ((o IS NOT NULL AND o_lit IS NULL AND o_blank IS NULL) OR
              (o IS NULL AND o_lit IS NOT NULL AND o_blank IS NULL) OR
              (o IS NULL AND o_lit IS NULL AND o_blank IS NOT NULL)),
       CHECK (o_blank <> s_blank),
       CONSTRAINT un__triples__s_p_o UNIQUE (s, p, o),
       CONSTRAINT un__triples__s_p_o_lit UNIQUE (s, p, o_lit, datatype, language),
       CONSTRAINT un__triples__s_p_o_blank UNIQUE (s, p, o_blank)
);

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
