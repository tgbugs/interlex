-- CONNECT TO interlex_test USER "interlex-admin";

CREATE TABLE fragment_prefix_sequences(
       prefix text PRIMARY KEY NOT NULL,
       suffix_max integer NOT NULL,
       current_pad integer NOT NULL DEFAULT 7, -- XXX NOTE when we overflow the current pad there is no point increasing the pad ...
       CHECK ((prefix ~* '^\S+') AND (prefix ~* '\S+$'))
);

-- FIXME TODO REMINDER rate limit on creating new terms to avoid abuse by regular users
CREATE OR REPLACE FUNCTION incrementPrefixSequence(prefix_in text, OUT suffix_id integer) RETURNS integer AS $incrementPrefixSequence$
BEGIN
    UPDATE fragment_prefix_sequences
    SET suffix_max = 1 + (SELECT suffix_max
                          FROM fragment_prefix_sequences
                          WHERE prefix = prefix_in)
    WHERE prefix = prefix_in;
    SELECT suffix_max INTO suffix_id FROM fragment_prefix_sequences WHERE prefix = prefix_in;
END;
$incrementPrefixSequence$ language plpgsql;

-- TODO implement this so that there will be no gaps
-- FIXME fragment prefixes make these non-unique, and they need additional sequences
CREATE TABLE interlex_ids(
       -- these when used in http://uri.interlex.org/base/ilx_{id} are the reference ids for terms
       -- they can however be mapped to more than one since they cannot (usually) be bound
       prefix text NOT NULL, -- the fragment prefix
       id text NOT NULL, -- the fragment suffix must be padded BEFORE being inserted into this table
       original_label text NOT NULL, -- require at least the original label in this table for accounting in case the later part of an exchange fails for some reason we can partially recover XXX ideally this is what we would require to be unique, but labels can change?
       -- consider instead triple label id maybe, but then we would have to allow it to be null
       CONSTRAINT pk__interlex_ids PRIMARY KEY (prefix, id),
       -- XXX if it looks like we are going to overflow the limit the padding rule will have to be changed changed, just bump it
       -- the check constraint here does not reference the current_pad because that can grow, in which case the check here should be updated
       CHECK ((original_label ~* '^\S+') AND (original_label ~* '\S+$')),
       CHECK ((prefix = 'tmp' AND id ~ '[0-9]{9}') OR
              (prefix = 'ilx' AND id ~ '[0-9]{7}') OR
              (prefix = 'cde' AND id ~ '[0-9]{7}') OR
              (prefix = 'fde' AND id ~ '[0-9]{7}') OR
              (prefix = 'pde' AND id ~ '[0-9]{8}'))
);

CREATE OR REPLACE FUNCTION newIdForPrefix(prefix_in text, original_label_in text) RETURNS text AS $newIdForPrefix$
/* NEVER CALL THIS FUNCTION BY ITSELF! ALWAYS USE WITH newEntity to ensure constraints are satisfied */
DECLARE
new_id text;
BEGIN
    new_id := LPAD(cast(incrementPrefixSequence(prefix_in) AS text),
                   (SELECT current_pad FROM fragment_prefix_sequences WHERE prefix = prefix_in),
                   '0');
    INSERT INTO interlex_ids (prefix, id, original_label) -- FIXME need to format with the leading zeros and plan for overflow
    VALUES (prefix_in, new_id, original_label_in);
    RETURN new_id;
END;
$newIdForPrefix$ language plpgsql;

CREATE TYPE label_type AS ENUM ('label', 'exact');
CREATE TABLE current_interlex_labels_and_exacts(
/*
used to enforce unique label and exact synonym mappings for all ilx terms
TODO figure out whether we can relax this to be across perspectives ...
this constraint is particularly tricky because ideally we want to enforce it
uniformly for all users, but there are legitimate use cases where we might need
to allow divergence
*/
       prefix text NOT NULL,
       id text NOT NULL,
       FOREIGN KEY (prefix, id) references interlex_ids (prefix, id),
       p label_type NOT NULL,
       o_lit text PRIMARY KEY,
       CHECK ((o_lit ~* '^\S+') AND (o_lit ~* '\S+$'))
       -- XXX NOTE we do not deal with datatype and lang here because
       -- inside interlex label for ilx terms should be unique, always english (sciengtish?), and without specified data type
);

CREATE OR REPLACE FUNCTION newEntity(rdf_type uri, frag_pref text, label text, exacts text[]) RETURNS uri AS $$
DECLARE
id_suffix text;
subject uri;
BEGIN
id_suffix := newIdForPrefix(frag_pref, label); -- FIXME wrong type
INSERT INTO current_interlex_labels_and_exacts (prefix, id, p, o_lit) VALUES (frag_pref, id_suffix, 'label', label);
INSERT INTO current_interlex_labels_and_exacts (prefix, id, p, o_lit) SELECT frag_pref, id_suffix, 'exact', exact FROM unnest(exacts) AS exact;
subject := 'http://' || reference_host() || '/base/' || frag_pref || '_' || id_suffix;
INSERT INTO triples (triple_identity, s, p, o) VALUES
       (tripleIdentity(subject, 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type', rdf_type, null, null, null),
        subject, 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type', rdf_type);
INSERT INTO triples (triple_identity, s, p, o_lit) VALUES
       (tripleIdentity(subject, 'http://www.w3.org/2000/01/rdf-schema#label', null, label, null, null),
        subject, 'http://www.w3.org/2000/01/rdf-schema#label', label);
INSERT INTO triples (triple_identity, s, p, o_lit)
       SELECT tripleIdentity(subject, 'http://uri.interlex.org/tgbugs/uris/readable/hasExactSynonym', null, exact, null, null),
              subject, 'http://uri.interlex.org/tgbugs/uris/readable/hasExactSynonym', exact FROM unnest(exacts) AS exact; -- FIXME FIXME determine predicate
RETURN subject;
END;
$$ language plpgsql;

/*
-- TODO figure out how this worked and use it to get prefix + and id
CREATE OR REPLACE FUNCTION ilxIdFromIri(iri uri, OUT (ilx_prefix char(32), ilx_id char(32))) RETURNS (char(32), char(32)) AS $ilxIdFromIri$
       BEGIN
           -- SELECT substring((uri_path_array(iri))[array_upper(uri_path_array(iri), 1)], 5)::char(8) INTO ilx_id;
           -- SELECT substring((uri_path_array(iri))[array_upper(uri_path_array(iri), 1)], 5)::char(8) INTO (ilx_id);
       END;
$ilxIdFromIri$ language plpgsql;
*/

CREATE TABLE existing_iris(
       -- TODO i think the way that we handle history for this
       -- is that this table can point to a triple identity
       -- and the triple is then tracked as part of the history
       -- for that ilx term added/removed etc. and this table
       -- is used to ensure that the current global state is always
       -- consistent, if you want to see the history for any individual
       -- term then it rides along on that term for that perspective
       -- just like any other, i think that is the answer
       -- i also think it means that iri and perspective_id are what must be unique

       -- note that this table does NOT enumerate any uri.interlex.org identifiers
       -- the default/curated user will be the fail over
       -- do we need exclude rules? latest + original user will always be inserted
       -- but do we really even need latest to be explicit here?
       ilx_prefix text NOT NULL,
       ilx_id text NOT NULL,
       iri uri UNIQUE NOT NULL CHECK (uri_host(iri) NOT LIKE '%interlex.org'),
       perspective integer NOT NULL references perspectives (id),  -- FIXME should probably be perspective instead
       FOREIGN KEY (ilx_prefix, ilx_id) REFERENCES interlex_ids (prefix, id),
       PRIMARY KEY (iri, perspective)
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
       -- any uri that has ever pointed to an identity +bound name+, the set of these is quite large
       -- even those that no longer resolve but are bound names
       -- NOTE that security/validity/trust is not managed at this level
       -- it is managed at the level of qualifiers, anyone can claim to be uberon
       -- the validity of the claim is orthogonal to the claim itself, these tables deal with the claims
       -- the best way to identify invalid claims is the enumerate them an mark them as such
       -- NOTE this table can be extended to track the current state of the resolution of a name

       name uri PRIMARY KEY, -- CHECK (uri_host(name) != reference_host()),
       -- should not be a reference name? yes, TODO make sure that {group}/ontologies/ etc. do not wind up in here
       -- XXX UPDATE on whether to allow reference host ontologies to be in here
       -- because of the role this table plays with ANY incoming ontology we need
       -- those names to be present in this table because there will be identities
       -- that need to be linked to a name, and the complexity of trying to pull
       -- stuff from the ontologies table is simply not worth it, so we have an
       -- index on uri_host(name) now and can always check against ontologies and specs
       first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX names_uri_host_index ON names (uri_host(name));


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
       expected_bound_name uri UNIQUE,  -- default name, but can be updated to a single external name
       -- FIXME what happens in cases where an external source looses control of a uri and has to change the bound name?
       -- I think we can use ordering on bound name identities to resolve the issue without too much trouble
       CHECK (uri_host(expected_bound_name) = reference_host()
              AND
              expected_bound_name = name
              OR
              uri_host(expected_bound_name) <> reference_host()),
       perspective integer NOT NULL references perspectives (id) -- TODO where names are actually uris check that the group name matches
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
           INSERT INTO reference_names (name, perspective)
                  -- this tracks the source that is the user's interlex
                  -- contributions that have no additional artifact
                  -- uploads are tied to bound name of the file
                  -- and can be tracked and computed separately
                  -- FIXME vs /{group}/ontologies/contributions which would be more consistent
                  SELECT 'http://' || reference_host() || '/' || g.groupname || '/contributions', p.id
                  FROM groups AS g
                  JOIN perspectives AS p ON p.group_id = g.id AND p.default_group_perspective
                  WHERE g.id = NEW.id;
           RETURN NULL;
       END;
$$ language plpgsql;

CREATE TRIGGER user_reference_name AFTER INSERT
       ON users FOR EACH ROW EXECUTE PROCEDURE user_reference_name();

-- graph_subsets, graphs, subgraphs... HRM content_sets, ie the actual ontology content

-- note to self: qualified and unqualified imports, all named based imports without identity are unqualified
-- we distinguish here because names 'point' to more than one type of thing that we want to be able to track the history of
CREATE TYPE named_type AS ENUM ('empty',
                                'serialization',
                                --'local_naming_conventions',  -- aka curies
                                -- bound to bound_name incidentally so they are ranked higher
                                -- FIXME hashing bound names for this is stupid ? or is it if you have very long names
                                --'bound_name',  -- just use the string itself? might be more space efficient to hash? we will want to be able to
                                         --   create name equivalences e.g. for mapping user iris to interlex iris?
                                         --   but probably not using the qualifier system... probably...
                                         --   nope, needed to track external renamings ?? we will find a use
                                         --   nope again, names don't have reference names, that would be redundant
                                         --   triple nope, names as defined in the names table sure do map to reference_names... but they might map to more than one, so quad nope
                                         --   quint nope says bound_name is in 1:1 with reference_name and need to be able to reconstruct the actual name
                                -- 'source',  -- (name, metadata_identity, data_identity) but could be any subset of those, and we can reconstruct using the load data

                                'data',  -- triples s p o type + lang
                                'subgraph', -- FIXME how is this any different from data? unnamed subgraphs
                                'qualifier',
                                'load',
                                'subject_graph',

                                -- new clearer names with better semantics
                                'graph_combined_local_conventions', -- (oid local_conventions graph_combined) subClassOf ??? TODO naming
                                'local_conventions', -- (sid ((prefix namespace) ...))
                                --'graph', -- ill specified
                                'graph_combined', -- (oid named_embedded_seq bnode_embedded_seq)
                                'bnode_embedded', -- this is specifically for bnode records for conn triples of the form (s ((p id) ...)) where id is a bnode_condensed identity it is the nei mentioned for bnode_conn_free_seq
                                'bnode_conn_free_seq', -- this uses the named embedded identity for connected subjects and condensed identity for free subgraphs, this means that bnode_conn_free_seq cannot be calculated directly from just the bnode_condensed identities
                                'bnode_condensed_seq', -- (sid ((us ((up uo) ...)) ...)) aka (sid (bnode-record ...)) subClassOf bnode_graph
                                'bnode_condensed', -- (us ((us uo) ...)) subClassOf bnode_record, but does not include any named subject id, be == bc
                                'named_embedded_seq', -- (sid ((ns ((np no) ...)) ...)) aka (sid (named-record ...)) subClassOf named_graph
                                'named_embedded', -- (ns ((np no) ...)) subClassOf named_record
                                'named_condensed', -- ((np no) ...) for consistency

                                -- these are for cases where the graph is not split into named/bnode
                                -- but where the named record and bnode record are paired and then
                                -- identified, we don't use it for a full graph right now but we
                                -- do use it for metadata
                                'graph',
                                'condensed_seq',
                                'condensed',
                                'embedded_seq',
                                'embedded',

                                'metadata_graph',
                                'metadata_graph_combined',
                                'truncated_metadata_graph', -- multi-parent shared subgraph case
                                'truncated_metadata_graph_combined'

                                -- singletion identified by hash on triple set  these are not named, that is the whole point, so they don't need to be here
                                -- 'name-metadata' -- (name, metadata_identity)
                                -- 'name-data' -- (name, data_identity)
                                -- 'source',  -- can be computed if we need it
                                );

/*
the full structure of the data is as follows

file/ontology/stream
    subgraph 1
    subgraph ...
    subgraph n
       s po 1 -> spo1
         po 2 -> spo2
         po 3 -> spo3

subgraphs and triples are hashed separately, triple ids
are not used directly to determine the parent structure
this is because we want identity to be homogenous so that
it can be applied recursively without the need to rederive
from the source data, however we do still need to know the
identity of the triples so that we can simplify inserts
without having to go to the database twice to get the
internal integer id for a triple or subgraph

choosing to map from subgraphs to triples does lead to
redundancy for small sparse changes however, which would
require us to shift frames to work over subgraphs rather
than ontologies ... this might ultimately be worth it ???

the total number of top level subgraphs in an ontology is
usually well below a million, though things like uniprot
or the protein ontology or the allele database do go far
beyond that

for the basic interlex use case the predominate use case
is individual terms and small groups of related terms

having to maintain a frame for every term also causes issues
because it means that changes involving multiple terms
have to write a frame per term ... instead of having the
change operate on the set as a whole ... but i think it
is easier to have all the subgraph frames share the same
timestamp and bundle them that way ...

TODO we really need to implement both approaches and
see what the tradeoffs are in terms of performance
*/
CREATE TABLE identities(
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       -- FIXME we will likely want an integer primary key if we start doing heavy joins over this table
       identity bytea UNIQUE, -- PRIMARY KEY,
       --version integer NOT NULL, -- TODO this needs to be tracked, it doesn't go in the primary key but is important if validating migrations i think? maybe it does go in the primary key? hrm
       -- XXX NOTE record_count is not record as in (s ((p o) ...)) it is record as in
       -- whatever we are counting for this type of thing, usually triples or triples + local conventions
       -- counting (s ((p o) ...)) records is significantly more difficult and is not needed for sanity checks
       record_count integer NOT NULL, -- ok to be zero for bound_name
       reference_name uri,  -- TODO ... maybe we could use this for reference names or subjects ? since we aren't actually using it for anything at the moment we lose foreign key but since we have named_type ...
       type named_type NOT NULL,
       first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL, -- XXX I think this is the best way to ensure that we can always have some basis for versioning even if everything else fails, we can have another table with extra info for versioning, but this should also vastly simplify versioning for records as well when we go to join/merge into a particular perspective
       /* -- uh ... this check was doing nothing ???
       CHECK (reference_name IS     NULL AND type = 'subgraph' OR
              reference_name IS NOT NULL AND type = 'subgraph' OR
              type <> 'subgraph'),
       */
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
CREATE INDEX identities_first_seen_index ON identities (first_seen);

/*
name_to_identity is a many to many table, it is not a prov table
its purpose is to make it possible to get from any name that we
have seen to the set of identities that it has been observed to
resolve to, or is bound to
*/
CREATE TYPE name_type AS ENUM ('bound', 'bound_version', 'pointer');
CREATE TABLE name_to_identity(
       -- as opposed to hashing names
       name uri,
       identity bytea,  -- usually should point to a serialization
       type name_type, -- FIXME will need a way to verify that bound and bound_version are true
       CONSTRAINT pk__name_to_identity PRIMARY KEY (name, identity, type),
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


CREATE TYPE identity_relation AS ENUM (
       'hasPart',
       'dereferencedTo',
       'parsedTo', -- serialization -> graph_and_local_conventions

       'hasEquivalent', -- use to assert that two different ids produced via different methods identify the same underlying source

       'hasMetadataGraph', -- ser -> meta (aka 'hasMetadata', but better to match conventions)
       'hasMetadataRecord', -- metadata_graph -> metadata_record

       'hasCondensed', -- embedded -> condensed (currently used for metadata to e.g. id unchanged metadata)

       'hasLocalConventions', -- graph_and_local_conventions -> local_conventions
       'hasGraph', -- graph_and_local_conventions -> graph
       'hasRecord', -- graph -> record (untyped)
       'hasBnodeGraph', -- graph -> bnode_graph
       'hasBnodeRecord', -- bnode_graph -> bnode_record
       'hasNamedGraph', -- graph -> named_graph XXX note that this is NOT the RDF named graph
       'hasNamedRecord' -- named_graph -> named_record
); -- , 'named', 'pointedTo', 'resolvedTo');
-- dereferencedTo history can be reconstructed for names -> serialization without a bound name

CREATE TYPE qualifier_relations AS ENUM('includes',
                                        'excludes',
                                        'hasPrev', -- hasNext? there are multiple possible nexts
                                        'break');

CREATE TYPE qualifier_types AS ENUM('group',
                                    'reference_name',  -- aka source qualifier
                                    -- 'ilx_id',  -- NO, left as reminder that this is NOT how to architect this
                                    -- users aren't really 'editing' the whole of the graph, they are
                                    -- just saying, I want this triple and not these other triples
                                    -- if _THEY_ 'merge' a triple back in later then the prior
                                    -- exclude will be ignored, just like lines in files
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

CREATE UNIQUE INDEX un__identity_relations__n1p_s_p
       -- FIXME one issue with this is that such inserts may fail silently if OCDN is set
       -- TODO this should really be (s, p, o, version) so we can migrate identity function versions, for now it detects if i do something stupid
       ON identity_relations
       (s, p)
       -- where not in multi-arity, in all other cases the value of the subject depends
       -- on the object and thus should always be unique, this is not strictly true for
       -- serialization parsesTo graph_and_local_conventions, however it indicates that
       -- the identity function has changed (thus the need for the version field)
       WHERE p NOT IN ('hasPart', 'dereferencedTo', 'hasBnodeRecord', 'hasNamedRecord');

CREATE INDEX identity_relations_s_index ON identity_relations (s);
CREATE INDEX identity_relations_o_index ON identity_relations (o);
-- TODO we are renaming qualifiers to frames to clarify the process

/*
writing out the git analogy
each ontology is a file
each change to any term in that ontology is a commit
each perspective is a branch that rebases (but retains the history) onto the head of its parent branch
the auto-rebasing behavior can be disabled
each perspective (branch) applies to all ontologies (files) XXX THIS is where the abstraction breaks down

the problem with perspectives being branches and ontologies being files is that the history for frames
only applies to a single ontology file otherwise the history for the uberon file gets tangled with
interlex, etc.

HOWEVER perspectives are still useful because they do represent users/groups/multiple versions of any file
it is the pairing of perspective and file that is the unit for history so consecutive frames must match
file and perspective?

the names that appear in this table should probably refer to the canonical base uri for the ontology
e.g. uri.interlex.org/base/ontologies/interlex because the perspective/user is orthogonal

when i want to make changes to someone else's changes then i think we deal with that by pointing
to the other person's perspective not to their uri name, and that can continue on with arbitrary
complexity

the way we handle any change on top of another perspective is that we detect when the parent
frame's perspective changes, we still record what the parent frame had as a perspective and
since we know the point in time it still works, if the parent perspective changes then when
we resolve things in the future we have to write a new frame i think?

see comment above identities, I'm pretty sure this needs to go per term so that individual
terms can track their upstream perspective ... though what we do about unnamed subgraphs
is an open question, e.g. owl general class axioms XXX EXCEPT that there are all these unhandled
cases for the unnamed subgraphs >_<
*/

CREATE TABLE identity_named_triples_ingest(
       -- we already have the subgraph triple mappings because those are the only identifiable unit for subgraphs
       -- thus we only need the named triples mapping, we don't need the full mapping
       --subject uri not null, -- this does not go here, it goes in another table if we need/want it or we can just get it when loading the trips
       named_embedded_identity bytea references identities (identity),
       triple_identity bytea,  -- is unique for the named subset -- see alters below for fk
       CONSTRAINT pk__id_nti__named_embedded_identity_triple_identity PRIMARY KEY (named_embedded_identity, triple_identity)
);

CREATE TABLE subgraph_triples( -- FIXME not clear whether we need this at all
       triple integer NOT NULL, -- see alters below
       -- subgraph_id integer NOT NULL references identities (id) -- FIXME TODO will almost cert need this for perf
       subgraph_identity bytea NOT NULL references identities (identity)
       --triple_identity NOT NULL,

);

/* -- not needed anymore i think/
CREATE TABLE latest_ontology_triples(
       -- we only retain the parent triples, any forkes will have their changes applied as needed
       ontology integer NOT NULL,
       triple integer NOT NULL
);
*/

CREATE TABLE name_perspective_parent(
       -- uri default parents ... hrm
       name uri NOT NULL references reference_names(name),
       perspective integer NOT NULL references perspectives(id),
       parent integer NOT NULL references perspectives(id),
       datetime TIMESTAMP WITH TIME ZONE
);

/*
CREATE TABLE perspective_parent(
       -- most perspectives have parents that are used to fill in information
       -- that they do not have, however not all perspectives will have this
       -- e.g. the uberon perspective might point to the empty perspective
       -- as would all files that track specific ontologies, e.g. the obo perspective
       perspective integer,
       parent integer,
       datetime
);
*/

/*
CREATE TABLE frame_lineage(
       -- XXX do not use, what we really wanted was perspective parent
       -- all frames have not only a previous frame
       -- but also a parent perspective
       frame_id
       perspective_id
       datetime
);
*/

CREATE TABLE qualifiers(
       -- XXX this table is old and we probably don't want to use it
       -- qualifiers are source triple hashes with an ordering rule
       -- but those orderings are also 'qualified' per group
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       identity bytea NOT NULL,
       perspective integer NOT NULL references perspectives (id),
       previous_qualifier_id integer,
       -- CONSTRAINT pk__qualifiers PRIMARY KEY (data_identity, group_id)
       CONSTRAINT fk__qualifiers_previous_qualifier_id
                  FOREIGN key (previous_qualifier_id)
                  REFERENCES qualifiers (id) match simple
);

-- TODO user explicitly included/excluded qualifiers (ie when they switch to closed world) needs to have datetime

CREATE TYPE transform_rule AS ENUM ('EquivClassIntersection', 'EquivClassUnion', 'RestrictionSome', 'RestrictionAll', 'List');

CREATE TABLE load_events(
       -- XXX this table is old and we probably don't want to use it
       -- NOTE: this is also the user edit log...
       -- SELECT * FROM load_events AS e JOIN identity_relations AS rel JOIN identities AS i ON e.serialization_identity = rel.s AND rel.o = i.identity WHERE rel.p = 'hasPart';
       -- gives the reference_names for the parts of a serialization, usually we go the other way
       -- SELECT * FROM reference_names AS ref JOIN identity_relations AS rel JOIN load_events AS e ON ref.identity = rel.o AND rel.s = e.serialization_identity WHERE rel.p = 'hasPart' AND datetime < some_time;
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       serialization_identity bytea,  -- FIXME not all load events have serializations
       non_ser_load_iri uri,
       -- identity bytea NOT NULL,  -- TODO trigger check on data and metadata
       perspective integer NOT NULL references perspectives (id), -- from /<user>/path-to-reference-name AND from api key mapping, they must match, merge records will have them separate but NOT load records
       --user_id integer NOT NULL, -- from the api key mapping
       datetime timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
       CHECK ((serialization_identity IS NOT NULL AND non_ser_load_iri IS     NULL) OR
              (serialization_identity IS     NULL AND non_ser_load_iri IS NOT NULL)),
       CONSTRAINT un__load_events__ident_perspective UNIQUE (serialization_identity, perspective), -- possibly redundent? FIXME also allows multiple groups to upload the same serialization which is bad maybe?
       CONSTRAINT fk__load_events__ident__identities
                  FOREIGN KEY (serialization_identity)
                  REFERENCES identities (identity)
);

/* -- pretty sure this is broken and we don't need/want this anymore
-- the issue is that qualifiers were rolling for the whole group
-- but i don't think this even did that correctly, and if all we
-- care about is temporal relations then we don't need those
-- qualifiers anyway
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
*/

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

/*
-- at some point we can benchmark vs this approach, but I honestly don't think it
-- will give us any real performance improvements
CREATE TABLE nodes (
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, -- preferred for 10+
       uri text,
       blank integer,
       datatype text,
       language varchar(10),
       subgraph_identity

)

CREATE TABLE inttrips(
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, -- preferred for 10+
       s integer,
       p integer,
       o integer,
);
*/

--CREATE OR REPLACE FUNCTION tripleIdentity(id integer, OUT identity text) RETURNS text AS $tripleIdentity$
CREATE OR REPLACE FUNCTION tripleIdentityOld(id integer, OUT identity bytea) RETURNS bytea AS $tripleIdentityOld$
       -- select digest('asdf' || digest(' ', 'sha256') || digest('', 'sha256') || digest(' ', 'sha256') || digest('', 'sha256'), 'sha256');
       -- matches IBNode(rdflib.Literal('asdf'))
       BEGIN
           SELECT digest(
                  coalesce(t.s, '') ||
                  coalesce(t.s_blank::text, '') || ' ' ||
                  coalesce(t.p, '') || ' ' ||
                  coalesce(t.o, '') ||
                  coalesce(t.o_blank::text, '') ||
                  coalesce(t.o_lit, '') ||    -- note that o_lits are hashed individually first along with each field to differentiate
                  coalesce(t.datatype, '') || -- this is not what is being done here right now
                  coalesce(t.language, '') || ' ' ||  -- FIXME this trailing space causes mismatch with python
                  coalesce(t.subgraph_identity::text, ''), 'sha256')
           FROM triples as t WHERE tripleIdentity.id = t.id INTO identity;
       END;
$tripleIdentityOld$ language plpgsql;

CREATE OR REPLACE FUNCTION tripleIdentity(s uri, p uri, o uri, o_lit text, datatype uri, language text) RETURNS bytea AS $tripleIdentity$
DECLARE
obj_ident bytea;
BEGIN
IF o IS NULL THEN
   obj_ident =
digest(
  digest(o_lit, 'sha256') ||
  digest(coalesce(datatype::text, ''), 'sha256') ||
  digest(coalesce(language, ''), 'sha256')
, 'sha256');
ELSE
   obj_ident = digest(o::text, 'sha256');
END IF;
RETURN
digest(
  digest(s::text, 'sha256') ||
  digest(
    digest(p::text, 'sha256') ||
    obj_ident
    , 'sha256')
, 'sha256');
END;
$tripleIdentity$ language plpgsql;

CREATE OR REPLACE FUNCTION tripleIdentityConn(s uri, p uri, obj_ident bytea) RETURNS bytea AS $tripleIdentityConn$
BEGIN
RETURN
digest(
  digest(s::text, 'sha256') ||
  digest(
    digest(p::text, 'sha256') ||
    obj_ident
    , 'sha256')
, 'sha256');
END;
$tripleIdentityConn$ language plpgsql;

CREATE TABLE triples(
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, -- preferred for 10+ -- TODO question about triple hash vs id, because we can't know exact id in advance and have to query and/or maintain the map ... maybe we want another unique column for that in addition for external query simplicity? it would need to be indexed anyway
       triple_identity bytea UNIQUE, -- FIXME TODO an auxillary column or what? it is what we would need/want for foreign key stuff I think, OR do we not care about triple identity at all? no, the reason we care about it is because we need/want a way to insert into the ontologies file to be able to reconstruct the original input
       --version_ti integer NOT NULL, -- TODO also need a version on the triple identity here
       s uri,
       s_blank integer, -- internal bnode counter for isomorphism checks
       p uri NOT NULL,
       o uri,
       o_lit text,
       o_blank integer, -- this is internal for (s_blank p o_blank) and triples.id for (s, p, o_blank)
       datatype uri,
       language text, -- FIXME can we put these in the datatype column as just strings?
       subgraph_identity bytea,
       -- FIXME SIGH as much as I want to enforce leading/trailing there are some edge cases
       -- such as when importing, or when referring to the contents of a whitespace string
       -- I think what we will have to do is add a set of immediate fixes on ingest that we always run
       -- that work on specific fields and immediately fix things after load as an immediate change set
       -- CHECK (o_lit ~* '(^\S+|\S+$)'),  -- no leading or trailing whitespace TODO also for other columns
       CHECK ((uri_host(s) <> reference_host()) OR
             -- currently we prevent users from entering /{group-other-than-base}/{ilx,cde,pde,fde}_ etc.
             -- however user uris are allowed
              (uri_host(s) = reference_host() AND (uri_path_array(s))[2] !~* '[A-Za-z]+_[0-9]+') OR -- FIXME or cde_, fde_, etc
              -- TODO we can't check that the id is actually in the database without a trigger
              -- TODO also prevent users from creating ilx_ fragments in /uris/
              -- only base may have ilx ids, all the rest are by construction from qualifiers
              -- FIXME un hardcode 'base' and 'ilx_'
              (uri_host(s) = reference_host() AND (uri_path_array(s))[1] = 'base' AND (uri_path_array(s))[2] ~* '[A-Za-z]+_[0-9]+')),
       -- these two should always be an exact copy of the checks for s
       CHECK ((uri_host(p) <> reference_host()) OR
              (uri_host(p) = reference_host() AND (uri_path_array(p))[2] !~* '[A-Za-z]+_[0-9]+') OR
              (uri_host(p) = reference_host() AND (uri_path_array(p))[1] = 'base' AND (uri_path_array(p))[2] ~* '[A-Za-z]+_[0-9]+')),
       CHECK ((uri_host(o) <> reference_host()) OR
              (uri_host(o) = reference_host() AND (uri_path_array(o))[2] !~* '[A-Za-z]+_[0-9]+') OR
              (uri_host(o) = reference_host() AND (uri_path_array(o))[1] = 'base' AND (uri_path_array(o))[2] ~* '[A-Za-z]+_[0-9]+')),
       CHECK ((s IS NOT NULL AND s_blank IS NULL) OR
              (s IS NULL AND s_blank IS NOT NULL) OR
              (s = 'annotation' AND s_blank IS NOT NULL)), -- reminder: this was to speed up retrieval of triples that are part of 3 triple annotation ?
              -- FIXME not validating our URIs in db ... this is useful but should fail
              -- even though rdflib in theory provides quite a bit of validation up from
              -- I actually think it only barfs on serialization or parsing, not from internal
       CHECK ((o IS NOT NULL AND o_lit IS     NULL AND o_blank IS     NULL) OR
              (o IS     NULL AND o_lit IS NOT NULL AND o_blank IS     NULL) OR
              (o IS     NULL AND o_lit IS     NULL AND o_blank IS NOT NULL)),
       CHECK (NOT (datatype IS NOT NULL AND language IS NOT NULL)),
       -- ensure that rows have either a triple identity XOR a subgraph identity OR it is a conn triple s p id
       CHECK ((triple_identity IS NOT NULL AND subgraph_identity IS     NULL) OR -- named case
              (triple_identity IS     NULL AND subgraph_identity IS NOT NULL) OR -- link and term cases
              (triple_identity IS NOT NULL AND s IS NOT NULL AND s != 'annotation' AND subgraph_identity IS NOT NULL)), -- conn case
       CHECK (triple_identity IS NULL OR -- database double sanity check
              (subgraph_identity IS     NULL AND triple_identity = tripleIdentity(s, p, o, o_lit, datatype, language)) OR
              (subgraph_identity IS NOT NULL AND triple_identity = tripleIdentityConn(s, p, subgraph_identity))),
       -- switching the subraph_identity check so that it satisfies the statement
       -- "if you have a subgraph_identity you MUST have an s_blank"
       -- the converse is not true, and we will use it to efficiently encode annotations
       -- this is more logical than before since we only really care that things that are
       -- members of a subgraph have distinct s_blanks. In the annotation subgraph it is
       -- entirely possible to have multiple triples with the same s_blank and different values
       -- I suspect that this may start breaking some of our other constraints though
       CHECK (subgraph_identity IS NULL OR
              (subgraph_identity IS NOT NULL AND
               s_blank IS NOT NULL OR o_blank IS NOT NULL)),
       -- the o_blank check stays since there is no use case for non null o_blanks without a subgraph
       -- (at this time) though in the future there might be some ways it could be used
       CHECK (o_blank IS NULL OR
              o_blank IS NOT NULL AND
              subgraph_identity IS NOT NULL),
       CHECK (o_blank <> s_blank)  -- XXX we do have some test graphs with the structure, obviously the are evil, see whether we need to support them
       -- CONSTRAINT un__triples__s_p_o UNIQUE (s, p, o),
       -- CONSTRAINT un__triples__s_p_o_lit UNIQUE (s, p, o_lit, datatype, language),
       -- FIXME o_lib can be BIG, too big to
       -- CONSTRAINT un__triples__s_p_o_blank UNIQUE (s, p, o_blank, subgraph_identity)
       -- CONSTRAINT un__triples__s_blank_p_o_blank UNIQUE (s_blank, p, o_blank, subgraph_identity)
);
CREATE INDEX triples__s__index ON triples (s);
CREATE INDEX triples__p__index ON triples (p);  -- needed accelerate transitive queries (watch out for the memory usage if creating after the fact)

CREATE INDEX triples__subgraph_identity__index
       ON triples (subgraph_identity);

CREATE INDEX triples__s_p_subgraph_identity__index
       ON triples (s, p, subgraph_identity)
       -- BEWARE if you do not restrict to s and si not null
       -- postgres will try to use all the memory to create
       -- the index
       WHERE s IS NOT NULL AND subgraph_identity IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_p_o
       -- assume uri_hash is safe since it is based on
       -- XXX that was a bad assumption, uri_hash has collisions
       -- e.g. for
       -- select uri_hash('http://uri.interlex.org/base/cde_0128858'::uri), uri_hash('http://uri.interlex.org/base/cde_0104467'::uri);
       -- uris are short enough that the overhead probably won't be all that high
       -- access/hash.h hash_any directly from the postgres sources
       ON triples
       (s, p, o)
       WHERE s IS NOT NULL AND
             o IS NOT NULL;

-- NOTE because these are partial indexes they cannot be used directly as constraints

CREATE UNIQUE INDEX un__triples__s_p_o_lit_md5
       ON triples (s, p, md5(o_lit))
       WHERE s IS NOT NULL AND
             o_lit IS NOT NULL AND
             datatype IS NULL AND
             language is NULL;

CREATE UNIQUE INDEX un__triples__s_p_o_lit_datatype_md5
       ON triples
       (s, p, md5(o_lit), datatype)
       WHERE s IS NOT NULL AND
             o_lit IS NOT NULL AND
             datatype IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_p_o_lit_lang_md5
       ON triples
       (s, p, md5(o_lit), md5(language))
       WHERE s IS NOT NULL AND
             o_lit IS NOT NULL AND
             language IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_md5
       ON triples
       (s_blank, p, o, subgraph_identity)
       WHERE s_blank IS NOT NULL AND
             o IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_lit_md5
       ON triples
       (s_blank, p, md5(o_lit), subgraph_identity)
       WHERE s_blank IS NOT NULL AND
             o_lit IS NOT NULL AND
             datatype IS NULL AND
             language is NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_lit_datatype_md5
       ON triples
       (s_blank, p, md5(o_lit), datatype, subgraph_identity)
       -- this should be a VERY rare condition
       WHERE s_blank IS NOT NULL AND
             o_lit IS NOT NULL AND
             datatype IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_lit_lang_md5
       ON triples
       (s_blank, p, md5(o_lit), md5(language), subgraph_identity)
       -- this should be a VERY rare condition
       WHERE s_blank IS NOT NULL AND
             o_lit IS NOT NULL AND
             language IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_p_o_blank
       ON triples
       (s, p, o_blank, subgraph_identity)
       WHERE s IS NOT NULL AND
             o_blank IS NOT NULL;

CREATE UNIQUE INDEX un__triples__s_blank_p_o_blank
       ON triples
       (s_blank, p, o_blank, subgraph_identity)
       WHERE s_blank IS NOT NULL AND
             o_blank IS NOT NULL;

/*
-- FIXME TODO ... we want something like this, but because only want insert to fail
-- if a triple is already present, we can't use this approach
CREATE UNIQUE INDEX un__triples_s_blank_rdf_first
       ON triples
       (s_blank, subgraph_identity)
       WHERE s_blank IS NOT NULL AND
             p = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#first';
*/

CREATE INDEX triples_type_index
       ON triples (o)
       -- if you want an index on all types including those that only appear on bnodes
       -- you need a separate index where the s IS NOT NULL restriction is not present
       -- or might be able to manage using nulls not distinct? but then the index has to
       -- be over (s, o) not just o
       WHERE s IS NOT NULL AND p = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type' AND o IS NOT NULL;

CREATE INDEX search_index ON triples USING GIN (to_tsvector('english', o_lit)) WHERE o_lit IS NOT NULL;

-- GIN is slow here GIST is pretty fast as well, perhaps a bit faster than btree (the default)?
-- the real answer here is the LOWER index so we can use LIKE AKA ~~ 'string'::text
CREATE INDEX label_lower_index ON triples (LOWER(o_lit)) WHERE p = 'http://www.w3.org/2000/01/rdf-schema#label';

-- ALTER TABLE triples DROP CONSTRAINT un__triples__s_p_o_lit;
-- CREATE UNIQUE INDEX un__triples_s_p_o_lit_md5 ON triples (s, p, md5(o_lit), datatype, language);
-- ALTER TABLE triples ADD CONSTRAINT un__triples_s_p_o_lit UNIQUE USING INDEX un__triples_s_p_o_lit_md5;
-- does not work, probably because md5(o_lit) but that is ok

-- note diff at load time from the previous qualifier for the source?
-- ON CONFLICT INSERT INTO temp table or something

ALTER TABLE subgraph_triples ADD CONSTRAINT fk_sgt_trips_id FOREIGN KEY (triple) REFERENCES triples (id);
ALTER TABLE identity_named_triples_ingest ADD CONSTRAINT fk_idnti_trips_identity FOREIGN KEY (triple_identity) REFERENCES triples (triple_identity);

-- one approach for lifting triples as a view per lift function
-- however this has a number of issues, it increases the complexity
-- of certain queries and makes it difficult to interoperate with
-- the triples table directly, it also means we would have to write
-- additional queries to correctly handle reconstructing the correct
-- view of a graph, the alternative seems to be to insert lifted
-- triples into the triples table and link them back to the source
-- somehow ...
CREATE MATERIALIZED VIEW IF NOT EXISTS view_lift_sco_res_onp_svf
AS
SELECT
DISTINCT
t_s.s, t_p.o as p, t_o.o, t_s.subgraph_identity -- si needed for filtering out old triples
FROM triples AS t_s
JOIN triples AS t_l ON t_s.o_blank = t_l.s_blank
JOIN triples AS t_p ON t_l.s_blank = t_p.s_blank
JOIN triples AS t_o ON t_l.s_blank = t_o.s_blank
WHERE t_s.s IS NOT NULL
  AND t_s.p = 'http://www.w3.org/2000/01/rdf-schema#subClassOf'
  AND t_l.s_blank IS NOT NULL
  AND t_p.s_blank IS NOT NULL
  AND t_o.s_blank IS NOT NULL
  AND t_s.subgraph_identity = t_l.subgraph_identity
  AND t_s.subgraph_identity = t_p.subgraph_identity
  AND t_s.subgraph_identity = t_o.subgraph_identity
  AND t_l.p = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'
  AND t_l.o = 'http://www.w3.org/2002/07/owl#Restriction'
  AND t_p.p = 'http://www.w3.org/2002/07/owl#onProperty'
  AND t_o.p = 'http://www.w3.org/2002/07/owl#someValuesFrom'
WITH NO DATA;

CREATE INDEX view_lift_sco_res_onp_svf__p__index ON view_lift_sco_res_onp_svf (p);

-- run this at the end of every ingest and don't worry about it
--REFRESH MATERIALIZED VIEW view_lift_sco_res_onp_svf;

-- transitive query helper functions

CREATE OR REPLACE FUNCTION connected_predicates_ilx(s_starts uri[], predicates uri[], obj_to_sub boolean = FALSE, max_depth integer = -1)
RETURNS TABLE (s uri, p uri, o uri, ident bytea) AS $$
BEGIN

IF obj_to_sub THEN

  RETURN QUERY
  WITH RECURSIVE tree(s, p, o, ident, dpth) AS (
    SELECT t.s, t.p, t.o, t.triple_identity as ident, 0 as dpth FROM triples AS t
    JOIN UNNEST(predicates) AS ps ON t.p = ps
    JOIN UNNEST(s_starts) AS ss ON t.o = ss -- object
  UNION ALL
    SELECT t.s, t.p, t.o, t.triple_identity as ident, tr.dpth + 1 as dpth FROM triples AS t
    JOIN tree AS tr ON t.o = tr.s -- object -> subject
    JOIN UNNEST(predicates) AS ps ON t.p = ps
    WHERE max_depth < 0 OR tr.dpth < max_depth
  )
  SELECT DISTINCT tro.s, tro.p, tro.o, tro.ident FROM tree as tro;

ELSE

  RETURN QUERY
  WITH RECURSIVE tree(s, p, o, ident, dpth) AS (
    SELECT t.s, t.p, t.o, t.triple_identity as ident, 0 as dpth FROM triples AS t
    JOIN UNNEST(predicates) AS ps ON t.p = ps
    JOIN UNNEST(s_starts) AS ss ON t.s = ss -- subject
  UNION ALL
    SELECT t.s, t.p, t.o, t.triple_identity as ident, tr.dpth + 1 as dpth FROM triples AS t
    JOIN tree AS tr ON t.s = tr.o -- subject -> object
    JOIN UNNEST(predicates) AS ps ON t.p = ps
    WHERE max_depth < 0 OR tr.dpth < max_depth
  )
  SELECT DISTINCT tro.s, tro.p, tro.o, tro.ident FROM tree as tro;

END IF;

END;
$$ language plpgsql;

CREATE OR REPLACE FUNCTION connected_predicates_ext(s_starts uri[], predicates uri[], obj_to_sub boolean = FALSE, max_depth integer = -1)
RETURNS TABLE (s uri, p uri, o uri, ident bytea) AS $$
BEGIN

IF obj_to_sub THEN

  RETURN QUERY
  WITH RECURSIVE tree(s, p, o, ident, dpth) AS (
    SELECT t.s, t.p, t.o, t.subgraph_identity as ident, 0 as dpth FROM view_lift_sco_res_onp_svf AS t
    JOIN UNNEST(predicates) AS ps ON t.p = ps
    JOIN UNNEST(s_starts) AS ss ON t.o = ss -- object
  UNION ALL
    SELECT t.s, t.p, t.o, t.subgraph_identity as ident, tr.dpth + 1 as dpth FROM view_lift_sco_res_onp_svf AS t
    JOIN tree AS tr ON t.o = tr.s -- object -> subject
    JOIN UNNEST(predicates) AS ps ON t.p = ps
    WHERE max_depth < 0 OR tr.dpth < max_depth
  )
  SELECT DISTINCT tro.s, tro.p, tro.o, tro.ident FROM tree as tro;

ELSE

  RETURN QUERY
  WITH RECURSIVE tree(s, p, o, ident, dpth) AS (
    SELECT t.s, t.p, t.o, t.subgraph_identity as ident, 0 as dpth FROM view_lift_sco_res_onp_svf AS t
    JOIN UNNEST(predicates) AS ps ON t.p = ps
    JOIN UNNEST(s_starts) AS ss ON t.s = ss -- subject
  UNION ALL
    SELECT t.s, t.p, t.o, t.subgraph_identity as ident, tr.dpth + 1 as dpth FROM view_lift_sco_res_onp_svf AS t
    JOIN tree AS tr ON t.s = tr.o -- subject -> object
    JOIN UNNEST(predicates) AS ps ON t.p = ps
    WHERE max_depth < 0 OR tr.dpth < max_depth
  )
  SELECT DISTINCT tro.s, tro.p, tro.o, tro.ident FROM tree as tro;

END IF;

END;
$$ language plpgsql;

CREATE OR REPLACE FUNCTION connected_predicates_all(s_starts uri[], predicates uri[], obj_to_sub boolean = FALSE, max_depth integer = -1)
RETURNS TABLE (s uri, p uri, o uri, ident bytea, ext boolean) AS $$
/*
don't bother with trying to sort out internal and external starts and predicates and
trying to enforce matching between them for the time being nearly all the data we have
will not cause issues if they are mixed since cross usage will mostly be rare
*/
BEGIN

IF obj_to_sub THEN

  RETURN QUERY
  WITH RECURSIVE trip_and_view AS (
      SELECT t.s, t.p, t.o, t.triple_identity as ident, false as ext FROM triples AS t
      JOIN UNNEST(predicates) AS ps ON t.p = ps
    UNION
      SELECT t.s, t.p, t.o, t.subgraph_identity as ident, true as ext FROM view_lift_sco_res_onp_svf AS t
      JOIN UNNEST(predicates) AS ps ON t.p = ps
  ), tree(s, p, o, ident, ext, dpth) AS (
      SELECT t.s, t.p, t.o, t.ident, t.ext, 0 as dpth FROM trip_and_view AS t
      JOIN UNNEST(s_starts) AS ss ON t.o = ss -- object
    UNION ALL
      SELECT t.s, t.p, t.o, t.ident, t.ext, tr.dpth + 1 as dpth FROM trip_and_view AS t
      JOIN tree AS tr ON t.o = tr.s -- object -> subject
      WHERE max_depth < 0 OR tr.dpth < max_depth
  )
  SELECT DISTINCT tro.s, tro.p, tro.o, tro.ident, tro.ext FROM tree as tro;

ELSE

  RETURN QUERY
  WITH RECURSIVE trip_and_view AS (
      SELECT t.s, t.p, t.o, t.triple_identity as ident, false as ext FROM triples AS t
      JOIN UNNEST(predicates) AS ps ON t.p = ps
    UNION
      SELECT t.s, t.p, t.o, t.subgraph_identity as ident, true as ext FROM view_lift_sco_res_onp_svf AS t
      JOIN UNNEST(predicates) AS ps ON t.p = ps
  ), tree(s, p, o, ident, ext, dpth) AS (
      SELECT t.s, t.p, t.o, t.ident, t.ext, 0 as dpth FROM trip_and_view AS t
      JOIN UNNEST(s_starts) AS ss ON t.s = ss -- subject
    UNION ALL
      SELECT t.s, t.p, t.o, t.ident, t.ext, tr.dpth + 1 as dpth FROM trip_and_view AS t
      JOIN tree AS tr ON t.s = tr.o -- subject -> object
      WHERE max_depth < 0 OR tr.dpth < max_depth
  )
  SELECT DISTINCT tro.s, tro.p, tro.o, tro.ident, tro.ext FROM tree as tro;

END IF;

END;
$$ language plpgsql;

-- replicas

CREATE TABLE subgraph_replicas (
       -- have to use surrogate because we need s and p to be nullable
       id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       graph_bnode_identity bytea NOT NULL references identities (identity),
       -- null s and null p always implies s_blank = 0
       s uri,
       p uri,
       subgraph_identity bytea NOT NULL,
       replica integer NOT NULL,
       CHECK ((s IS NOT NULL AND p IS NOT NULL)
           OR (s IS NULL     AND p IS     NULL)),
       -- nulls not distinct requires >=postgresql-15
       UNIQUE NULLS NOT DISTINCT (graph_bnode_identity, s, p, subgraph_identity, replica)
);

CREATE INDEX subgraph_replicas__s__index ON subgraph_replicas (s);
CREATE INDEX subgraph_replicas__subgraph_identity__index ON subgraph_replicas (subgraph_identity);
CREATE INDEX subgraph_replicas__s_p_subgraph_identity__index
       ON subgraph_replicas (s, p, subgraph_identity)
       NULLS NOT DISTINCT;
CREATE INDEX subgraph_replicas__subgraph_identity_replica__index
       ON subgraph_replicas (subgraph_identity, replica);

CREATE TABLE subgraph_deduplication (
       -- FIXME TODO figure out what constraints we can have here
       -- id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       graph_bnode_identity bytea NOT NULL references identities (identity),
       subject_subgraph_identity bytea NOT NULL,
       subject_replica integer NOT NULL,
       o_blank integer NOT NULL,  -- the subject_subgraph_identity o_blank
       object_subgraph_identity bytea NOT NULL,
       object_replica integer NOT NULL,
       PRIMARY KEY (  -- FIXME TODO vs unique
               graph_bnode_identity,
               subject_subgraph_identity,
               subject_replica,
               o_blank,
               object_subgraph_identity,
               object_replica)
);

CREATE INDEX subgraph_deduplication__ssi_srep__index
       ON subgraph_deduplication (subject_subgraph_identity, subject_replica);

CREATE INDEX subgraph_deduplication__ssi___index
       ON subgraph_deduplication (subject_subgraph_identity);

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
       -- better way: use sentiel values? s_blank -> id with subgraph_identity as null ...
       triple_id integer NOT NULL,  -- ah, and now we see the problem with having 3 tables
       annotation_triple_id integer NOT NULL,
       CONSTRAINT fk__annotations__triple_id__triples
                  FOREIGN KEY (triple_id)
                  REFERENCES triples (id),
       CONSTRAINT fk__annotations__annotation_triple_id__triples
                  FOREIGN KEY (annotation_triple_id)
                  REFERENCES triples (id)
);

CREATE TABLE perspective_heads(
       -- this is how we are going to deal with multiple versions of multiple terms
       -- http://uri.interlex.org/tgbugs/ilx_0101431 will point to pers-tgbugs http://uri.interlex.org/base/ilx_0101431 some-identity
       -- http://purl.obolibrary.org/obo/UBERON_0000955 can work in a similar way
       -- but we don't have a where i can edit it right now
       -- http://uri.interlex.org/tgbugs/ontologies/uris/some-ontology works the same way
       perspective_id integer NOT NULL,
       subject uri NOT NULL,
       head_identity bytea NOT NULL
);
