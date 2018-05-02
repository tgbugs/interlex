--
SELECT rn.expected_bound_name, i2.type
       FROM identity_relations AS ir
       JOIN identities AS i1 ON i1.identity = ir.s
       JOIN identities AS i2 ON i2.identity = ir.o
       JOIN reference_names AS rn ON i1.reference_name = rn.name
       WHERE ir.p = 'hasPart';

-- TODO the relationship between ids and subgraphs is a
-- recapitulation of the relationship between name and data (not named data)
-- it may be worth having a table or view that maintains a mapping from
-- subject rdf:type owl:* to subgraphs, unbound names can be thought of
-- as untyped as well... linked subgraphs are then typed by predicate
CREATE OR REPLACE FUNCTION ilx_id_triples(ilx_id char(7)) RETURNS TABLE (
s uri,
s_blank integer,
p uri,
o uri,
o_lit text,
datatype uri,
language varchar(10),
o_blank integer,
subgraph_identity bytea
) AS
$$
    DECLARE
        baseuri uri;
    BEGIN
        baseuri = 'http://' || reference_host() || '/' || ilx_id;
        RETURN QUERY
        WITH graph AS (
        SELECT t.s, t.s_blank, t.p, t.o,
                t.o_lit, t.datatype, t.language, t.o_blank, t.subgraph_identity
        FROM triples AS t JOIN existing_iris AS e
        ON t.s = iri OR t.s = baseuri
        WHERE e.ilx_id = ilx_id_triples.ilx_id
        ), subgraphs AS (
        SELECT sg.s, sg.s_blank, sg.p, sg.o,
               sg.o_lit, sg.datatype, sg.language,
               sg.o_blank, sg.subgraph_identity
        FROM triples AS sg, graph AS g
        WHERE sg.subgraph_identity = g.subgraph_identity AND sg.s is NULL
        )
        SELECT g.s, g.s_blank, g.p, g.o,
               g.o_lit, g.datatype, g.language, g.o_blank, g.subgraph_identity
        FROM graph as g
        UNION
        SELECT sg.s, sg.s_blank, sg.p, sg.o,
               sg.o_lit, sg.datatype, sg.language, sg.o_blank, sg.subgraph_identity
        FROM subgraphs as sg;
END
$$ language plpgsql;

--

SELECT * FROM ilx_id_triples('0101431');

--

SELECT t2.s, t2.p, t2.o, t2.o_lit
       FROM triples AS t1
       JOIN triples AS t2
       ON t1.s = t2.s
       WHERE t1.p::text LIKE '%#type' AND t1.o::text LIKE '%#Ontology';

--

SELECT t2.s, t2.p, t2.o, t2.o_lit
       FROM triples AS t1
       JOIN triples AS t2
       ON t1.s = t2.s
       WHERE t1.p::text LIKE '%#type' AND t1.o::text LIKE '%#Class';

--

/*
INSERT INTO triples (s, p, o, o_lit) VALUES
       ('http://uri.interlex.org/tgbugs/curies',
        'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
        -- /types/readable/Curies or /type/readable/Curies
        'http://uri.interlex.org/base/readable/Curies',
        null
       null)
       ('http://uri.interlex.org/tgbugs/curies', -- this is a bad way store these
       -- we could produce curie only sets as triples
       -- but it seems to make much more sense to just... use them as such
        'http://purl.obolibrary.org/obo/GO_',
        null,
        'GO')
*/

--

SELECT i.reference_name, i.identity, l.group_id, -- q.id
       l.datetime
FROM
-- qualifiers as q,
     load_events as l
JOIN identity_relations as ir
     ON ir.s = l.serialization_identity
JOIN identities as i
     ON ir.o = i.identity
WHERE --q.group_id = 5 AND
      i.type = 'data' AND
      ir.p = 'hasPart'
      -- ir.s = NEW.serialization_identity
ORDER BY l.datetime
      ;
