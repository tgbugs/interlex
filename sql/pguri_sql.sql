/*
reimplementation of the pguri c extension implementation of RFC 3986
in pure plpgsql using a text DOMAIN to provide the uri type

behavior should be identical with the exception of collation behavior

works without need for postgres superuser access which is not available
on managed solutions such as aws rds, other implementations using the
postgres trusted language extensions were attempted as well but ultimately
their performance optimizations required superuser access and they were
vastly more complext to test and deploy due to needing custom langauge
runtimes etc. so the fact that this DOMAIN approach is simpler and more
performant is a big win, in some (important) cases this implementation
can also be faster than the pguri c extension because it operates using
the highly optimized postgresql test type internally
*/

-- uri type as text DOMAIN

CREATE FUNCTION _uri_fast(s text) RETURNS boolean -- uris with no escape sequences and no square brackets
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT s ~ '^[A-Za-z][A-Za-z0-9+.-]*://(?:[A-Za-z0-9._~!$&''()*+,;=:-]*@)?[A-Za-z0-9._~!$&''()*+,;=-]*(:[0-9]*)?([/?#][A-Za-z0-9._~!$&''()*+,;=:/?#-]*)?$'
$fn$;


CREATE FUNCTION uri_valid(s text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
DECLARE
    scheme text; authority text; hostport text;
BEGIN
    IF _uri_fast(s) THEN
        RETURN true;
    END IF;
    -- check for invalid chars
    IF s !~ '^([A-Za-z0-9._~:/?#@!$&''()*+,;=[\]-]|%[0-9A-Fa-f]{2})*$' THEN
        RETURN false;
    END IF;
    scheme := substring(s from '^([^:/?#]*):');
    IF scheme IS NOT NULL AND scheme !~ '^[A-Za-z][A-Za-z0-9+.-]*$' THEN
        RETURN false;
    END IF;
    authority := substring(s from '^(?:[^:/?#]+:)?//([^/?#]*)');
    IF authority IS NOT NULL THEN
        IF authority ~ '@.*@' THEN
            RETURN false;
        END IF;
        hostport := regexp_replace(authority, '^[^@]*@', '');
        IF NOT (hostport ~ '^[^][@:/?#]*(:[0-9]*)?$'                            -- reg-name (common)
             OR hostport ~ '^\[[0-9A-Fa-f:.]+\](:[0-9]*)?$'                     -- IPv6
             OR hostport ~ '^\[[vV][0-9A-Fa-f]+\.[^][/?#]+\](:[0-9]*)?$') THEN  -- IPvFuture
            RETURN false;
        END IF;
    END IF;
    -- square brackets only as an authority ip literal host
    IF s ~ '[][]' THEN
        IF authority IS NULL OR left(regexp_replace(authority, '^[^@]*@', ''), 1) <> '[' THEN
            RETURN false;
        END IF;
        IF regexp_replace(s, '\[[^\]]*\]', '') ~ '[][]' THEN
            RETURN false;
        END IF;
    END IF;
    RETURN true;
END;
$fn$;


-- mimic pguri error handling
CREATE FUNCTION uri_raise_invalid(s text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '22P02',   -- invalid_text_representation, as pguri uses
        MESSAGE = format('invalid input syntax for type uri: "%s"', s);
END;
$fn$;

-- use CASE to ensure errors mimic pguri
CREATE DOMAIN uri AS text COLLATE "C" -- COLLATE "C" force byte order comparison
    CONSTRAINT uri_check CHECK (
        CASE WHEN _uri_fast(VALUE) THEN true
             WHEN uri_valid(VALUE) THEN true
             ELSE uri_raise_invalid(VALUE) END);


-- uri type accessors

CREATE FUNCTION uri_scheme(uri) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT substring($1::text from '^[A-Za-z][A-Za-z0-9+.-]*(?=:)')
$fn$;

CREATE FUNCTION uri_userinfo(uri) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT substring($1::text from '^(?:[^:/?#]+:)?//([^/?#@]*)@')
$fn$;

CREATE FUNCTION uri_host(uri) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT substring($1::text from
        '^(?:[^:/?#]+:)?//(?:[^/?#@]*@)?\[?((?<=\[)[^\]]*(?=\])|[^]:/?#[]*)')
$fn$;

CREATE FUNCTION uri_port(uri) RETURNS integer
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT substring($1::text from
        '^(?:[^:/?#]+:)?//(?:[^/?#@]*@)?(?:\[[^\]]*\]|[^:/?#]*):([0-9]+)(?:[/?#]|$)')::integer
$fn$;

CREATE FUNCTION uri_path(uri) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT substring($1::text from '^(?:[^:/?#]+:)?(?://[^/?#]*)?([^?#]*)')
$fn$;

CREATE FUNCTION uri_query(uri) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT substring($1::text from '^[^#?]*\?([^#]*)')
$fn$;

CREATE FUNCTION uri_fragment(uri) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT substring($1::text from '(?<=#).*$')
$fn$;

CREATE FUNCTION uri_path_array(uri) RETURNS text[]
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
DECLARE
    t text := $1::text;
    p text;
BEGIN
    p := substring(t from '^(?:[^:/?#]+:)?(?://[^/?#]*)?([^?#]*)');
    IF p = '' THEN
        RETURN ARRAY[]::text[];
    END IF;
    IF left(p, 1) = '/' THEN
        IF p = '/' AND t !~ '^(?:[^:/?#]+:)?//' THEN
            RETURN ARRAY[]::text[];
        END IF;
        RETURN (string_to_array(p, '/'))[2:];
    END IF;
    RETURN string_to_array(p, '/');
END;
$fn$;

-- host_inet: only for IP literals; plpgsql so a bad literal yields NULL not error
CREATE FUNCTION uri_host_inet(uri) RETURNS inet
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
BEGIN
    -- bail out early if not inet
    IF $1::text !~ '^(?:[^:/?#]+:)?//(?:[^/?#@]*@)?[0-9[]' THEN
        RETURN NULL;
    END IF;
    DECLARE
        h text := uri_host($1);
    BEGIN
        IF position(':' in h) > 0 THEN -- ipv6 case
            RETURN h::inet;
        END IF;
        IF h ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$' THEN
            RETURN h::inet;
        END IF;
        RETURN NULL;
    EXCEPTION WHEN others THEN
        RETURN NULL;
    END;
END;
$fn$;

-- uri type comparison

-- case-insensitive text_range compare; NULL = absent = least (pguri cmp_text_range)
CREATE FUNCTION _uri_ctr(a text, b text) RETURNS integer
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $fn$
    SELECT CASE
        WHEN a IS NULL AND b IS NULL THEN 0
        WHEN a IS NULL THEN -1
        WHEN b IS NULL THEN 1
        -- COLLATE "C" match pguri's ASCII strncasecmp
        WHEN lower(a) COLLATE "C" < lower(b) COLLATE "C" THEN -1
        WHEN lower(a) COLLATE "C" > lower(b) COLLATE "C" THEN 1
        ELSE 0 END
$fn$;

-- expand an IPv6 inner text to 8 group integers (for memcmp-style ordering)
CREATE FUNCTION _uri_ip6_key(inp text) RETURNS integer[]
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
DECLARE
    s text := lower(inp);
    m text[];
    l text[]; r text[]; g text[];
    missing int;
    res int[] := ARRAY[]::int[];
    grp text;
BEGIN
    m := regexp_match(s, '^(.*:)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$');
    IF m IS NOT NULL THEN
        s := m[1] || to_hex((m[2]::int << 8) | m[3]::int) || ':'
                  || to_hex((m[4]::int << 8) | m[5]::int);
    END IF;
    IF position('::' in s) > 0 THEN
        IF split_part(s, '::', 1) = '' THEN l := ARRAY[]::text[];
        ELSE l := string_to_array(split_part(s, '::', 1), ':'); END IF;
        IF split_part(s, '::', 2) = '' THEN r := ARRAY[]::text[];
        ELSE r := string_to_array(split_part(s, '::', 2), ':'); END IF;
        missing := 8 - COALESCE(array_length(l, 1), 0) - COALESCE(array_length(r, 1), 0);
        IF missing < 1 THEN missing := 1; END IF;
        g := l;
        FOR i IN 1..missing LOOP g := array_append(g, '0'); END LOOP;
        g := g || r;
    ELSE
        g := string_to_array(s, ':');
    END IF;
    FOREACH grp IN ARRAY g LOOP
        res := array_append(res,
            ('x' || lpad(CASE WHEN grp = '' THEN '0' ELSE grp END, 8, '0'))::bit(32)::int);
    END LOOP;
    RETURN res;
END;
$fn$;

CREATE FUNCTION uri_cmp(uri, uri) RETURNS integer
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT bttextcmp($1::text, $2::text)
$fn$;

-- match pguri component-wise comparison exactly at cost of performance (not used by default)
CREATE FUNCTION uri_cmp_exact(uri, uri) RETURNS integer
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
DECLARE
    hre   constant text := '^(?:[^:/?#]+:)?//(?:[^/?#@]*@)?(\[[^\]]*\]|[^:/?#]*)';
    pre   constant text := '^(?:[^:/?#]+:)?//(?:[^/?#@]*@)?(?:\[[^\]]*\]|[^:/?#]*):([0-9]+)(?:[/?#]|$)';
    ip4re constant text := '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$';
    sa text := $1::text;
    sb text := $2::text;
    scha text := substring(sa from '^([^:/?#]+):');
    schb text := substring(sb from '^([^:/?#]+):');
    ha text := regexp_replace(substring(sa from hre), '^\[(.*)\]$', '\1'); -- NULL implies no authority
    hb text := regexp_replace(substring(sb from hre), '^\[(.*)\]$', '\1');
    uia text := substring(sa from '^(?:[^:/?#]+:)?//([^/?#@]*)@');
    uib text := substring(sb from '^(?:[^:/?#]+:)?//([^/?#@]*)@');
    poa int := substring(sa from pre)::int;
    pob int := substring(sb from pre)::int;
    ka int; kb int;
    res int;
BEGIN
    res := _uri_ctr(scha, schb);
    IF res = 0 THEN
        ka := CASE WHEN ha IS NULL THEN -1 WHEN ha ~ ':' THEN 2 WHEN ha ~ ip4re THEN 1 ELSE 0 END;
        kb := CASE WHEN hb IS NULL THEN -1 WHEN hb ~ ':' THEN 2 WHEN hb ~ ip4re THEN 1 ELSE 0 END;
        IF ka = -1 THEN
            res := CASE WHEN kb = -1 THEN 0 ELSE -1 END;
        ELSIF ka = 1 THEN
            IF kb = -1 THEN res := 1;
            ELSIF kb = 1 THEN
                res := CASE WHEN string_to_array(ha, '.')::int[] < string_to_array(hb, '.')::int[] THEN -1
                            WHEN string_to_array(ha, '.')::int[] > string_to_array(hb, '.')::int[] THEN 1
                            ELSE 0 END;
            ELSE res := -1; END IF;
        ELSIF ka = 2 THEN
            IF kb = -1 THEN res := 1;
            ELSIF kb = 1 THEN res := 1;
            ELSIF kb = 2 THEN
                res := CASE WHEN _uri_ip6_key(ha) < _uri_ip6_key(hb) THEN -1
                            WHEN _uri_ip6_key(ha) > _uri_ip6_key(hb) THEN 1
                            ELSE 0 END;
            ELSE res := -1; END IF;
        ELSE
            res := _uri_ctr(ha, hb);
        END IF;
    END IF;
    IF res = 0 THEN res := sign(COALESCE(poa, -1) - COALESCE(pob, -1)); END IF; -- port
    IF res = 0 THEN res := _uri_ctr(uia, uib); END IF;                          -- userinfo
    IF res = 0 THEN                                                             -- whole string
        res := CASE WHEN lower(sa) COLLATE "C" < lower(sb) COLLATE "C" THEN -1
                    WHEN lower(sa) COLLATE "C" > lower(sb) COLLATE "C" THEN 1 ELSE 0 END;
    END IF;
    IF res = 0 THEN -- then strcmp (byte order)
        res := CASE WHEN sa COLLATE "C" < sb COLLATE "C" THEN -1
                    WHEN sa COLLATE "C" > sb COLLATE "C" THEN 1 ELSE 0 END;
    END IF;
    RETURN res;
END;
$fn$;

CREATE FUNCTION uri_hash(uri) RETURNS integer
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    SELECT hashtext($1::text)
$fn$;

-- uri type normalization

CREATE FUNCTION _uri_pct(s text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
DECLARE
    out text := '';
    i int := 1;
    n int := length(s);
    hh text; ch text; vv int;
BEGIN
    IF position('%' in s) = 0 THEN RETURN s; END IF; -- no percent encoding to deal with
    WHILE i <= n LOOP
        IF substr(s, i, 1) = '%' AND i + 2 <= n
           AND substr(s, i + 1, 2) ~ '^[0-9A-Fa-f]{2}$' THEN
            hh := upper(substr(s, i + 1, 2));
            vv := ('x' || lpad(hh, 8, '0'))::bit(32)::int;
            IF vv = 0 THEN -- chr(0) is not valid text
                out := out || '%' || hh;
            ELSE
                ch := chr(vv);
                IF ch ~ '^[A-Za-z0-9._~-]$' THEN out := out || ch;
                ELSE out := out || '%' || hh; END IF;
            END IF;
            i := i + 3;
        ELSE
            out := out || substr(s, i, 1);
            i := i + 1;
        END IF;
    END LOOP;
    RETURN out;
END;
$fn$;

CREATE FUNCTION _uri_remove_dots(inp text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
DECLARE
    i text := inp;
    o text := '';
    p int;
BEGIN
    IF inp !~ '(^|/)\.\.?(/|$)' THEN RETURN inp; END IF; -- no '.'/'..' path segment to remove
    WHILE length(i) > 0 LOOP
        IF left(i, 3) = '../' THEN i := substr(i, 4);
        ELSIF left(i, 2) = './' THEN i := substr(i, 3);
        ELSIF left(i, 3) = '/./' THEN i := '/' || substr(i, 4);
        ELSIF i = '/.' THEN i := '/';
        ELSIF left(i, 4) = '/../' THEN
            i := '/' || substr(i, 5);
            p := length(o) - position('/' in reverse(o)) + 1;
            IF position('/' in reverse(o)) = 0 THEN o := ''; ELSE o := left(o, p - 1); END IF;
        ELSIF i = '/..' THEN
            i := '/';
            IF position('/' in reverse(o)) = 0 THEN o := ''; ELSE o := left(o, length(o) - position('/' in reverse(o))); END IF;
        ELSIF i = '.' OR i = '..' THEN i := '';
        ELSE
            IF left(i, 1) = '/' THEN
                p := position('/' in substr(i, 2));
                IF p = 0 THEN o := o || i; i := '';
                ELSE o := o || left(i, p); i := substr(i, p + 1); END IF;
            ELSE
                p := position('/' in i);
                IF p = 0 THEN o := o || i; i := '';
                ELSE o := o || left(i, p - 1); i := substr(i, p); END IF;
            END IF;
        END IF;
    END LOOP;
    RETURN o;
END;
$fn$;

CREATE FUNCTION uri_normalize(uri) RETURNS uri
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
DECLARE
    u text := $1::text; -- unly decode value here to avoid unconditional regex calls
    scheme text; authraw text; path text; query text; frag text;
    ui text; hostport text; host_raw text; porttail text; hinner text; host_n text;
    authority text; pos int; out text := '';
    haspct boolean;
BEGIN
    -- check if already normalized to avoid more expensive operations
    IF position('%' in u) = 0 AND position('[' in u) = 0
       AND u !~ '(^|[/:?#])\.\.?([/?#]|$)'
       AND u !~ '^[^/?#]*(?:[A-Z]|//[^/?#]*[A-Z])' THEN
        RETURN $1;
    END IF;
    scheme  := substring(u from '^([A-Za-z][A-Za-z0-9+.-]*):');
    authraw := substring(u from '^(?:[^:/?#]+:)?//([^/?#]*)'); -- NULL if none
    path    := COALESCE(substring(u from '^(?:[^:/?#]+:)?(?://[^/?#]*)?([^?#]*)'), '');
    query   := substring(u from '^[^#?]*\?([^#]*)'); -- one pass, see uri_query
    frag    := substring(u from '#(.*)$');
    haspct  := position('%' in u) > 0; -- check for percent encoding once
    IF authraw IS NOT NULL THEN
        ui := substring(authraw from '^([^@]*)@');
        hostport := regexp_replace(authraw, '^[^@]*@', '');
        IF left(hostport, 1) = '[' THEN -- ip literal host
            pos := position(']' in hostport);
            host_raw := left(hostport, pos);
            porttail := substr(hostport, pos + 1);
        ELSE
            pos := position(':' in hostport);
            IF pos = 0 THEN host_raw := hostport; porttail := '';
            ELSE host_raw := left(hostport, pos - 1); porttail := substr(hostport, pos); END IF;
        END IF;
        IF left(host_raw, 1) = '[' THEN
            hinner := substr(host_raw, 2, length(host_raw) - 2);
            IF hinner ~ ':' THEN -- expand ipv6
                host_n := '[' || array_to_string(ARRAY(
                    SELECT lpad(to_hex(g), 4, '0')
                    FROM unnest(_uri_ip6_key(hinner)) g), ':') || ']';
            ELSE -- IPvFuture: lowercase
                host_n := '[' || lower(hinner) || ']';
            END IF;
        ELSE
            host_n := lower(CASE WHEN haspct THEN _uri_pct(host_raw) ELSE host_raw END);
        END IF;
        authority := '';
        IF ui IS NOT NULL THEN
            authority := (CASE WHEN haspct THEN _uri_pct(ui) ELSE ui END) || '@';
        END IF;
        authority := authority || host_n || porttail; -- keep port verbatim
    END IF;
    IF haspct THEN path := _uri_pct(path); END IF;
    -- test after decoding: %2E decodes to '.' and can create a dot segment
    IF path ~ '(^|/)\.\.?(/|$)' THEN path := _uri_remove_dots(path); END IF;
    IF scheme IS NOT NULL THEN out := out || lower(scheme) || ':'; END IF;
    IF authraw IS NOT NULL THEN out := out || '//' || authority; END IF;
    out := out || path;
    IF query IS NOT NULL THEN
        out := out || '?' || (CASE WHEN haspct THEN _uri_pct(query) ELSE query END);
    END IF;
    IF frag IS NOT NULL THEN
        out := out || '#' || (CASE WHEN haspct THEN _uri_pct(frag) ELSE frag END);
    END IF;
    -- can't avoid the double type check here because the uri DOMAIN can't trust any input
    RETURN out::uri;
END;
$fn$;

-- uri type operators

CREATE FUNCTION uri_lt(uri, uri) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$ SELECT $1::text < $2::text $fn$;
CREATE FUNCTION uri_le(uri, uri) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$ SELECT $1::text <= $2::text $fn$;
CREATE FUNCTION uri_gt(uri, uri) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$ SELECT $1::text > $2::text $fn$;
CREATE FUNCTION uri_ge(uri, uri) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$ SELECT $1::text >= $2::text $fn$;
CREATE FUNCTION uri_eq(uri, uri) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$ SELECT $1::text = $2::text $fn$;
CREATE FUNCTION uri_ne(uri, uri) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$ SELECT $1::text <> $2::text $fn$;

-- uri type (un)escape

CREATE FUNCTION uri_escape(s text,
                           space_to_plus boolean DEFAULT false,
                           normalize_breaks boolean DEFAULT false) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
DECLARE
    b bytea; n int; i int; c int; out text := '';
BEGIN
    IF normalize_breaks THEN
        s := regexp_replace(s, E'\r\n|\r|\n', E'\r\n', 'g');
    END IF;
    -- calling replace repeatedly avoids plpgsql statement overhead
    IF octet_length(s) = length(s) AND s !~ '[\x00-\x1F\x7F]' THEN
        IF space_to_plus THEN
            RETURN
                replace(replace(replace(replace(replace(replace(replace(replace(
                replace(replace(replace(replace(replace(replace(replace(replace(
                replace(replace(replace(replace(replace(replace(replace(replace(
                replace(replace(replace(replace(replace(
                    s,
                    '%',  '%25'), '+',  '%2B'), ' ',  '+'),
                    '!',  '%21'), '"',  '%22'), '#',  '%23'),
                    '$',  '%24'), '&',  '%26'), '''', '%27'),
                    '(',  '%28'), ')',  '%29'), '*',  '%2A'),
                    ',',  '%2C'), '/',  '%2F'), ':',  '%3A'),
                    ';',  '%3B'), '<',  '%3C'), '=',  '%3D'),
                    '>',  '%3E'), '?',  '%3F'), '@',  '%40'),
                    '[',  '%5B'), '\',  '%5C'), ']',  '%5D'),
                    '^',  '%5E'), '`',  '%60'), '{',  '%7B'),
                    '|',  '%7C'), '}',  '%7D');
        ELSE
            RETURN
                replace(replace(replace(replace(replace(replace(replace(replace(
                replace(replace(replace(replace(replace(replace(replace(replace(
                replace(replace(replace(replace(replace(replace(replace(replace(
                replace(replace(replace(replace(replace(
                    s,
                    '%',  '%25'), ' ',  '%20'), '+',  '%2B'),
                    '!',  '%21'), '"',  '%22'), '#',  '%23'),
                    '$',  '%24'), '&',  '%26'), '''', '%27'),
                    '(',  '%28'), ')',  '%29'), '*',  '%2A'),
                    ',',  '%2C'), '/',  '%2F'), ':',  '%3A'),
                    ';',  '%3B'), '<',  '%3C'), '=',  '%3D'),
                    '>',  '%3E'), '?',  '%3F'), '@',  '%40'),
                    '[',  '%5B'), '\',  '%5C'), ']',  '%5D'),
                    '^',  '%5E'), '`',  '%60'), '{',  '%7B'),
                    '|',  '%7C'), '}',  '%7D');
        END IF;
    END IF;

    -- handle multibyte cases
    b := convert_to(s, 'UTF8');
    n := octet_length(b);
    FOR i IN 0 .. n - 1 LOOP
        c := get_byte(b, i);
        IF (c BETWEEN 97 AND 122) OR (c BETWEEN 65 AND 90) OR (c BETWEEN 48 AND 57)
           OR c = 45 OR c = 46 OR c = 95 OR c = 126 THEN -- - . _ ~
            out := out || chr(c);
        ELSIF space_to_plus AND c = 32 THEN
            out := out || '+';
        ELSE
            out := out || '%' || upper(lpad(to_hex(c), 2, '0'));
        END IF;
    END LOOP;
    RETURN out;
END;
$fn$;

CREATE FUNCTION _uri_unescape_pct(s text, plus_to_space boolean,
                                  break_conversion boolean) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
    -- the SELECT here prevents inlining so it is in a separate function so that
    -- the fast branch can be inlined
    SELECT COALESCE(convert_from(decode(COALESCE(string_agg(
               CASE
                   WHEN m[1] IS NOT NULL
                       THEN CASE WHEN break_conversion THEN '0d0a' ELSE '0a' END
                   WHEN m[2] IS NOT NULL THEN m[2]
                   ELSE encode(convert_to(
                            CASE WHEN plus_to_space
                                 THEN replace(m[3], '+', ' ')
                                 ELSE m[3] END, 'UTF8'), 'hex')
               END, '' ORDER BY ord), ''), 'hex'), 'UTF8'), '')
    FROM regexp_matches(
             s, '(%0[Dd]%0[Aa]|%0[Dd]|%0[Aa])|%([0-9A-Fa-f]{2})|([^%]+|%)', 'g')
         WITH ORDINALITY AS t(m, ord)
$fn$;

CREATE FUNCTION uri_unescape(s text,
                             plus_to_space boolean DEFAULT false,
                             break_conversion boolean DEFAULT false) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fn$
BEGIN
    -- use plpgsql so that this function can be inlined for query optimization
    -- also _uri_unescape_pct is included as a function call so that the fast
    -- branch here can be inlined to avoid function call overhead
    IF position('%' in s) = 0 THEN -- faster to check for percent encoding first
        IF plus_to_space THEN
            RETURN replace(s, '+', ' ');
        END IF;
        RETURN s;
    END IF;
    RETURN _uri_unescape_pct(s, plus_to_space, break_conversion);
END;
$fn$;
