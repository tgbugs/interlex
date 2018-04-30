-- interlex-admin interlex_test

GRANT CONNECT ON DATABASE :database TO "interlex-user";
GRANT USAGE ON SCHEMA interlex TO "interlex-user";

GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA interlex TO "interlex-user";  -- tables includes views
GRANT USAGE ON ALL SEQUENCES IN SCHEMA interlex TO "interlex-user";

GRANT UPDATE (expected_bound_name) ON interlex.reference_names TO "interlex-user";
