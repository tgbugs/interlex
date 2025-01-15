-- interlex-admin interlex_test

GRANT CONNECT ON DATABASE :database TO "interlex-user";
GRANT USAGE ON SCHEMA interlex TO "interlex-user";

GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA interlex TO "interlex-user";  -- tables includes views
GRANT USAGE ON ALL SEQUENCES IN SCHEMA interlex TO "interlex-user";

GRANT UPDATE (orcid) ON interlex.users TO "interlex-user";
GRANT UPDATE (own_role) ON interlex.groups TO "interlex-user";
GRANT UPDATE (argon2_string) ON interlex.user_passwords TO "interlex-user";
GRANT UPDATE (email_validated) ON interlex.user_emails TO "interlex-user";
GRANT DELETE ON interlex.emails_validating TO "interlex-user";

GRANT UPDATE (user_role) ON interlex.user_permissions TO "interlex-user";

GRANT UPDATE (expected_bound_name) ON interlex.reference_names TO "interlex-user";
