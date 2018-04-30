if [ -z $1 ]; then
    PORT=5423
else
    PORT=$1
fi

if [ -z $2 ]; then
    DATABASE=interlex_test
else
    DATABASE=$2
fi

# postgres setup
psql -U postgres -h localhost -p $PORT -d postgres  -f ilx-setup-postgres-postgres.sql -v database=$DATABASE
psql -U postgres -h localhost -p $PORT -d $DATABASE -f ilx-setup-postgres-interlex.sql

# interlex-admin setup
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f ilx-schema-interlex.sql
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f ilx-schema-groups.sql
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f ilx-schema-triple-tables.sql
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f ilx-schema-uri-mapping-tables.sql
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f ilx-schema-inserts.sql
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f ilx-schema-permissions.sql -v database=$DATABASE

# tests
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f ilx-schema-test.sql
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f ilx-schema-test-fail.sql

