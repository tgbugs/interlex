ABS_PATH="`dirname \"$0\"`"
ABS_PATH="`( cd \"$ABS_PATH\" && pwd )`"
if [ -z "$ABS_PATH" ] ; then
  exit 1
fi
echo "$ABS_PATH"

SQL="${ABS_PATH}/../sql/"
RESOURCES="${ABS_PATH}/../resources/"

if [ -z $1 ]; then
    PORT=5432
else
    PORT=$1
fi

if [ -z $2 ]; then
    DATABASE=interlex_test
else
    DATABASE=$2
fi

# postgres setup
psql -U postgres -h localhost -p $PORT -d postgres  -f "${SQL}/postgres.sql" -v database=$DATABASE
psql -U postgres -h localhost -p $PORT -d $DATABASE -f "${SQL}/extensions.sql"

# interlex-admin setup
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f "${SQL}/schemas.sql"
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f "${SQL}/groups.sql"
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f "${SQL}/triples.sql"
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f "${SQL}/user-uris.sql"
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f "${SQL}/inserts.sql" -v resources=${RESOURCES} 
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f "${SQL}/permissions.sql" -v database=$DATABASE

# tests
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f "${SQL}/test.sql"
psql -U interlex-admin -h localhost -p $PORT -d $DATABASE -f "${SQL}/test-fail.sql"

