#!/usr/bin/env bash

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve all symlinks
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # resolve relative symlinks
done
ABS_PATH="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

ALT_PATH="${ABS_PATH}/../"
echo ${ALT_PATH}

cd ${ALT_PATH} &&
python setup.py bdist_wheel --universal &&
python setup.py clean --all &&
rm -rf *.egg-info &&
mv dist/* run/ &&
rmdir dist &&
#pipenv install  # leave this out for now due to gunicorn detection issues
rm alt.zip;
zip -r alt.zip README.md &&
zip -r alt.zip run/ &&
scp -v alt.zip ${INTERLEX_USER}@${INTERLEX_SERVER}:/home/${INTERLEX_USER}/
