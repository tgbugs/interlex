#!/usr/bin/env bash
# [[file:../README.org::config-build.sh][config-build.sh]]
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve all symlinks
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # resolve relative symlinks
done
ABS_PATH="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

ALT_PATH="${ABS_PATH}/../"
pushd "${ALT_PATH}" &&
git clean -dfx &&  # cleans only the alt subdir
git checkout HEAD -- resources/filesystem/  # prevent stale user
popd || exit 1
pushd "${ALT_PATH}" &&
grep -rl interlex resources/filesystem/ | xargs sed -i "s/{:interlex-user}/${INTERLEX_USER}/g" &&
popd || exit 101
pushd "${ALT_PATH}" &&
python setup.py bdist_wheel --universal &&
python setup.py clean --all &&
rm -rf ./*.egg-info &&
mv dist/* run/ &&
rmdir dist &&
#pipenv install  # leave this out for now due to gunicorn detection issues
rm alt.zip;
zip -r alt.zip README.org &&
zip -r alt.zip run/ &&
popd || exit 2
pushd "${ALT_PATH}" &&
zip -r alt.zip resources/filesystem/  # first time only add deploy files
popd || exit 102
# config-build.sh ends here
