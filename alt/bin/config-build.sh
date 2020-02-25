#!/usr/bin/env bash
# [[file:~/git/interlex/alt/README.org::config-build.sh][config-build.sh]]
# [[[[file:~/git/interlex/alt/README.org::&alt-path][&alt-path]]][&alt-path]]
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve all symlinks
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # resolve relative symlinks
done
ABS_PATH="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

ALT_PATH="${ABS_PATH}/../"
# &alt-path ends here
# [[[[file:~/git/interlex/alt/README.org::*pushd-clean][*pushd-clean]]][*pushd-clean]]
pushd ${ALT_PATH} &&
git clean -dfx &&  # cleans only the alt subdir
git checkout HEAD -- deploy_files/  # prevent stale user
# *pushd-clean ends here
grep -rl interlex deploy_files/ | xargs sed -i "s/{interlex-user}/${INTERLEX_USER}/g" &&
# [[[[file:~/git/interlex/alt/README.org::*build-alt-zip][*build-alt-zip]]][*build-alt-zip]]
python setup.py bdist_wheel --universal &&
python setup.py clean --all &&
rm -rf *.egg-info &&
mv dist/* run/ &&
rmdir dist &&
#pipenv install  # leave this out for now due to gunicorn detection issues
rm alt.zip;
zip -r alt.zip README.org &&
zip -r alt.zip run/ &&
# *build-alt-zip ends here
zip -r alt.zip deploy_files/  # first time only add deploy files
# [[[[file:~/git/interlex/alt/README.org::*scp-zip][*scp-zip]]][*scp-zip]]
scp -v alt.zip ${INTERLEX_USER}@${INTERLEX_SERVER}:/home/${INTERLEX_USER}/
popd || exit 1
# *scp-zip ends here
# config-build.sh ends here
