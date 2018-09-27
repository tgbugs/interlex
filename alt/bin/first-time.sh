#!/usr/bin/env bash

grep -rl interlex deploy_files/ | xargs sed -i "s/{interlex-user}/${INTERLEX_USER}/g" &&
python setup.py bdist_wheel --universal &&
python setup.py clean --all &&
rm -rf *.egg-info &&
mv dist/* run/ &&
rmdir dist &&
#pipenv install  # leave this out for now due to gunicorn detection issues
rm alt.zip;
zip -r alt.zip README.md &&
zip -r alt.zip run/ &&
zip -r alt.zip deploy_files/  # first time only
scp alt.zip ${INTERLEX_SERVER}:/home/${INTERLEX_USER}/
