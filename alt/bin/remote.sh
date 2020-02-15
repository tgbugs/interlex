#!/usr/bin/env bash
# [[file:~/git/interlex/alt/README.org::remote.sh][remote.sh]]
ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "
# [[[[file:~/git/interlex/alt/README.org::*remote-command][*remote-command]]][*remote-command]]
mv -f run/*.whl .
rm run/Pipenv.lock
unzip -o alt.zip || exit 1
cd run || exit 2
pipenv --rm
pipenv install *.whl || exit 3

# *remote-command ends here
"
SSH_EXIT=$?
if [ $SSH_EXIT -ne 0 ]; then
    exit $SSH_EXIT
fi
# remote.sh ends here
