#!/usr/bin/env bash
# [[file:../README.org::remote.sh][remote.sh]]
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve all symlinks
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # resolve relative symlinks
done
ABS_PATH="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

ALT_PATH="${ABS_PATH}/../"
TEMP_DIR=$(ssh ${INTERLEX_DEPLOY_USER}@${INTERLEX_SERVER} "mktemp -d")
TD_EXIT=$?
if [ $TD_EXIT -ne 0 ]; then
    exit $TD_EXIT
fi
pushd "${ALT_PATH}" &&
# so apparently we're deploying on things so old that rsync doesn't have the commands on the remote it needs
#rsync --rsh ssh --archive --verbose alt.zip ${INTERLEX_DEPLOY_USER}@${INTERLEX_SERVER}:${TEMP_DIR}/alt.zip || exit 20
scp alt.zip ${INTERLEX_DEPLOY_USER}@${INTERLEX_SERVER}:${TEMP_DIR}/alt.zip || exit 20
popd || exit 3
ssh ${INTERLEX_DEPLOY_USER}@${INTERLEX_SERVER} "
sudo mv ${TEMP_DIR}/alt.zip /var/lib/interlex/alt.zip
sudo rmdir ${TEMP_DIR}
sudo chown ${INTERLEX_USER}:${INTERLEX_USER} /var/lib/interlex/alt.zip
pushd /var/lib/interlex
sudo -u ${INTERLEX_USER} mv -f run/*.whl .
sudo -u ${INTERLEX_USER} rm run/Pipfile.lock
sudo -u ${INTERLEX_USER} unzip -o alt.zip || exit 1
pushd run || exit 2
sudo -u ${INTERLEX_USER} pipenv --rm
sudo -u ${INTERLEX_USER} pipenv install *.whl --skip-lock || exit 3
popd || exit 4
popd || exit 5
sudo systemctl restart ilxalt &&
    sleep 5
sudo systemctl is-active --quiet ilxalt
if [ $? -ne 0 ]; then
    sudo journalctl -u ilxalt.service -n 50
    exit 100;
fi
"
SSH_EXIT=$?
if [ $SSH_EXIT -ne 0 ]; then
    exit $SSH_EXIT
fi
# remote.sh ends here
