#!/usr/bin/env bash
# [[file:../README.org::config-remote.sh][config-remote.sh]]
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
pushd /var/lib/interlex || exit 22
sudo -u ${INTERLEX_USER} rm -rf run/
sudo -u ${INTERLEX_USER} rm -rf resources/filesystem/
sudo -u ${INTERLEX_USER} unzip -o alt.zip || exit 1
sudo -u ${INTERLEX_USER} chmod 0755 run
sudo /bin/cp -f resources/filesystem/etc/systemd/system/ilxalt.service /etc/systemd/system/ || exit 2
sudo /bin/cp -f resources/filesystem/etc/systemd/system/ilxalt.socket /etc/systemd/system/ || exit 3
sudo /bin/cp -f resources/filesystem/etc/tmpfiles.d/ilxalt.conf /etc/tmpfiles.d/ || exit 4
sudo /bin/cp -f resources/filesystem/etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-available/ || exit 5  # carful here XXX DO NOT NUKE FROM ORBIT THANKS
sudo unlink /etc/nginx/sites-enabled/uri.interlex.org.conf
sudo ln -s /etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-enabled/uri.interlex.org.conf || exit 6
sudo systemd-tmpfiles --create || exit 7
sudo systemctl daemon-reload || exit 8
sudo systemctl enable ilxalt || exit 9
pushd run  || exit 10
sudo -u ${INTERLEX_USER} pipenv --rm  # the very first time this can fail
sudo -u ${INTERLEX_USER} pipenv install --skip-lock || exit 11
popd || exit 12
sudo -u ${INTERLEX_USER} touch .mypass || exit 13
sudo -u ${INTERLEX_USER} chmod 0600 .mypass || exit 14
if [ ! -s .mypass ]; then
    echo ~/.mypass has no records
    exit 15
fi
popd || exit 16
sudo systemctl restart ilxalt &&
    sleep 5
sudo systemctl is-active --quiet ilxalt
if [ $? -ne 0 ]; then
    sudo journalctl -u ilxalt.service -n 50
    exit 100;
fi
sudo systemctl restart nginx
"
SSH_EXIT=$?
if [ $SSH_EXIT -eq 15 ]; then
    echo you need to edit ~/.mypass on ${INTERLEX_SERVER} as ${INTERLEX_USER} to complete setup
    echo the pattern used to set the password is documented in step five of README.org on the server
    exit $SSH_EXIT
elif [ $SSH_EXIT -ne 0 ]; then
    echo remote command failed with $SSH_EXIT
    exit $SSH_EXIT
fi
# config-remote.sh ends here
