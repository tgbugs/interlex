#!/usr/bin/env bash
# [[file:~/git/interlex/alt/README.org::remote.sh][remote.sh]]
ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "
# [[[[file:~/git/interlex/alt/README.org::remote-command][remote-command]]][remote-command]]
mv -f run/*.whl . ;
rm run/Pipenv.lock;
unzip -o alt.zip &&
    cd run &&
    pipenv --rm;
pipenv install *.whl &&
    sudo systemctl restart ilxalt &&
    sleep 5
sudo systemctl is-active --quiet ilxalt
if [ $? -ne 0 ]; then
    sudo journalctl -u ilxalt.service -n 50;
    exit 1;
fi
# remote-command ends here
"
SSH_EXIT=$?
if [ $SSH_EXIT -ne 0 ]; then
    exit $SSH_EXIT
fi
# remote.sh ends here
