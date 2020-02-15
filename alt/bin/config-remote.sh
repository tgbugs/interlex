#!/usr/bin/env bash
# [[file:~/git/interlex/alt/README.org::config-remote.sh][config-remote.sh]]
ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "
# [[[[file:~/git/interlex/alt/README.org::*config-remote-command][*config-remote-command]]][*config-remote-command]]
rm -rf run/
rm -rf deploy_files/
unzip -o alt.zip || exit 1
sudo /bin/cp -f deploy_files/etc/systemd/system/ilxalt.service /etc/systemd/system/ || exit 2
sudo /bin/cp -f deploy_files/etc/systemd/system/ilxalt.socket /etc/systemd/system/ || exit 3
sudo /bin/cp -f deploy_files/etc/tmpfiles.d/ilxalt.conf /etc/tmpfiles.d/ || exit 4
sudo /bin/cp -f deploy_files/etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-available/ || exit 5  # carful here
sudo unlink /etc/nginx/sites-enabled/uri.interlex.org.conf
sudo ln -s /etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-enabled/uri.interlex.org.conf || exit 6
sudo systemd-tmpfiles --create || exit 7
sudo systemctl daemon-reload || exit 8
sudo systemctl enable ilxalt || exit 9
cd run  || exit 10
pipenv --rm  # the very first time this can fail
pipenv install || exit 11
cd ~/ || exit 12
touch .mypass || exit 13
chmod 0600 .mypass || exit 14
if [ ! -s .mypass ]; then
    echo ~/.mypass has no records
    exit 15
fi
sudo systemctl restart ilxalt &&
    sleep 5
sudo systemctl is-active --quiet ilxalt
if [ $? -ne 0 ]; then
    sudo journalctl -u ilxalt.service -n 50
    exit 100;
fi
sudo systemctl restart nginx
# *config-remote-command ends here
"
SSH_EXIT=$?
if [ $SSH_EXIT -eq 15 ]; then
    echo you need to edit ~/.mypass on ${INTERLEX_SERVER} as ${INTERLEX_USER} to complete setup
    echo the pattern used to set the password is deocumented in step five of README.org on the server
    exit $SSH_EXIT
elif [ $SSH_EXIT -ne 0 ]; then
    echo remote command failed with $SSH_EXIT
    exit $SSH_EXIT
fi
# config-remote.sh ends here
