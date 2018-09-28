#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "rm -rf run/;  # in case it is not actually the first time
    rm -rf deploy_files/;
    unzip -o alt.zip &&
    sudo /bin/cp -f deploy_files/etc/systemd/system/ilxalt.service /etc/systemd/system/ &&
    sudo /bin/cp -f deploy_files/etc/systemd/system/ilxalt.socket /etc/systemd/system/ &&
    sudo /bin/cp -f deploy_files/etc/tmpfiles.d/ilxalt.conf /etc/tmpfiles.d/ &&
    sudo /bin/cp -f deploy_files/etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-available/ && # carful here
    sudo unlink /etc/nginx/sites-enabled/uri.interlex.org.conf;
    sudo ln -s /etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-enabled/uri.interlex.org.conf &&
    sudo systemd-tmpfiles --create &&
    sudo systemctl enable ilxalt &&
    pip3.6 install --user --ignore-installed pipenv &&
    cd run &&
    ~/.local/bin/pipenv pipenv install &&
    cd ~/ &&
    touch .mypass &&
    chmod 0600 .mypass"
if [ $? -ne 0 ]; then
    exit 1
fi
echo you need to edit ~/.mypass on ${INTERLEX_SERVER} as ${INTERLEX_USER} to complete the setup
echo the pattern used to set the password is deocumented in step five of README.md on the server
