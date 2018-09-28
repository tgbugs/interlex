#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "unzip alt.zip &&
    sudo /bin/cp deploy_files/etc/systemd/system/ilxalt.service /etc/systemd/system/ &&
    sudo /bin/cp deploy_files/etc/systemd/system/ilxalt.socket /etc/systemd/system/ &&
    sudo /bin/cp deploy_files/etc/tmpfiles.d/ilxalt.conf /etc/tmpfiles.d/ &&
    sudo /bin/cp deploy_files/etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-available/ && # carful here
    sudo unlink /etc/nginx/sites-enabled/uri.interlex.org.conf;
    sudo ln -s /etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-enabled/uri.interlex.org.conf &&
    sudo systemd-tmpfiles --create &&
    sudo systemctl enable ilxalt &&
    cd run && pipenv install && cd ~/ && touch .mypass && chmod 0600 .mypass"
echo you need to edit ~/.mypass on ${INTERLEX_SERVER} as ${INTERLEX_USER} to complete the setup
echo the pattern used to set the password is deocumented in step five of README.md on the server
