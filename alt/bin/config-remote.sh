#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "rm -rf run/;
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
    ~/.local/bin/pipenv --rm;  # the very first time this can fail
    ~/.local/bin/pipenv install &&
    cd ~/ &&
    touch .mypass &&
    chmod 0600 .mypass
    if [ -s .mypass ]; then
        sudo systemctl restart ilxalt &&
        sudo systemctl restart nginx;
    else
        echo ~/.mypass has no records;
        exit 2;
    fi"
SSH_EXIT=$?
if [ $SSH_EXIT -eq 2 ]; then
    echo you need to edit ~/.mypass on ${INTERLEX_SERVER} as ${INTERLEX_USER} to complete setup
    echo the pattern used to set the password is deocumented in step five of README.md on the server
    exit $SSH_EXIT
elif [ $SSH_EXIT -ne 0 ]; then
    exit $SSH_EXIT
fi
