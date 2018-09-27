#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "unzip alt.zip &&
    sudo cp deploy_files/etc/systemd/system/ilxalt.service /etc/systemd/system/ &&
    sudo cp deploy_files/etc/systemd/system/ilxalt.socket /etc/systemd/system/ &&
    sudo cp deploy_files/etc/tmpfiles.d/ilxalt.conf /etc/tmpfiles.d/ &&
    sudo cp deploy_files/etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-available/ && # carful here
    sudo ln -s /etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-enabled/uri.interlex.org.conf &&
    sudo systemd-tmpfiles --create &&
    sudo systemctl enable ilxalt &&
    cd run && pipenv install && cd ~/ && touch .mypass && chmod 0600 .mypass"
# the remainder should be done manually
# ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "vi .mypass && # add an entry according to the pattern described below"
# ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "sudo systemctl start ilxalt"
