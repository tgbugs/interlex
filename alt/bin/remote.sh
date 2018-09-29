#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "mv -f run/*.whl . ;
    unzip -o alt.zip &&
    sudo systemctl stop ilxalt &&
    cd run &&
    ~/.local/bin/pipenv --rm &&
    ~/.local/bin/pipenv install *.whl &&
    sudo systemctl start ilxalt &&
    sleep 5
    if [ -n $(sudo systemctl is-active --quiet ilxalt) ]; then
        sudo journalctl -u ilxalt.service | tail -n 50;
        exit 1;
    fi"
if [ $? -ne 0 ]; then
    exit 1
fi
