#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "mv -f run/*.whl . ;
    unzip -o alt.zip &&
    sudo systemctl stop ilxalt &&
    cd run &&
    ~/.local/bin/pipenv --rm &&
    ~/.local/bin/pipenv install *.whl &&
    sudo systemctl start ilxalt &&
    sleep 5
    sudo systemctl is-active --quiet ilxalt
    if [ $? -ne 0 ]; then
        sudo journalctl -u ilxalt.service | tail -n 50;
        exit 1;
    fi"
if [ $? -ne 0 ]; then
    exit 1
fi
