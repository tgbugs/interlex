#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "mv -f run/*.whl . ;
    unzip -o alt.zip &&
    sudo systemctl stop ilxalt &&
    cd run &&
    ~/.local/bin/pipenv install *.whl &&
    ~/.local/bin/pipenv update &&
    sudo systemctl start ilxalt"
if [ $? -ne 0 ]; then
    exit 1
fi
