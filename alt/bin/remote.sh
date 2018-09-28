#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "mv run/*.whl . ;
    unzip -o alt.zip &&
    sudo systemctl stop ilxalt &&
    cd run &&
    ~/.local/bin/pipenv install *.whl &&
    ~/.local/bin/pipenv update &&
    sudo systemctl start ilxalt"
