#!/usr/bin/env bash

ssh ${INTERLEX_USER}@${INTERLEX_SERVER} "mv run/*.whl . ;
    unzip -o alt.zip &&
    sudo systemctl stop ilxalt &&
    cd run &&
    pipenv install *.whl &&
    pipenv update &&
    sudo systemctl start ilxalt"
