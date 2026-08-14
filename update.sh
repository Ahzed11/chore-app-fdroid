#!/bin/bash

cd metascoop
echo "::group::Building metascoop executable"
go build -o metascoop
echo "::endgroup::"

./metascoop -ap=../apps.yaml -rd=../fdroid/repo -pat="$GH_ACCESS_TOKEN" $1
EXIT_CODE=$?
cd ..

echo "Scoop had an exit code of $EXIT_CODE"

set -e

if [ $EXIT_CODE -eq 2 ]; then
    # Exit code 2 means that there were no significant changes
    echo "This means that there were no significant changes"
    exit 0
elif [ $EXIT_CODE -eq 0 ]; then
    # Exit code 0 means that we can commit everything & push

    echo "This means that we now have changes we should push"

    # TASK-105: never publish an index whose APK was signed with any key but
    # the pinned one — a signature change bricks updates for every installed
    # user (Android refuses signature changes). check_signatures.py re-extracts
    # the cert from every APK in fdroid/repo AND cross-checks the index
    # `signer` fields against signing_cert.sha256; abort before committing if
    # any of it drifts.
    python3 check_signatures.py fdroid/repo || exit 3

    git config --global user.name 'github-actions'
    git config --global user.email '41898282+github-actions[bot]@users.noreply.github.com'

    git add .
    git commit -m"Automated update"
    git push
else 
    echo "This is an unexpected error"

    exit $EXIT_CODE
fi
