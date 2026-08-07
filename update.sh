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

    # TASK-100: never publish an index whose versions drifted signing keys —
    # a signature change bricks updates for every installed user (Android
    # refuses signature changes). Abort before committing if drift is found.
    python3 check_signatures.py fdroid/repo/index-v1.json || exit 3

    git config --global user.name 'github-actions'
    git config --global user.email '41898282+github-actions[bot]@users.noreply.github.com'

    git add .
    git commit -m"Automated update"
    git push
else 
    echo "This is an unexpected error"

    exit $EXIT_CODE
fi
