#!/bin/bash

SHA="-C $SEMAPHORE_GIT_SHA"
BRANCH="-B $SEMAPHORE_GIT_BRANCH"
PR=
if [ "x$SEMAPHORE_GIT_PR_NUMBER" != "x" ]; then
    PR="-P $SEMAPHORE_GIT_PR_NUMBER"
    SHA="-C $SEMAPHORE_GIT_PR_SHA"
    BRANCH="-B $SEMAPHORE_GIT_PR_BRANCH"
fi
BUILD="-b $SEMAPHORE_JOB_ID"
NAME="-n '$SEMAPHORE_JOB_NAME'"

# Are we in a PR context? The variables are wrong if so.
if [[ "$SEMAPHORE_GIT_REF_TYPE" == "pull-request" ]]; then
    echo "codecov wrapper: this appears to be a PR named '$SEMAPHORE_GIT_PR_NAME', setting params accordingly..."
fi

./codecov $SHA $BRANCH $PR $BUILD -r $SEMAPHORE_GIT_REPO_SLUG -f 'coverage.out.*' "$@" || echo 'Failed to upload coverage data.'
rm -f coverage.out.*