#!/bin/bash
#
# This script builds the application from source.

# Get the parent directory of where this script is.
set -e

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

# Change into that directory
cd $DIR

echo "--> Building Kenmare..."
go get -d && go build -o bin/kenmare

echo "--> Running Kenmare..."
bin/kenmare --env=development
