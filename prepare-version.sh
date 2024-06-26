#!/bin/bash

VERSION_FILE="VERSION"
NEWTAG=$1
sed -i "s/v[[:digit:]]*\.[[:digit:]]*\.[[:digit:]]*/${NEWTAG//./\\.}/" $VERSION_FILE
