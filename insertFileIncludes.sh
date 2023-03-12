#!/bin/bash

# This script inserts stuff from other files into the draft
# Intended to be called by the makefile


FILE=$1
if [ ! -f $FILE ]; then
    >&2 echo "$0: Error: file \"$FILE\" does not exist."
    exit -1
fi

DIR=$2

#REGEX_MATCH="^!!(.*)$"
cat $FILE | sed -r "s|^\!\!([-a-zA-Z0-9_./]*)$|cat $DIR/\1|e"