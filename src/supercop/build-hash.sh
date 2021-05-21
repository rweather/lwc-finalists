#!/bin/sh
DIR="$1"
NAME=`dirname "$DIR"`
CATEGORY=`dirname "$NAME"`
NAME=`basename "$NAME"`
CATEGORY=`basename "$CATEGORY"`
KAT_FILE=`echo "$DIR"/../LWC_HASH_KAT_*`
TMP_FILE="/tmp/kat$$"
echo "Checking HASH $CATEGORY/$NAME"
if "$CC" $CFLAGS "-I$DIR" -o kat-hash hash_test.c "$DIR"/*.c ; then
    ./kat-hash >"$TMP_FILE"
    if diff --strip-trailing-cr -q "$TMP_FILE" "$KAT_FILE" ; then
        rm -f "$TMP_FILE"
        exit 0
    else
        rm -f "$TMP_FILE"
        echo '***** KAT tests failed *****'
        exit 1
    fi
else
    echo '***** Compilation failed *****'
    exit 1
fi
