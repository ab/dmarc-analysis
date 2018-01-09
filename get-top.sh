#!/bin/bash

if [ $# -lt 1 ]; then
    cat >&2 <<EOM
usage: $(basename "$0") TOP_NUM_DOMAINS

Get the top N domains.
EOM
    exit 1
fi

run() {
    echo >&2 "+ $*"
    "$@"
}

set -eu

num="$1"

outfile="top-$num.$(date +%F).txt"
govoutfile="gov.$(date +%F).txt"
zipfile="top-1m.csv.$(date +%F).zip"

run rm -f top-1m.csv.zip
run wget -c -O "$zipfile" http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
run unzip -p "$zipfile" | run head -n "$num" | run cut -d, -f2- > "$outfile"
run unzip -p "$zipfile" | run cut -d, -f2- | run grep -E '\.gov$' > "$govoutfile"

echo "Wrote top $num domains to $outfile"
echo "Wrote top $(wc -l "$govoutfile" | awk '{ print $1 }') gov domains to $govoutfile"
