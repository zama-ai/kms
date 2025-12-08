#!/usr/bin/env bash

set -euo pipefail

OUTDIR=$1
PARTYID=$2

mkdir -p "$OUTDIR/$PARTYID"
while true; do
	now=$(date +%s)
	out=$(lsof -i)
	openfiles=$(echo "$out" | wc -l | xargs)
	echo "$out" > $OUTDIR/$PARTYID/$now
	echo "$now,$openfiles" >> $OUTDIR/party-$PARTYID
	sleep 1
done

