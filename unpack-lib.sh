#!/bin/bash

if [[ -z "$1" ]]; then
	echo "$0 <path>"
	exit 1
elif [[ ! -d "$1" ]]; then
	echo "$1 is not a directory"
	exit 1
fi

OUTPAT="$1/combined.pat"

> "$OUTPAT"

for LIB in $(find $1 -name "*.lib"); do
	LIB=$(realpath "$LIB")
	if [[ ! -d "$LIB.ext" ]]; then
		echo "creating $LIB.ext"
		mkdir -p "$LIB.ext"
	fi
	for SUB in $(strings "$LIB" | grep '\w\\\w\+.obj' | sed 's#\\#/#g' | sort | uniq); do
		WNPTH=$(dirname "$LIB.ext/$SUB")
		if [[ ! -d "$WNPTH" ]]; then
			mkdir -p "$WNPTH"
		fi
	done
	echo "Unpacking "$(basename $LIB)
	sh -c "cd $LIB.ext ; ar x $LIB 2>&1 | grep -v -i 'illegal output pathname for archive member\|dll:'"
	for BAD in $(find "$LIB.ext" -type f | grep '\\'); do
		FIX=$(echo "$BAD" | sed 's#\\#/#g')
		WNPTH=$(dirname "$FIX")
		if [[ ! -d "$WNPTH" ]]; then
			mkdir -p "$WNPTH"
		fi
		mv "$BAD" "$FIX"
	done
	sh -c "cd $LIB.ext ; find . -name '*.obj' | xargs -I % sh -c \"echo 'Creating pat %.pat' ; rz-sign -q -e 'flirt.node.optimize=0' -e 'bin.demangle=false' -o %.pat % || sleep 0\""
	for PAT in $(find "$LIB.ext" -name "*.pat"); do
		cat $PAT | sed 's/---//g' >> "$OUTPAT"
	done
done

echo "---" >> "$OUTPAT"