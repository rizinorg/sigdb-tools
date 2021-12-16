#!/bin/bash
set -e

ARCH="x86"
BITS="64"
SYSO="linux"
LIBN="musl-libc.a"
VARIANT="ubuntu"
VERB=-v

TOOLDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SRC="$1"

if [[ -z "$SRC" ]]; then
	echo "usage: $0 <source-database/arch/library>"
	echo "  example:"
	echo "    $0 sigdb-src/amd64/musl-dev/"
	exit 1
fi

notify() {
	echo "#################################################"
	echo "  $@"
	echo "#################################################"
}


notify "building middle pac"
find "$SRC" ! -path "$SRC" -type d -maxdepth 1 | xargs -I % python "$TOOLDIR/db_shrink.py" $VERB -a $ARCH -b $BITS -s $SYSO -l $LIBN -o "%"  -i "%"

notify "building final pac"
if [[ -z "$VARIANT" ]]; then
	python "$TOOLDIR/db_shrink.py" $VERB -a $ARCH -b $BITS -s $SYSO -l $LIBN -i "$SRC" -o "$SRC"
	rz-sign -e "flirt.sig.deflate=true" -e "asm.arch=$ARCH" -e "asm.bits=$BITS" -c "$SRC/"$LIBN".deflate.sig" "$SRC/"$ARCH"_"$BITS"_"$SYSO"_"$LIBN".pac"
else
	python "$TOOLDIR/db_shrink.py" $VERB -a $ARCH -b $BITS -s $SYSO -V $VARIANT -l $LIBN -i "$SRC" -o "$SRC"
	rz-sign -e "flirt.sig.deflate=true" -e "asm.arch=$ARCH" -e "asm.bits=$BITS" -c "$SRC/"$LIBN".deflate.sig" "$SRC/"$ARCH"_"$BITS"_"$SYSO"_"$VARIANT"_"$LIBN".pac"
fi