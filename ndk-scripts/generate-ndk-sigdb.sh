#!/bin/sh
# SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only
set -e

SOURCE="$1"
DEST="$2"

if [ -z "$SOURCE" ]; then
	echo "the android-ndks directory location is invalid."
	echo "$0 </path/to/android-ndks> <destination dir>"
	exit 1
elif [ -z "$DEST" ]; then
	echo "the output directory is invalid."
	echo "$0 </path/to/android-ndks> <destination dir>"
	exit 1
fi

# old SDK format with platforms
for NDK in $(ls $SOURCE); do
	if [ -f "$SOURCE/$NDK" ]; then
		continue
	fi
	PLATFORM="$SOURCE/$NDK/platforms"
	if [ ! -d "$PLATFORM" ]; then
		continue
	fi
	for SDK in $(ls $PLATFORM); do
		if [ ! -d "$PLATFORM/$SDK" ]; then
			continue
		fi
		for ARCHSDK in $(ls $PLATFORM/$SDK); do
			if [ ! -d "$PLATFORM/$SDK/$ARCHSDK/usr/lib" ]; then
				continue
			fi
			ARCH=""
			case $ARCHSDK in
				arch-arm)
				ARCH="arm/32"
				;;
				arch-arm64)
				ARCH="arm/64"
				;;
				arch-mips)
				ARCH="mips/32"
				;;
				arch-mips64)
				ARCH="mips/64"
				;;
				arch-x86)
				ARCH="x86/32"
				;;
				arch-x86_64)
				ARCH="x86/64"
				;;
				*)
				echo "unknown arch $ARCHSDK"
				exit 1
				;;
			esac
			SRC="$PLATFORM/$SDK/$ARCHSDK/usr/lib"
			NDKREL=${NDK#"android-ndk-"}
			TARGET="$DEST/elf/$ARCH/$SDK"
			echo "working on: $TARGET/$NDKREL"
			mkdir -p "$TARGET"
			cp -r "$SRC" "$TARGET/$NDKREL"
		done
	done
done

# new SDK without platform; using sysroot
for NDK in $(ls $SOURCE); do
	if [ -f "$SOURCE/$NDK" ]; then
		continue
	fi
	PLATFORM="$SOURCE/$NDK/platforms"
	if [ -d "$PLATFORM" ]; then
		continue
	fi
	PLATFORM="$SOURCE/$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/"
	for ARCHSDK in $(ls $PLATFORM); do
		if [ ! -d "$PLATFORM/$ARCHSDK" ]; then
			continue
		fi
		ARCH=""
		case $ARCHSDK in
			arm-linux-androideabi)
			ARCH="arm/32"
			;;
			aarch64-linux-android)
			ARCH="arm/64"
			;;
			i686-linux-android)
			ARCH="x86/32"
			;;
			x86_64-linux-android)
			ARCH="x86/64"
			;;
			*)
			echo "unknown target arch $ARCHSDK"
			exit 1
			;;
		esac
		NDKREL=${NDK#"android-ndk-"}
		TARGETUNK="$DEST/elf/$ARCH/unknown/$NDKREL"
		mkdir -p "$TARGETUNK"
		LASTSDK="0"
		for ENTRY in $(ls "$PLATFORM/$ARCHSDK"); do
			if [ -f "$PLATFORM/$ARCHSDK/$ENTRY" ]; then
				cp "$PLATFORM/$ARCHSDK/$ENTRY" "$TARGETUNK"
				continue
			fi
			LASTSDK="$ENTRY"
			TARGET="$DEST/elf/$ARCH/android-$ENTRY/"
			echo "working on: $TARGET"
			mkdir -p "$TARGET"
			cp -r "$PLATFORM/$ARCHSDK/$ENTRY" "$TARGET/$NDKREL"
		done
		LASTSDK=$((LASTSDK+1))
		TARGET="$DEST/elf/$ARCH/android-$LASTSDK"
		echo "renaming 'unknown' to 'android-$LASTSDK'"
		mv -v "$DEST/elf/$ARCH/unknown" "$TARGET"
	done
done
NREM=$(find "$DEST" -name "*.so" | xargs -I % rm -v % | wc -l)
echo "removed $NREM *.so files"
for ARFILE in $(find $DEST -name "*.a"); do
	echo "extracting: $ARFILE"
	ARFILE=$(realpath "$ARFILE")
	mkdir -p "$ARFILE.ext"
	WORKDIR=$(pwd)
	cd "$ARFILE.ext"
	ar x "$ARFILE" || sleep 0
	cd "$WORKDIR"
done

echo "all the .a files has been unpacked and stored under '$DEST'"
echo "you can now call generate-pat-from-obj.py to create the pat files."
