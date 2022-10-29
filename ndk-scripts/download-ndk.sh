#!/bin/sh
# SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only
set -e

echo "creating android-ndks"
mkdir android-ndks || sleep 0
cd android-ndks

wget --continue https://dl.google.com/android/ndk/android-ndk-r9d-linux-x86_64.tar.bz2
wget --continue https://dl.google.com/android/repository/android-ndk-r10e-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r11c-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r12b-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r13b-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r14b-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r15c-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r16b-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r17c-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r18b-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r20b-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r21e-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r22b-linux-x86_64.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r23c-linux.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r24-linux.zip
wget --continue https://dl.google.com/android/repository/android-ndk-r25b-linux.zip

tar xvf android-ndk-r9d-linux-x86_64.tar.bz2
unzip android-ndk-r10e-linux-x86_64.zip
unzip android-ndk-r11c-linux-x86_64.zip
unzip android-ndk-r12b-linux-x86_64.zip
unzip android-ndk-r13b-linux-x86_64.zip
unzip android-ndk-r14b-linux-x86_64.zip
unzip android-ndk-r15c-linux-x86_64.zip
unzip android-ndk-r16b-linux-x86_64.zip
unzip android-ndk-r17c-linux-x86_64.zip
unzip android-ndk-r18b-linux-x86_64.zip
unzip android-ndk-r19c-linux-x86_64.zip
unzip android-ndk-r20b-linux-x86_64.zip
unzip android-ndk-r21e-linux-x86_64.zip
unzip android-ndk-r22b-linux-x86_64.zip
unzip android-ndk-r23c-linux.zip
unzip android-ndk-r24-linux.zip
unzip android-ndk-r25b-linux.zip
