#!/bin/bash

# attempt to update our copy of libnsgif from the upstream repo

set -e

git clone git://git.netsurf-browser.org/libnsgif.git

echo copying out source files ...
cp libnsgif/src/libnsgif.c .
cp libnsgif/include/libnsgif.h .
cp libnsgif/src/lzw.[ch] .
cp libnsgif/src/utils/log.h utils

echo applying patches ...
for patch in patches/*.patch; do
  patch -p0 <$patch
done

echo cleaning up ...
rm -rf libnsgif

