#!/bin/bash

# attempt to update our copy of libnsgif from the upstream repo

set -e

git clone git://git.netsurf-browser.org/libnsgif.git

echo copying out source files ...

cp libnsgif/README.md README-ns.md
cp libnsgif/COPYING .

cp libnsgif/include/nsgif.h .
cp libnsgif/src/lzw.[ch] .
cp libnsgif/src/gif.c .

cp libnsgif/test/cli.[ch] test/
cp libnsgif/test/nsgif.c test/

if [ -d patches ]; then
  echo applying patches ...
  for patch in patches/*.patch; do
    patch -p0 <$patch
  done
fi

echo cleaning up ...
rm -rf libnsgif
