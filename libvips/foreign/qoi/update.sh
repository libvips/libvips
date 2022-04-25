#!/bin/bash

# attempt to update our copy of libnsgif from the upstream repo

set -e

git clone https://github.com/phoboslab/qoi

echo copying out source files ...

cp qoi/qoi.h .

if [ -d "patches" ]
then
  echo applying patches ...
  for patch in patches/*.patch; do
    patch -p0 <$patch
  done
fi

echo cleaning up ...
rm -rf qoi
