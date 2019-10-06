#!/bin/sh

# test the various restartable loaders

# set -x
set -e

. ./variables.sh

if test_supported jpegload; then
	./test_descriptors $image
fi
