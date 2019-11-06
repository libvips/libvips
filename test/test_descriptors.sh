#!/bin/sh

# test the various restartable loaders

# webp uses streams, but it needs to mmap the input, so you can't close() the
# fd on minimise

# set -x
set -e

. ./variables.sh

if test_supported jpegload; then
	./test_descriptors $image
fi

if test_supported pngload; then
	./test_descriptors $test_images/sample.png
fi

if test_supported tiffload; then
	./test_descriptors $test_images/sample.tif
fi

if test_supported radload; then
	./test_descriptors $test_images/sample.hdr
fi
