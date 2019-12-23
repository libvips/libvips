#!/bin/sh

# test the various restartable loaders

# webp and ppm use streams, but they mmap the input, so you can't close() the
# fd on minimise

# set -x
set -e

. ./variables.sh

if test_supported jpegload_stream; then
	./test_descriptors $image
fi

if test_supported pngload_stream; then
	./test_descriptors $test_images/sample.png
fi

if test_supported tiffload_stream; then
	./test_descriptors $test_images/sample.tif
fi

if test_supported radload_stream; then
	./test_descriptors $test_images/sample.hdr
fi

if test_supported svgload_stream; then
	./test_descriptors $test_images/logo.svg
fi

