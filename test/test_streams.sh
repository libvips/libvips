#!/bin/sh

# test load and save via stream*u

set -x
set -e

. ./variables.sh

if test_supported jpegload_stream; then
	./test_streams $image $tmp/x.png

	# test max difference < 10
	test_difference $image $tmp/x.png 10
fi
