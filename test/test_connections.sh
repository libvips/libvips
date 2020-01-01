#!/bin/sh

# test load and save via custom connection

# set -x
set -e

. ./variables.sh

if test_supported jpegload_source; then
	./test_connections $image $tmp/x.png

	# test max difference < 10
	test_difference $image $tmp/x.png 10
fi
