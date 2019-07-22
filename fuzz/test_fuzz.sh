#!/bin/sh

#set -x
set -e

# Glib is build without -fno-omit-frame-pointer. We need
# to disable the fast unwinder to get full stacktraces.
export ASAN_OPTIONS="fast_unwind_on_malloc=0:allocator_may_return_null=1"

# Hide all warning messages from vips.
export VIPS_WARNING=0

ret=0

for fuzzer in *_fuzzer; do
	find "${fuzzer}_corpus" -type f -not -empty -print0 \
	  | xargs -0 -n1 "./$fuzzer" || ret=1
done

exit $ret
