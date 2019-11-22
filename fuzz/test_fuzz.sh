#!/bin/sh

#set -x
set -e

# Glib is built without -fno-omit-frame-pointer. We need
# to disable the fast unwinder to get full stacktraces.
export ASAN_OPTIONS="fast_unwind_on_malloc=0:allocator_may_return_null=1"
export UBSAN_OPTIONS="print_stacktrace=1"

# Hide all warning messages from vips.
export VIPS_WARNING=0

ret=0

for fuzzer in *_fuzzer; do
  for file in common_fuzzer_corpus/*; do
    if ! ./$fuzzer $file; then
      echo FAIL $fuzzer $file
      ret=1
    fi
  done
done

exit $ret
