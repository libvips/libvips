#!/bin/sh

#set -x
set -e

. ../test/variables.sh

# Glib is built without -fno-omit-frame-pointer. We need
# to disable the fast unwinder to get full stacktraces.
export ASAN_OPTIONS="$ASAN_OPTIONS:fast_unwind_on_malloc=0:allocator_may_return_null=1"
export UBSAN_OPTIONS="$UBSAN_OPTIONS:print_stacktrace=1"

# Hide all warning messages from vips.
export VIPS_WARNING=0

ret=0

for fuzzer in *_fuzzer; do
  for file in $top_srcdir/fuzz/common_fuzzer_corpus/*; do
    exit_code=0
    ./$fuzzer $file || exit_code=$?
    if [ $exit_code -ne 0 ]; then
      echo FAIL $fuzzer $file
      ret=1
    fi
  done
done

exit $ret
