#!/bin/sh

#set -x
set -e

. ../test/variables.sh

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

  # Run fuzzer-specific corpus if it exists.
  corpus_dir="$top_srcdir/fuzz/${fuzzer}_corpus"
  if [ -d "$corpus_dir" ]; then
    for file in "$corpus_dir"/*; do
      exit_code=0
      ./$fuzzer $file || exit_code=$?
      if [ $exit_code -ne 0 ]; then
        echo FAIL $fuzzer $file
        ret=1
      fi
    done
  fi
done

exit $ret
